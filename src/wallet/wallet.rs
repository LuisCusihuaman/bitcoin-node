use std::collections::HashMap;
use std::sync::mpsc::Sender;
use std::vec;

use bitcoin_hashes::hash160;
use bitcoin_hashes::Hash;
use rand::rngs::OsRng;
use rand::Rng;
use secp256k1::{Message, Secp256k1, SecretKey};

use crate::config::Config;
use crate::logger::log;
use crate::net::message::get_utxos::PayloadGetUtxos;
use crate::net::message::tx::{decode_internal_tx, OutPoint, Tx, TxIn, TxOut};
use crate::net::message::{MessagePayload, TxStatus};
use crate::net::p2p_connection::P2PConnection;
use crate::node::utxo::Utxo;
use crate::utils::{array_to_hex, double_sha256, pk_hash_from_addr};

#[derive(Clone)]
pub struct Wallet {
    config: Config,
    logger_tx: Sender<String>,
    node_manager: P2PConnection,
    pub users: Vec<User>,
    pub pending_tx: PendingTx,
    pub tnxs_history: HashMap<[u8; 32], (Tx, TxStatus, String, f64)>,
    pub available_money: u64,
}

impl Wallet {
    pub fn new(config: Config, sender: Sender<String>, user: User) -> Wallet {
        let logger_tx = sender.clone();
        let node_manager = P2PConnection::connect("127.0.0.1:18333", sender).unwrap();

        Wallet {
            config,
            logger_tx,
            node_manager,
            users: vec![user],
            pending_tx: PendingTx {
                receive_addr: "".to_string(),
                amount: 0.0,
            },
            tnxs_history: HashMap::new(),
            available_money: 0.0 as u64,
        }
    }

    pub fn add_user(&mut self, user: User) {
        self.users.push(user);
    }

    // Sends the Tx to the node
    pub fn send(&mut self, message: MessagePayload) {
        log(
            self.logger_tx.clone(),
            format!("Wallet sending message: {:?}", message),
        );
        self.node_manager.send(&message).unwrap();
    }

    // Handler when the wallet receives messages from the node
    pub fn receive(&mut self) {
        let (_addrs, messages) = self.node_manager.receive();

        for message in messages {
            match message {
                MessagePayload::UTXOs(payload) => {
                    let tx = match self.create_tx(
                        payload.utxos,
                        self.users[0].clone(),
                        self.pending_tx.receive_addr.clone(),
                        self.pending_tx.amount,
                    ) {
                        Some(tx) => tx,
                        None => return,
                    };

                    // sign the Tx
                    let signed_tx = Self::sign_tx(tx.clone(), self.users[0].clone());

                    let mut buffer = vec![];
                    let signed_tx_encoded = signed_tx.encode(&mut buffer);

                    let mut offset = 0;
                    let tx_decoded = decode_internal_tx(&signed_tx_encoded, &mut offset).unwrap();

                    println!("Signed Tx id: {:?}", array_to_hex(&(tx_decoded.clone().id)));
                    println!("Signed Tx: {:?}", array_to_hex(&signed_tx_encoded));
                    // send the Tx to the node
                    self.tnxs_history.insert(
                        tx_decoded.clone().id,
                        (
                            tx_decoded.clone(),
                            TxStatus::Unconfirmed,
                            self.pending_tx.receive_addr.clone(),
                            self.pending_tx.amount,
                        ),
                    );
                    self.send(MessagePayload::Tx(signed_tx));
                }
                MessagePayload::TxStatus(payload) => {
                    // update the status of the Tx
                    if payload.status.clone() == TxStatus::Unknown {
                        log(
                            self.logger_tx.clone(),
                            "Transaction Error. Unknown transaction status".to_string(),
                        );
                        continue;
                    }

                    match self.tnxs_history.get(&payload.tx_id) {
                        Some(tx_history) => {
                            self.tnxs_history.insert(
                                payload.tx_id,
                                (
                                    tx_history.0.clone(),
                                    payload.status,
                                    tx_history.2.clone(),
                                    tx_history.3,
                                ),
                            );
                        }
                        None => {
                            log(
                                self.logger_tx.clone(),
                                "Transaction id not found in transaction history".to_string(),
                            );
                        }
                    };
                }
                _ => continue,
            }
        }
    }

    // Returns a Tx (not yet signed)
    fn create_tx(
        &mut self,
        utxos: Vec<Utxo>,
        user: User,
        to_address: String,
        amount: f64,
    ) -> Option<Tx> {
        let mut available_money = 0;
        for i in utxos.iter() {
            available_money += i.value;
        }
        self.available_money = available_money;

        let amount = amount * 100_000_000.0; // amount to send in satoshis
        let fee = 100000.0; // self.config.tx_fee ; // fee for the Tx

        if amount <= 0 as f64 {
            log(self.logger_tx.clone(), "Error: Invalid amount".to_string());
            return None;
        }

        if (available_money as f64) < (amount + fee) {
            log(
                self.logger_tx.clone(),
                "Error: Insufficient funds".to_string(),
            );
            return None;
        }

        let mut tx_ins: Vec<TxIn> = vec![];

        let mut counter = 0.0;

        for i in utxos.iter() {
            if counter >= (amount + fee) {
                break;
            }

            let p2pkh_script = Self::create_p2pkh_script(user.get_pk_hash());

            let mut tx_id = i.transaction_id;
            tx_id.reverse();

            let tx_in = TxIn {
                previous_output: OutPoint {
                    hash: tx_id,
                    index: i.output_index,
                },
                script_length: p2pkh_script.len(),
                signature_script: p2pkh_script.to_vec(),
                sequence: 0xffffffff,
            };

            counter += i.value as f64;
            tx_ins.push(tx_in);
        }

        let change = counter - amount - fee;

        // Design choice.
        // There's always going to be two TxOuts. One for the amount and one for the change.
        let pk_script_amount = Self::create_p2pkh_script(pk_hash_from_addr(&to_address)); // This is the pubHashKey of the receiver

        let tx_out_amount = TxOut {
            value: amount as u64,
            pk_script_length: pk_script_amount.len(),
            pk_script: pk_script_amount,
        };

        let pk_script_change = Self::create_p2pkh_script(user.get_pk_hash()); // This is the pubHashKey of the sender

        let tx_out_change = TxOut {
            value: change as u64,
            pk_script_length: pk_script_change.len(),
            pk_script: pk_script_change,
        };

        let tx_outs: Vec<TxOut> = vec![tx_out_amount, tx_out_change];

        let tx = Tx {
            id: [0; 32],
            version: 1,
            flag: 0,
            tx_in_count: tx_ins.len(),
            tx_in: tx_ins,
            tx_out_count: tx_outs.len(),
            tx_out: tx_outs,
            tx_witness: vec![],
            lock_time: 0,
        };
        Some(tx)
    }

    fn get_sig_input(tx: Tx, index: usize, user: User) -> Vec<u8> {
        let mut modified_tx = tx.clone();

        for (i, tx_in) in tx.tx_in.iter().enumerate() {
            if i == index {
                let mut sig_script_inv = tx_in.signature_script.clone();
                sig_script_inv.reverse();

                // Esto es una coinbase o si es una sigScript invalida
                if tx_in.script_length < 33 {
                    continue;
                }

                // Public Key
                let mut sec_pk = sig_script_inv[0..33].to_vec();
                sec_pk.reverse();

                let pk_hash = hash160::Hash::hash(&sec_pk).to_byte_array();

                let p2pkh_script = Wallet::create_p2pkh_script(pk_hash);

                modified_tx.tx_in[i].signature_script = p2pkh_script.clone();
                modified_tx.tx_in[i].script_length = p2pkh_script.len();
            } else {
                modified_tx.tx_in[i].signature_script = vec![];
                modified_tx.tx_in[i].script_length = 0;
            }
        }

        let mut buffer = vec![];
        let mut tx_bytes = modified_tx.encode(&mut buffer);
        tx_bytes.extend([1, 0, 0, 0]);

        let signature_hash = double_sha256(&tx_bytes).to_byte_array();
        let private_key = user.secret_key;

        let message = Message::from_slice(&signature_hash).unwrap();
        let signature = private_key.sign_ecdsa(message);
        let der = signature.clone().serialize_der().to_vec();
        let sec = user.public_key;

        let mut script_sig: Vec<u8> = vec![];
        script_sig.extend(vec![(der.len() + 1) as u8]);
        script_sig.extend(der);
        script_sig.extend([1]); // SIGHASH_ALL
        script_sig.extend(vec![sec.len() as u8]);
        script_sig.extend(sec);

        script_sig
    }

    // Returns a signed transaction
    fn sign_tx(mut tx: Tx, user: User) -> Tx {
        let copy_tx = tx.clone();

        for (index, _tx_in) in copy_tx.tx_in.iter().enumerate() {
            let script_sig = Wallet::get_sig_input(copy_tx.clone(), index, user.clone());

            tx.tx_in[index].signature_script = script_sig.clone();
            tx.tx_in[index].script_length = script_sig.len();
        }
        tx
    }

    // Returns a p2pkh script from a public key hash
    fn create_p2pkh_script(pk_hash: [u8; 20]) -> Vec<u8> {
        let mut p2pkh_script: Vec<u8> = Vec::new();

        p2pkh_script.extend([118]); // 0x76 = OP_DUP
        p2pkh_script.extend([169]); // 0xa9 = OP_HASH160
        p2pkh_script.extend(vec![pk_hash.len() as u8]);
        p2pkh_script.extend(pk_hash);
        p2pkh_script.extend([136]); // 0x88 = OP_EQUALVERIFY
        p2pkh_script.extend([172]); // 0xac = OP_CHECKSIG

        p2pkh_script
    }

    pub fn create_pending_tx(&mut self, receiver_addr: String, amount: f64) {
        let get_utxo_message = MessagePayload::GetUTXOs(PayloadGetUtxos {
            address: self.users[0].get_pk_hash(),
        });

        // Send message to node
        self.send(get_utxo_message);

        // Save the pending transaction in the wallet. When the UTXOs arrive, the wallet will create the transaction
        self.pending_tx = PendingTx {
            receive_addr: receiver_addr,
            amount,
        };
    }
    pub fn update_balance(&mut self) {
        let get_utxo_message = MessagePayload::GetUTXOs(PayloadGetUtxos {
            address: self.users[0].get_pk_hash(),
        });

        // Send message to node
        self.send(get_utxo_message);

        // Save the pending transaction in the wallet. When the UTXOs arrive, the wallet will create the transaction
        self.pending_tx = PendingTx {
            receive_addr: "".to_string(),
            amount: -1.0,
        };
    }
    pub fn update_txs_history(&mut self) {
        for (_, tx_history) in self.tnxs_history.clone().iter() {
            let tx_cloned = tx_history.0.clone();
            self.send(MessagePayload::GetTxStatus(tx_cloned));
        }
    }
}

#[derive(Clone, Debug)]
pub struct PendingTx {
    pub receive_addr: String,
    pub amount: f64,
}

#[derive(Clone, Debug)]
pub struct User {
    pub name: String,
    pub pk_hash: [u8; 20],
    pub secret_key: SecretKey,
    pub public_key: [u8; 33],
    // pub txns_hist: Vec<Tx>,
}

impl User {
    pub fn new(name: String, priv_key_wif: String, is_anonymous: bool) -> User {
        let mut rng = OsRng::default();
        let secp = Secp256k1::new();

        // Secret Key
        let secret_key = match is_anonymous {
            true => {
                let mut private_key_bytes: [u8; 32] = [0; 32];
                rng.fill(&mut private_key_bytes);

                SecretKey::from_slice(&private_key_bytes).unwrap()
            }
            false => {
                let secret_key_bytes = bs58::decode(priv_key_wif)
                    .with_check(None)
                    .into_vec()
                    .unwrap();

                SecretKey::from_slice(&secret_key_bytes[1..33]).unwrap()
            }
        };

        // Public key
        let public_key = secret_key.public_key(&secp).serialize();

        // Generate address
        let pk_hash = hash160::Hash::hash(&public_key).to_byte_array();

        User {
            name,
            pk_hash,
            secret_key,
            public_key,
        }
    }

    // 33 byte public key
    pub fn get_pub_key(&self) -> [u8; 33] {
        self.public_key
    }

    pub fn get_pk_hash(&self) -> [u8; 20] {
        self.pk_hash
    }

    pub fn get_name(&self) -> String {
        self.name.clone()
    }
}

#[cfg(test)]
mod tests {
    use crate::logger::Logger;
    use crate::net::message::ping_pong::PayloadPingPong;
    use crate::net::message::tx::{OutPoint, Tx, TxIn, TxOut};
    use crate::utils::get_address_base58;

    use super::*;

    #[test]
    fn test_wallet_save_multiple_users() {
        let logger = Logger::mock_logger();
        let config = Config::from_file("nodo.config")
            .map_err(|err| err.to_string())
            .unwrap();

        let user1 = User::new("Alice".to_string(), "".to_string(), true);

        let mut wallet = Wallet::new(config, logger.tx, user1);

        let user2 = User::new("Bob".to_string(), "".to_string(), true);

        wallet.add_user(user2);

        assert_eq!(wallet.users.len(), 2);
    }

    #[test]
    fn test_received_correctly_uxtos() {
        let logger = Logger::mock_logger();
        let config = Config::from_file("nodo.config")
            .map_err(|err| err.to_string())
            .unwrap();

        let user = User::new("Alice".to_string(), "".to_string(), true);

        let _wallet = Wallet::new(config, logger.tx, user);

        // enviar get utxos
        // voy a enviar un msg Payload y quiero recibir una lista de UTXOs

        //let utxo = !vec[]
    }

    #[test]
    fn test_create_anonymous_user_correctly() {
        let user = User::new("Alice".to_string(), "".to_string(), true);

        assert_eq!(user.get_name(), "Alice");
        assert!(!user.get_pk_hash().is_empty());
        assert!(!user.get_pub_key().is_empty());
        // assert!(user.get_tx_hist().is_empty());
    }

    #[test]
    fn test_creates_user_from_priv_key_correctly() {
        let priv_key_wif = "cVK6pF1sfsvvmF9vGyq4wFeMywy1SMFHNpXa3d4Hi2evKHRQyTbn".to_string();
        let address_wif = "mx34LnwGeUD8tc7vR8Ua1tCq4t6ptbjWGb";

        let pub_addr_hashed = bs58::decode(address_wif)
            .with_check(None)
            .into_vec()
            .unwrap();

        let address_bytes = &pub_addr_hashed[1..];

        // [111, 181, 51, 138, 19, 120, 118, 0, 187, 24, 163, 236, 151, 149, 117, 93, 82, 212, 10, 107, 236]
        let user = User::new("bob".to_string(), priv_key_wif, false);

        assert_eq!(user.get_pk_hash(), address_bytes[..]);
        assert_eq!(get_address_base58(user.get_pk_hash()), address_wif);
        assert_eq!(user.get_name(), "bob");
        // assert!(user.get_tx_hist().is_empty());
    }

    #[test]
    fn test_encode_decode_priv_key() {
        // Encodeo
        // Here is how the WIF format is created:
        // 1. For mainnet private keys, start with the prefix 0x80 , for testnet 0xef .
        // 2. Encode the secret in 32-byte big-endian.
        // 3. If the SEC format used for the public key address was compressed, add a suffix of 0x01 .
        // 4. Combine the prefix from #1, serialized secret from #2, and suffix from #3.
        // 5. Do a hash256 of the result from #4 and get the first 4 bytes.
        // 6. Take the combination of #4 and #5 and encode it in Base58.

        let priv_key_wif = "cVK6pF1sfsvvmF9vGyq4wFeMywy1SMFHNpXa3d4Hi2evKHRQyTbn";

        let priv_key_bytes = bs58::decode(priv_key_wif)
            .with_check(None)
            .into_vec()
            .unwrap();

        // Crea la secretKey a partir de los bytes de la clave privada
        // [0xef, secret_key (32 bytes), 0x01]
        let _secret_key = SecretKey::from_slice(&priv_key_bytes[1..33]).unwrap();

        // Encode
        let mut buff = vec![0xef];

        for i in priv_key_bytes[1..33].iter() {
            buff.push(*i);
        }

        buff.push(0x01);

        // buffer has [0xef, ... , 0x01]
        let wif = bs58::encode(buff).with_check().into_string();

        assert_eq!(wif, priv_key_wif);
    }

    #[test]
    fn test_wallet_sends_ping_to_node_manager() -> Result<(), String> {
        let logger = Logger::mock_logger();
        let config = Config::from_file("nodo.config")
            .map_err(|err| err.to_string())
            .unwrap();

        let user = User::new("Alice".to_string(), "".to_string(), true);

        let mut wallet = Wallet::new(config, logger.tx, user);

        let ping_message = MessagePayload::Ping(PayloadPingPong::new());

        wallet.send(ping_message);
        wallet.receive();

        Ok(())
    }

    #[test]
    fn test_wallet_sends_get_tx_status() -> Result<(), String> {
        let logger = Logger::mock_logger();
        let config = Config::from_file("nodo.config")
            .map_err(|err| err.to_string())
            .unwrap();

        let priv_key_wif = "cSM1NQcoCMDP8jy2AMQWHXTLc9d4HjSr7H4AqxKk2bD1ykbaRw59".to_string();
        let messi = User::new("Messi".to_string(), priv_key_wif, false);

        let mut wallet = Wallet::new(config, logger.tx, messi);

        let tx = Tx {
            id: [
                168, 100, 164, 165, 157, 239, 225, 158, 30, 139, 116, 50, 75, 224, 71, 198, 133,
                10, 228, 4, 57, 246, 166, 229, 0, 245, 47, 243, 166, 54, 94, 44,
            ],
            version: 2,
            flag: 0,
            tx_in_count: 1,
            tx_in: vec![TxIn {
                previous_output: OutPoint {
                    hash: [0; 32],
                    index: 255,
                },
                script_length: 18,
                signature_script: vec![
                    3, 206, 247, 1, 5, 82, 126, 227, 169, 4, 0, 0, 0, 0, 14, 0, 0, 0,
                ],
                sequence: 4294967295,
            }],
            tx_out_count: 1,
            tx_out: vec![TxOut {
                value: 5000020000,
                pk_script_length: 25,
                pk_script: vec![
                    118, 169, 20, 195, 208, 147, 199, 86, 220, 79, 141, 216, 23, 181, 3, 198, 78,
                    203, 128, 39, 118, 33, 52, 136, 172,
                ],
            }],
            tx_witness: vec![],
            lock_time: 0,
        };

        let tx_status_message = MessagePayload::GetTxStatus(tx);

        wallet.send(tx_status_message);
        wallet.receive();

        Ok(())
    }

    #[test]
    fn test_wallet_create_tx() -> Result<(), String> {
        let logger = Logger::mock_logger();
        let config = Config::from_file("nodo.config")
            .map_err(|err| err.to_string())
            .unwrap();

        let priv_key_wif = "cSM1NQcoCMDP8jy2AMQWHXTLc9d4HjSr7H4AqxKk2bD1ykbaRw59".to_string();
        let messi = User::new("Messi".to_string(), priv_key_wif, false);

        let receiver_addr = "mx34LnwGeUD8tc7vR8Ua1tCq4t6ptbjWGb".to_string();
        let amount = 0.001544886;

        let mut wallet = Wallet::new(config, logger.tx, messi);

        wallet.create_pending_tx(receiver_addr, amount);

        wallet.receive();

        Ok(())
    }

    #[test]
    fn create_tx() -> Result<(), String> {
        let priv_key_wif = "cSM1NQcoCMDP8jy2AMQWHXTLc9d4HjSr7H4AqxKk2bD1ykbaRw59".to_string();
        let messi = User::new("Messi".to_string(), priv_key_wif, false);

        let pk_hash = messi.get_pk_hash();

        let p2pkh_script_change = Wallet::create_p2pkh_script(pk_hash);

        let mut hash = [
            0xbc, 0xe6, 0x6d, 0x59, 0x5c, 0xff, 0x86, 0x50, 0xac, 0x37, 0xfc, 0x18, 0x17, 0x27,
            0xf1, 0xc5, 0xc6, 0xa8, 0x73, 0x14, 0x09, 0x69, 0x4b, 0x29, 0x70, 0x8f, 0x36, 0x8a,
            0x12, 0x89, 0xcc, 0x7b,
        ];
        hash.reverse();

        let tx_in_1 = TxIn {
            previous_output: OutPoint {
                hash: hash,
                index: 0,
            },
            script_length: p2pkh_script_change.len(),
            signature_script: p2pkh_script_change.to_vec(),
            sequence: 0xffffffff,
        };

        // Target tx_out
        let value = (0.001 * 100_000_000.0) as u64;

        let pk_hash_target = pk_hash_from_addr("mx34LnwGeUD8tc7vR8Ua1tCq4t6ptbjWGb");

        let p2pkh_script_target = Wallet::create_p2pkh_script(pk_hash_target);

        let tx_out_target = TxOut {
            value: value,
            pk_script_length: p2pkh_script_target.len(),
            pk_script: p2pkh_script_target.clone(),
        };

        // Change tx_out
        let change = (0.01102208 * 100_000_000.0) as u64;

        let tx_out_change = TxOut {
            value: change,
            pk_script_length: p2pkh_script_change.len(),
            pk_script: p2pkh_script_change.clone(),
        };

        // Create tx
        let tx = Tx {
            id: [0u8; 32],
            version: 1,
            flag: 0,
            tx_in_count: 1,
            tx_in: vec![tx_in_1],
            tx_out_count: 2,
            tx_out: vec![tx_out_target, tx_out_change],
            tx_witness: vec![],
            lock_time: 0,
        };

        let tx_signed = Wallet::sign_tx(tx, messi);

        let mut buffer = vec![];
        let _final_tx_encode = tx_signed.encode(&mut buffer);
        // println!("tx_signed: {:?}", tx_signed);

        Ok(())
    }
}
