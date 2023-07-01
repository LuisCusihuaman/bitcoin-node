use std::collections::HashMap;
use std::sync::mpsc::Sender;
use std::vec;

use bitcoin_hashes::hash160;
use bitcoin_hashes::Hash;
use bs58::decode;
use rand::rngs::OsRng;
use rand::Rng;
use secp256k1::{Message, Secp256k1, SecretKey};

use crate::logger::log;
use crate::net::message::get_utxos::PayloadGetUtxos;
use crate::net::message::tx::{decode_internal_tx, decode_tx, OutPoint, Tx, TxIn, TxOut};
use crate::net::message::{MessagePayload, TxStatus};
use crate::net::p2p_connection::P2PConnection;
use crate::wallet::config::Config;
use crate::node::utxo::Utxo;
use crate::utils::{array_to_hex, double_sha256, pk_hash_from_addr};

#[derive(Clone)]
pub struct Wallet {
    config: Config,
    logger_tx: Sender<String>,
    node_manager: P2PConnection,
    pub users: Vec<User>,
    pub index_last_active_user: usize,
    // Borrar esto despues
}

impl Wallet {
    pub fn new(config: Config, sender: Sender<String>, users: Vec<User>) -> Wallet {
        let logger_tx = sender.clone();
        let node_manager = P2PConnection::connect(config.node_manager_address.as_str(), sender.clone()).unwrap();

        Wallet {
            config,
            logger_tx,
            node_manager,
            users: users.clone(),
            index_last_active_user: 0,
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
                    self.users[self.index_last_active_user].utxo_available = payload.utxos;
                    self.users[self.index_last_active_user].utxo_updated = true;
                }

                MessagePayload::TxStatus(payload) => {
                    // update the status of the Tx
                    if payload.status.clone() == TxStatus::Unknown {
                        log(
                            self.logger_tx.clone(),
                            format!("Transaction Error. Unknown transaction status"),
                        );
                        continue;
                    }

                    match self.users[self.index_last_active_user].clone().tnxs_history.get(&payload.tx_id) {
                        Some(tx_history) => {
                            self.users[self.index_last_active_user].tnxs_history.insert(
                                payload.tx_id,
                                (
                                    tx_history.0.clone(),
                                    payload.status,
                                    tx_history.2.clone(),
                                    tx_history.3.clone(),
                                ),
                            );
                        }
                        None => {
                            log(
                                self.logger_tx.clone(),
                                format!("Transaction id not found in transaction history"),
                            );
                        }
                    };
                }
                _ => continue,
            }
        }
    }

    // Returns a Tx (not yet signed)
    fn create_tx(&mut self, user: User, to_address: String, amount: f64) -> Option<Tx> {
        self.users[self.index_last_active_user].available_money = self.get_balance();

        let amount = amount * 100_000_000.0; // amount to send in satoshis
        let fee =  self.config.tx_fee; // self.config.tx_fee ; // fee for the Tx

        if amount <= 0 as f64 {
            log(self.logger_tx.clone(), format!("Error: Invalid amount"));
            return None;
        }

        if (self.users[self.index_last_active_user].available_money as f64) < (amount + fee) {
            log(self.logger_tx.clone(), format!("Error: Insufficient funds"));
            return None;
        }

        let mut tx_ins: Vec<TxIn> = vec![];

        let mut counter = 0.0;

        for i in self.users[self.index_last_active_user].utxo_available.clone().iter() {
            if counter >= (amount + fee) {
                break;
            }

            let p2pkh_script = Self::create_p2pkh_script(user.get_pk_hash());

            let mut tx_id = i.transaction_id.clone();
            tx_id.reverse();

            let tx_in = TxIn {
                previous_output: OutPoint {
                    hash: tx_id,
                    index: i.output_index,
                },
                script_length: p2pkh_script.len() as usize,
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
            tx_in_count: tx_ins.len() as usize,
            tx_in: tx_ins,
            tx_out_count: tx_outs.len() as usize,
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
        let signature = private_key.sign_ecdsa(message.clone());
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

    // Creates TX in a pending status
    pub fn create_pending_tx(&mut self, receiver_addr: String, amount: f64) {
        // Get the UTXOs from the node
        self.update_balance();

        // Save the pending transaction in the wallet. When the UTXOs arrive, the wallet will create the transaction
        self.users[self.index_last_active_user].pending_tx = PendingTx {
            receive_addr: receiver_addr,
            amount,
        };
    }

    // Sends any pending transaction that's in the wallet
    pub fn send_pending_tx(&mut self) {
        if self.users[self.index_last_active_user].utxo_updated == false && self.users[self.index_last_active_user].pending_tx.receive_addr == "".to_string() {
            // log(
            //     self.logger_tx.clone(),
            //     format!("Transaction Error. Balance outdated"),
            // );
            return;
        }

        let tx = match self.create_tx(
            self.users[self.index_last_active_user].clone(),
            self.users[self.index_last_active_user].pending_tx.receive_addr.clone(),
            self.users[self.index_last_active_user].pending_tx.amount,
        ) {
            Some(tx) => tx,
            None => return,
        };

        // sign the Tx
        let signed_tx = Self::sign_tx(tx.clone(), self.users[self.index_last_active_user].clone());

        let mut buffer = vec![];
        let signed_tx_encoded = signed_tx.encode(&mut buffer);

        let mut offset = 0;
        let tx_decoded = decode_internal_tx(&signed_tx_encoded, &mut offset).unwrap();

        println!("Signed Tx id: {:?}", array_to_hex(&(tx_decoded.clone().id)));
        println!("Signed Tx: {:?}", array_to_hex(&signed_tx_encoded));

        let addr = self.users[self.index_last_active_user].pending_tx.receive_addr.clone();
        let amount = self.users[self.index_last_active_user].pending_tx.amount;

        // send the Tx to the node
        self.users[self.index_last_active_user].tnxs_history.insert(
            tx_decoded.clone().id,
            (
                tx_decoded.clone(),
                TxStatus::Unconfirmed,
                addr,
                amount,
            ),
        );
        self.send(MessagePayload::Tx(signed_tx));
        self.users[self.index_last_active_user].utxo_updated = false;
        self.users[self.index_last_active_user].pending_tx = PendingTx {
            receive_addr: "".to_string(),
            amount: 0.0,
        };
    }

    // Updates the balances of the wallet
    pub fn update_balance(&mut self) {
        let get_utxo_message = MessagePayload::GetUTXOs(PayloadGetUtxos {
            address: self.users[self.index_last_active_user].get_pk_hash(),
        });

        // Send message to node
        self.send(get_utxo_message);
    }

    // Returns the balance of the wallet
    pub fn get_balance(&mut self) -> u64 {
        let mut available_money = 0;

        for i in self.users[self.index_last_active_user].utxo_available.iter() {
            available_money += i.value;
        }

        available_money
    }

    pub fn update_txs_history(&mut self) {
        for (_, tx_history) in self.users[self.index_last_active_user].tnxs_history.clone().iter() {
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
    pub tnxs_history: HashMap<[u8; 32], (Tx, TxStatus, String, f64)>, //tnxs_history: Vec<(TxStatus, Tx)>, // puede ser un struct
    pub utxo_available: Vec<Utxo>,
    pub available_money: u64,
    pub utxo_updated: bool,
    pub pending_tx: PendingTx,
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
            utxo_available: vec![],
            tnxs_history: HashMap::new(),
            available_money: 0.0 as u64,
            utxo_updated: false,
            pending_tx: PendingTx {
                receive_addr: "".to_string(),
                amount: 0.0,
            },
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

        let mut wallet = Wallet::new(config, logger.tx, vec![user1]);

        let user2 = User::new("Bob".to_string(), "".to_string(), true);

        wallet.add_user(user2);

        assert_eq!(wallet.users.len(), 2);
    }

    #[test]
    fn test_create_one_active_user(){
        let logger = Logger::mock_logger();
        let config = Config::from_file("nodo.config")
            .map_err(|err| err.to_string())
            .unwrap();

        let priv_key_wif = "cSM1NQcoCMDP8jy2AMQWHXTLc9d4HjSr7H4AqxKk2bD1ykbaRw59".to_string();
        let messi = User::new("Messi".to_string(), priv_key_wif, false);

        let mut wallet = Wallet::new(config, logger.tx, vec![messi]);

        assert_eq!(wallet.users.len(), 1);

        let priv_key_wif = "cVK6pF1sfsvvmF9vGyq4wFeMywy1SMFHNpXa3d4Hi2evKHRQyTbn".to_string();
        let maradona = User::new("Messi".to_string(), priv_key_wif, false);

        wallet.add_user(maradona);
        assert_eq!(wallet.users.len(), 2);
    }


    #[test]
    fn test_create_tx_from_user_one(){
        let logger = Logger::mock_logger();
        let config = Config::from_file("nodo.config")
            .map_err(|err| err.to_string())
            .unwrap();

        let priv_key_wif = "cSM1NQcoCMDP8jy2AMQWHXTLc9d4HjSr7H4AqxKk2bD1ykbaRw59".to_string();
        let messi = User::new("Messi".to_string(), priv_key_wif, false);

        let mut wallet = Wallet::new(config, logger.tx, vec![messi]);

        assert_eq!(wallet.users.len(), 1);

        let priv_key_wif = "cVK6pF1sfsvvmF9vGyq4wFeMywy1SMFHNpXa3d4Hi2evKHRQyTbn".to_string();
        let maradona = User::new("Messi".to_string(), priv_key_wif, false);

        wallet.add_user(maradona);
        assert_eq!(wallet.users.len(), 2);

        let receiver_addr = "mx34LnwGeUD8tc7vR8Ua1tCq4t6ptbjWGb".to_string();
        let amount = 0.001544886;

        // User one creates Tx
        wallet.create_pending_tx(receiver_addr, amount, );

    }

    #[test]
    fn test_received_correctly_uxtos() {
        let logger = Logger::mock_logger();
        let config = Config::from_file("nodo.config")
            .map_err(|err| err.to_string())
            .unwrap();

        let user = User::new("Alice".to_string(), "".to_string(), true);

        let _wallet = Wallet::new(config, logger.tx, vec![user]);

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

        let mut wallet = Wallet::new(config, logger.tx, vec![user]);

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

        let mut wallet = Wallet::new(config, logger.tx, vec![messi]);

        let tx = Tx {
            id: [
                168, 100, 164, 165, 157, 239, 225, 158, 30, 139, 116, 50, 75, 224, 71, 198, 133,
                10, 228, 4, 57, 246, 166, 229, 0, 245, 47, 243, 166, 54, 94, 44,
            ], // the trhurut
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
        // Primer cuenta
        // bitcoin_address: mx34LnwGeUD8tc7vR8Ua1tCq4t6ptbjWGb
        // secret_secret: cVK6pF1sfsvvmF9vGyq4wFeMywy1SMFHNpXa3d4Hi2evKHRQyTbn

        // Segunda cuenta
        // bitcoin_address: mpiQbuypLNHoUCXeFtrS956jPSNhwmYwai
        // secret_key: cSM1NQcoCMDP8jy2AMQWHXTLc9d4HjSr7H4AqxKk2bD1ykbaRw59

        let logger = Logger::mock_logger();
        let config = Config::from_file("nodo.config")
            .map_err(|err| err.to_string())
            .unwrap();

        let priv_key_wif = "cSM1NQcoCMDP8jy2AMQWHXTLc9d4HjSr7H4AqxKk2bD1ykbaRw59".to_string();
        let messi = User::new("Messi".to_string(), priv_key_wif, false);

        let receiver_addr = "mx34LnwGeUD8tc7vR8Ua1tCq4t6ptbjWGb".to_string();
        let amount = 0.001544886;

        let mut wallet = Wallet::new(config, logger.tx, vec![messi]);

        wallet.create_pending_tx(receiver_addr, amount);

        wallet.receive();

        Ok(())
    }
}
