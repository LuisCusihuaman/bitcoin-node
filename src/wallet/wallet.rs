use crate::config::Config;
use crate::logger::log;
use crate::net::message::get_utxos::PayloadGetUtxos;
use crate::net::message::tx::{OutPoint, Tx, TxIn, TxOut};
use crate::net::message::MessagePayload;
use crate::net::p2p_connection::P2PConnection;
use crate::node::utxo::Utxo;
use crate::utils::pk_hash_from_addr;
use bitcoin_hashes::hash160;
use bitcoin_hashes::Hash;
use rand::rngs::OsRng;
use rand::Rng;
use secp256k1::{Secp256k1, SecretKey};
use std::sync::mpsc::Sender;
use std::vec;

pub struct Wallet {
    config: Config,
    logger_tx: Sender<String>,
    node_manager: P2PConnection,
    users: Vec<User>,
}

impl Wallet {
    pub fn new(config: Config, sender: Sender<String>) -> Wallet {
        let logger_tx = sender.clone();
        let node_manager = P2PConnection::connect("127.0.0.1:8080", sender.clone()).unwrap();

        Wallet {
            config,
            logger_tx,
            node_manager,
            users: Vec::new(),
        }
    }

    pub fn add_user(&mut self, user: User) {
        self.users.push(user);
    }

    pub fn send(&mut self, message: MessagePayload) {
        log(
            self.logger_tx.clone(),
            format!("Wallet sending message: {:?}", message),
        );
        self.node_manager.send(&message).unwrap();
    }

    // Wallet --> Nodo
    // espero espero espero (bloqueante)
    // Nodo --> Wallet
    // va a hacer cosas

    // Wallet --> Nodo, dame las utxos
    // FIN
    // Nodo --> Wallet utxos
    // wallet crea tx con esas utxos (si puede)

    pub fn receive(&mut self) {
        let (_addrs, messages) = self.node_manager.receive();
        for message in messages {
            match message {
                MessagePayload::UTXOs(payload) => {
                    let tx = match self.create_tx(payload.utxos) {
                        Some(tx) => tx,
                        None => continue,
                    };

                    // sign the Tx
                    let signed_tx = self.sign_tx(tx);

                    // send the Tx to the node
                    self.send(MessagePayload::Tx(signed_tx));
                }

                _ => continue,
            }
        }
    }

    fn create_tx(&mut self, utxos: Vec<Utxo>) -> Option<Tx> {
        // Validating Transactions

        // 1. The inputs of the transaction are previously unspent. The fact that we ask the node for the UTXOs
        //  associated with the address means that they are unspent.

        // The sum of the inputs is greater than or equal to the sum of the outputs.
        let mut available_money = 0;
        for i in utxos.iter() {
            if !self.tx_verified(i) {
                // Verify the sigScript
                log(
                    self.logger_tx.clone(),
                    format!("Could not verify transaction {:?} ", i),
                );
                continue; // should return at this point
            }
            available_money += i.value;
        }

        // Fix this numbers
        let amount = 10.0; // amount if the amount of money to send
        let fee = 0.1; // fee for the Tx

        if (available_money as f64) < (amount + fee) {
            log(self.logger_tx.clone(), format!("Error: Insufficient funds"));
            return None;
        }

        // Utxos have been verified at this point. We create the Tx_in for each Utxo

        let mut tx_ins: Vec<TxIn> = vec![];

        // Create the TxIns from UTXOs
        for i in utxos.iter() {
            let sig_script = vec![];
            // TODO: Create sig_script

            let tx_in = TxIn {
                previous_output: OutPoint {
                    hash: i.transaction_id,
                    index: i.output_index,
                },
                script_length: sig_script.len() as usize,
                signature_script: sig_script,
                sequence: 0, // Verify this
            };
            tx_ins.push(tx_in);
        }

        // Create the TxOuts
        let change = (available_money as f64) - amount - fee;

        // create pk_script for each TxOut

        // Design choice. There's always going to be two TxOuts. One for the amount and one for the change.

        let mut pk_script_amount = vec![]; // This is the pubHashKey of the receiver

        // TODO: Create pk_script_amount

        // This TxOut for the amount goes to the receiver
        // Here I need the pubHashKey of the receiver
        let tx_out_amount = TxOut {
            value: amount as u64,
            pk_script_length: pk_script_amount.len(),
            pk_script: pk_script_amount,
        };

        // This tx_out_change goes to the sender
        // Here I need the pubHashKey of the sender (The User that owns the wallet)

        let mut pk_script_change = vec![]; // This is the pubHashKey of the sender

        let tx_out_change = TxOut {
            value: change as u64,
            pk_script_length: pk_script_change.len(),
            pk_script: pk_script_change,
        };

        // list of tx_outs for the Tx
        let tx_outs: Vec<TxOut> = vec![tx_out_amount, tx_out_change];

        // Create the Tx to send to the node
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

    // Necesito recibir aca

    // * Amount to spend
    // * Address to send
    // * UTXOs to spend

    // Verify that the ScriptSig successfully unlocks the previous ScriptPubKey.
    fn tx_verified(&mut self, utxo: &Utxo) -> bool {
        true
    }

    fn sign_tx(&mut self, tx: Tx) -> Tx {
        tx
    }

    // Raul quiere crear una transacción para Roberto, de 10 patacones.
    // wallet.create_tx(from, to, amount); Termina lo que ve Raul

    // Wallet le pide al nodo las UTXOs de Raul
    // Nodo le envía a Wallet las UTXOs de Raul
    // Wallet crea la transacción

    fn create_pending_tx(&mut self, mut sender: User, receiver: &str, amount: f64) {
        let addr_receiver = pk_hash_from_addr(receiver);

        // Create send utxo message
        let get_utxo_message = MessagePayload::GetUTXOs(PayloadGetUtxos {
            address: sender.get_pk_hash(),
        });

        // Send message to node
        self.send(get_utxo_message);

        // Save the pending transaction
        let pending = PendingTx {
            from: sender.get_pk_hash(),
            to: addr_receiver,
            amount: amount,
            created: false,
        };

        sender.pending_tx.push(pending); // Otro nombre
    }
}

#[derive(Clone, Debug)]
pub struct PendingTx {
    from: [u8; 20],
    to: [u8; 20],
    amount: f64,
    created: bool,
}

#[derive(Clone, Debug)]
pub struct User {
    pub name: String,
    pub pk_hash: [u8; 20],
    pub secret_key_bytes: Vec<u8>,
    pub secret_key: SecretKey,
    pub public_key: [u8; 33],
    pub txns_hist: Vec<Tx>,
    pub pending_tx: Vec<PendingTx>, // TODO quizas alcanza solo con el vector de arriba
}

impl User {
    pub fn new(name: String, priv_key_wif: String, is_anonymous: bool) -> User {
        let mut rng = OsRng::default();
        let secp = Secp256k1::new();

        // Secret Key
        let secret_key_bytes = match is_anonymous {
            true => {
                let mut private_key_bytes: [u8; 32] = [0; 32];
                rng.fill(&mut private_key_bytes);

                private_key_bytes.to_vec()
            }
            false => bs58::decode(priv_key_wif)
                .with_check(None)
                .into_vec()
                .unwrap(),
        };

        let secret_key = SecretKey::from_slice(&secret_key_bytes[1..33]).unwrap();

        // Public key
        let public_key = secret_key.public_key(&secp).serialize();

        // Generate address
        let pk_hash = hash160::Hash::hash(&public_key).to_byte_array();

        User {
            name,
            pk_hash,
            secret_key_bytes,
            secret_key,
            public_key,
            txns_hist: Vec::new(),
            pending_tx: Vec::new(),
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

    pub fn get_tx_hist(&self) -> Vec<Tx> {
        self.txns_hist.clone()
    }
}

#[cfg(test)]
mod tests {
    use bitcoin_hashes::sha256;
    use bs58::decode;
    use secp256k1::ffi::{secp256k1_ecdsa_signature_serialize_der, PublicKey};
    use secp256k1::Message;

    use super::*;
    use crate::logger::Logger;
    use crate::net::message::ping_pong::PayloadPingPong;
    use crate::net::message::tx::{decode_internal_tx, OutPoint, Tx, TxIn, TxOut};
    use crate::utils::{double_sha256, get_address_base58};

    #[test]
    fn test_wallet_save_multiple_users() {
        let logger = Logger::mock_logger();
        let config = Config::from_file("nodo.config")
            .map_err(|err| err.to_string())
            .unwrap();

        let mut wallet = Wallet::new(config, logger.tx);

        let user1 = User::new("Alice".to_string(), "".to_string(), true);
        let user2 = User::new("Bob".to_string(), "".to_string(), true);

        wallet.add_user(user1);
        wallet.add_user(user2);

        assert_eq!(wallet.users.len(), 2);
    }

    #[test]
    fn test_received_correctly_uxtos() {
        let logger = Logger::mock_logger();
        let config = Config::from_file("nodo.config")
            .map_err(|err| err.to_string())
            .unwrap();

        let mut wallet = Wallet::new(config, logger.tx);

        let user = User::new("Alice".to_string(), "".to_string(), true);

        wallet.add_user(user);

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
        assert!(user.get_tx_hist().is_empty());
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
        assert!(user.get_tx_hist().is_empty());
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

        let mut wallet = Wallet::new(config, logger.tx);

        let ping_message = MessagePayload::Ping(PayloadPingPong::new());

        wallet.send(ping_message);
        wallet.receive();

        Ok(())
    }

    #[test]
    fn test_wallet_create_tx() -> Result<(), String> {
        let logger = Logger::mock_logger();
        let config = Config::from_file("nodo.config")
            .map_err(|err| err.to_string())
            .unwrap();

        let mut wallet = Wallet::new(config, logger.tx);

        let priv_key_wif = "cVK6pF1sfsvvmF9vGyq4wFeMywy1SMFHNpXa3d4Hi2evKHRQyTbn".to_string();
        let messi = User::new("Messi".to_string(), priv_key_wif, false);

        wallet.add_user(messi.clone());

        wallet.create_pending_tx(messi.clone(), "mx34LnwGeUD8tc7vR8Ua1tCq4t6ptbjWGb", 10.0);

        wallet.receive();

        Ok(())
    }

    #[test]
    fn create_tx_from_jimmy_song() -> Result<(), String> {
        let priv_key_wif = "cSM1NQcoCMDP8jy2AMQWHXTLc9d4HjSr7H4AqxKk2bD1ykbaRw59".to_string();

        let messi = User::new("Messi".to_string(), priv_key_wif, false);

        let tx_in_1 = TxIn {
            previous_output: OutPoint {
                hash: [
                    0xbc, 0xe6, 0x6d, 0x59, 0x5c, 0xff, 0x86, 0x50, 0xac, 0x37, 0xfc, 0x18, 0x17,
                    0x27, 0xf1, 0xc5, 0xc6, 0xa8, 0x73, 0x14, 0x09, 0x69, 0x4b, 0x29, 0x70, 0x8f,
                    0x36, 0x8a, 0x12, 0x89, 0xcc, 0x7b,
                ],
                index: 1,
            },
            script_length: 0, // signature_script.len(),
            signature_script: vec![],
            sequence: 4294967294,
        };

        // Target tx_out
        let value = (0.001 * 100_000_000.0) as u64;

        let mut p2kh_script_target: Vec<u8> = Vec::new();
        p2kh_script_target.extend([0x76]); // 0x76 = OP_DUP
        p2kh_script_target.extend([0xa9]); // 0xa9 = OP_HASH160
        p2kh_script_target.extend(pk_hash_from_addr("mx34LnwGeUD8tc7vR8Ua1tCq4t6ptbjWGb"));
        p2kh_script_target.extend([0x88]); // 0x88 = OP_EQUALVERIFY
        p2kh_script_target.extend([0xac]); // 0xac = OP_CHECKSIG

        let tx_out_target = TxOut {
            value: value,
            pk_script_length: p2kh_script_target.len(),
            pk_script: p2kh_script_target.clone(),
        };

        // Change tx_out
        let change = (0.01102208 * 100_000_000.0) as u64;

        let mut p2pkh_script_change: Vec<u8> = Vec::new();
        p2pkh_script_change.extend([0x76]); // 0x76 = OP_DUP
        p2pkh_script_change.extend([0xa9]); // 0xa9 = OP_HASH160
        p2pkh_script_change.extend(messi.get_pk_hash());
        p2pkh_script_change.extend([0x88]); // 0x88 = OP_EQUALVERIFY
        p2pkh_script_change.extend([0xac]); // 0xac = OP_CHECKSIG

        let tx_out_change = TxOut {
            value: change,
            pk_script_length: p2pkh_script_change.len(),
            pk_script: p2pkh_script_change.clone(),
        };

        // Create tx
        let mut tx = Tx {
            id: [0u8; 32], // Se rellena despues
            version: 1,
            flag: 0,
            tx_in_count: 1,
            tx_in: vec![tx_in_1],
            tx_out_count: 2,
            tx_out: vec![tx_out_target, tx_out_change],
            tx_witness: vec![],
            lock_time: 0,
        };

        let mut buffer = [0u8; 1];
        let mut tx_bytes = tx.encode(&mut buffer);

        tx_bytes.extend([0x01, 0x00, 0x00, 0x00]);

        // firmar la transaccion
        let private_key = messi.secret_key;

        let signature_hash = sha256::Hash::hash(&tx_bytes).to_byte_array(); // signature hash

        let secp = Secp256k1::new();
        let message = Message::from_slice(&signature_hash).unwrap();
        let signature = secp.sign_ecdsa(&message.clone(), &private_key);
        let signature_bytes = signature.clone().serialize_der().to_vec();

        tx.tx_in[0].signature_script = signature_bytes.clone();
        tx.tx_in[0].script_length = signature_bytes.len();

        let expected_bytes = [
            1, 0, 0, 0, 1, 129, 63, 121, 1, 26, 203, 128, 146, 93, 254, 105, 179, 222, 243, 85,
            254, 145, 75, 209, 217, 106, 63, 95, 113, 191, 131, 3, 198, 169, 137, 199, 209, 0, 0,
            0, 0, 107, 72, 48, 69, 2, 33, 0, 237, 129, 255, 25, 46, 117, 163, 253, 35, 4, 0, 77,
            202, 219, 116, 111, 165, 226, 76, 80, 49, 204, 252, 242, 19, 32, 176, 39, 116, 87, 201,
            143, 2, 32, 122, 152, 109, 149, 92, 110, 12, 179, 93, 68, 106, 137, 211, 245, 97, 0,
            244, 215, 246, 120, 1, 195, 25, 103, 116, 58, 156, 142, 16, 97, 91, 237, 1, 33, 3, 73,
            252, 78, 99, 30, 54, 36, 165, 69, 222, 63, 137, 245, 216, 104, 76, 123, 129, 56, 189,
            148, 189, 213, 49, 210, 226, 19, 191, 1, 107, 39, 138, 254, 255, 255, 255, 2, 161, 53,
            239, 1, 0, 0, 0, 0, 25, 118, 169, 20, 188, 59, 101, 77, 202, 126, 86, 176, 77, 202, 24,
            242, 86, 108, 218, 240, 46, 141, 154, 218, 136, 172, 153, 195, 152, 0, 0, 0, 0, 0, 25,
            118, 169, 20, 28, 75, 199, 98, 221, 84, 35, 227, 50, 22, 103, 2, 203, 117, 244, 13,
            247, 159, 234, 18, 136, 172, 25, 67, 6, 0,
        ];

        println!("tx_bytes: {:?}", tx_bytes);

        let mut offset = 0;
        let expected_bytes = decode_internal_tx(&expected_bytes, &mut offset).unwrap();

        assert!(tx.version == expected_bytes.version);
        assert!(tx.flag == expected_bytes.flag);
        assert!(tx.tx_in_count == expected_bytes.tx_in_count);
        assert!(tx.tx_out_count == expected_bytes.tx_out_count);
        assert!(tx.tx_witness == expected_bytes.tx_witness);
        assert!(tx.lock_time == expected_bytes.lock_time);

        Ok(())
    }

    #[test]
    fn create_tx() -> Result<(), String> {
        let priv_key_wif = "cSM1NQcoCMDP8jy2AMQWHXTLc9d4HjSr7H4AqxKk2bD1ykbaRw59".to_string();
        let messi = User::new("Messi".to_string(), priv_key_wif, false);

        let pk_hash = messi.get_pk_hash();

        let mut p2pkh_script_change: Vec<u8> = Vec::new();
        p2pkh_script_change.extend([118]); // 0x76 = OP_DUP
        p2pkh_script_change.extend([169]); // 0xa9 = OP_HASH160
        p2pkh_script_change.extend(vec![pk_hash.len() as u8]);
        p2pkh_script_change.extend(pk_hash);
        p2pkh_script_change.extend([136]); // 0x88 = OP_EQUALVERIFY
        p2pkh_script_change.extend([172]); // 0xac = OP_CHECKSIG

        // In this example, we will pay 0.1 testnet bitcoins (tBTC) to mx34LnwGeUD8tc7vR8Ua1tCq4t6ptbjWGb (nuestra otra cuenta)
        // we have an output denoted by a transaction ID and output index bce66d595cff8650ac37fc181727f1c5c6a8731409694b29708f368a1289cc7b:0
        // (0.01302208 tBTC) we’ll send the bitcoins back to outselves to mpiQbuypLNHoUCXeFtrS956jPSNhwmYwai (nuestra cuenta actual)

        // 0.01302208 BTC in wallet
        // 0.001 BTC for fee
        // 0.001 BTC to send
        // 0.01102208 BTC to receive

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
        //let aux = hash160::Hash::hash(&pk_hash_target).to_byte_array();

        let mut p2pkh_script_target: Vec<u8> = Vec::new();
        p2pkh_script_target.extend([118]); // 0x76 = OP_DUP
        p2pkh_script_target.extend([169]); // 0xa9 = OP_HASH160
        p2pkh_script_target.extend(vec![pk_hash_target.len() as u8]); // Length pk_hash
        p2pkh_script_target.extend(pk_hash_target);
        p2pkh_script_target.extend([136]); // 0x88 = OP_EQUALVERIFY
        p2pkh_script_target.extend([172]); // 0xac = OP_CHECKSIG

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
        let mut tx = Tx {
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

        let mut buffer = [0u8; 1];
        let mut tx_bytes = tx.encode(&mut buffer);
        tx_bytes.extend([1, 0, 0, 0]);

        let signature_hash = double_sha256(&tx_bytes).to_byte_array();

        // firmar la transaccion
        let private_key = messi.secret_key;

        let message = Message::from_slice(&signature_hash).unwrap();
        let signature = private_key.sign_ecdsa(message.clone());
        let der = signature.clone().serialize_der().to_vec();
        let sec = messi.public_key;

        let mut script_sig: Vec<u8> = Vec::new();
        script_sig.extend(vec![(der.len() + 1) as u8]);
        script_sig.extend(der);
        script_sig.extend([1]); // SIGHASH_ALL
        script_sig.extend(vec![sec.len() as u8]);
        script_sig.extend(sec);

        tx.tx_in[0].signature_script = script_sig.clone();
        tx.tx_in[0].script_length = script_sig.len();

        let final_tx_encode = tx.encode(&mut buffer);
        println!("final_tx_encode: {:?}", final_tx_encode);

        Ok(())
    }

    #[test]
    fn decode_jimmy_song_raw_tx() {
        let buffer = [
            1, 0, 0, 0, 1, 129, 63, 121, 1, 26, 203, 128, 146, 93, 254, 105, 179, 222, 243, 85,
            254, 145, 75, 209, 217, 106, 63, 95, 113, 191, 131, 3, 198, 169, 137, 199, 209, 0, 0,
            0, 0, 107, 72, 48, 69, 2, 33, 0, 237, 129, 255, 25, 46, 117, 163, 253, 35, 4, 0, 77,
            202, 219, 116, 111, 165, 226, 76, 80, 49, 204, 252, 242, 19, 32, 176, 39, 116, 87, 201,
            143, 2, 32, 122, 152, 109, 149, 92, 110, 12, 179, 93, 68, 106, 137, 211, 245, 97, 0,
            244, 215, 246, 120, 1, 195, 25, 103, 116, 58, 156, 142, 16, 97, 91, 237, 1, 33, 3, 73,
            252, 78, 99, 30, 54, 36, 165, 69, 222, 63, 137, 245, 216, 104, 76, 123, 129, 56, 189,
            148, 189, 213, 49, 210, 226, 19, 191, 1, 107, 39, 138, 254, 255, 255, 255, 2, 161, 53,
            239, 1, 0, 0, 0, 0, 25, 118, 169, 20, 188, 59, 101, 77, 202, 126, 86, 176, 77, 202, 24,
            242, 86, 108, 218, 240, 46, 141, 154, 218, 136, 172, 153, 195, 152, 0, 0, 0, 0, 0, 25,
            118, 169, 20, 28, 75, 199, 98, 221, 84, 35, 227, 50, 22, 103, 2, 203, 117, 244, 13,
            247, 159, 234, 18, 136, 172, 25, 67, 6, 0,
        ];

        let mut offset: usize = 0;
        let _tx = decode_internal_tx(&buffer, &mut offset);

        let _tx = Tx {
            id: [
                69, 44, 98, 157, 103, 228, 27, 174, 195, 172, 111, 4, 254, 116, 75, 75, 150, 23,
                248, 248, 89, 198, 59, 48, 2, 248, 104, 78, 122, 79, 238, 3,
            ],
            version: 1,
            flag: 0,
            tx_in_count: 1,
            tx_in: [TxIn {
                previous_output: OutPoint {
                    hash: [
                        1, 0, 0, 0, 1, 129, 63, 121, 1, 26, 203, 128, 146, 93, 254, 105, 179, 222,
                        243, 85, 254, 145, 75, 209, 217, 106, 63, 95, 113, 191, 131, 3,
                    ],
                    index: 3347687878,
                },
                script_length: 107,
                signature_script: [
                    72, 48, 69, 2, 33, 0, 237, 129, 255, 25, 46, 117, 163, 253, 35, 4, 0, 77, 202,
                    219, 116, 111, 165, 226, 76, 80, 49, 204, 252, 242, 19, 32, 176, 39, 116, 87,
                    201, 143, 2, 32, 122, 152, 109, 149, 92, 110, 12, 179, 93, 68, 106, 137, 211,
                    245, 97, 0, 244, 215, 246, 120, 1, 195, 25, 103, 116, 58, 156, 142, 16, 97, 91,
                    237, 1, 33, 3, 73, 252, 78, 99, 30, 54, 36, 165, 69, 222, 63, 137, 245, 216,
                    104, 76, 123, 129, 56, 189, 148, 189, 213, 49, 210, 226, 19, 191, 1, 107, 39,
                    138,
                ]
                .to_vec(),
                sequence: 4294967294,
            }]
            .to_vec(),
            tx_out_count: 2,
            tx_out: [
                TxOut {
                    value: 32454049,
                    pk_script_length: 25,
                    pk_script: [
                        118, 169, 20, 188, 59, 101, 77, 202, 126, 86, 176, 77, 202, 24, 242, 86,
                        108, 218, 240, 46, 141, 154, 218, 136, 172,
                    ]
                    .to_vec(),
                },
                TxOut {
                    value: 10011545,
                    pk_script_length: 25,
                    pk_script: [
                        118, 169, 20, 28, 75, 199, 98, 221, 84, 35, 227, 50, 22, 103, 2, 203, 117,
                        244, 13, 247, 159, 234, 18, 136, 172,
                    ]
                    .to_vec(),
                },
            ]
            .to_vec(),
            tx_witness: vec![],
            lock_time: 410393,
        };
    }

    #[test]
    fn decode_raw_tx() {
        let buffer = [
            1, 0, 0, 0, 1, 123, 204, 137, 18, 138, 54, 143, 112, 41, 75, 105, 9, 20, 115, 168, 198,
            197, 241, 39, 23, 24, 252, 55, 172, 80, 134, 255, 92, 89, 109, 230, 188, 0, 0, 0, 0,
            107, 72, 48, 69, 2, 33, 0, 203, 253, 67, 149, 211, 148, 156, 140, 100, 15, 122, 117,
            247, 249, 33, 236, 47, 140, 133, 58, 221, 62, 150, 10, 177, 115, 126, 64, 202, 57, 76,
            34, 2, 32, 1, 204, 159, 233, 122, 6, 203, 175, 22, 6, 217, 125, 106, 91, 162, 199, 117,
            104, 135, 14, 74, 240, 91, 3, 239, 161, 163, 163, 68, 92, 207, 179, 1, 33, 2, 20, 28,
            142, 103, 244, 6, 181, 130, 126, 50, 140, 1, 132, 188, 50, 59, 67, 144, 104, 43, 227,
            97, 153, 206, 105, 1, 12, 47, 189, 173, 128, 172, 255, 255, 255, 255, 2, 160, 134, 1,
            0, 0, 0, 0, 0, 25, 118, 169, 20, 181, 51, 138, 19, 120, 118, 0, 187, 24, 163, 236, 151,
            149, 117, 93, 82, 212, 10, 107, 236, 136, 172, 128, 209, 16, 0, 0, 0, 0, 0, 25, 118,
            169, 20, 100, 227, 171, 27, 188, 160, 210, 116, 110, 81, 97, 65, 97, 169, 21, 128, 49,
            207, 184, 237, 136, 172, 0, 0, 0, 0,
        ];

        let mut offset: usize = 0;
        let tx = decode_internal_tx(&buffer, &mut offset).unwrap();

        println!("{:?}", tx);

        let _tx = Tx {
            id: [
                133, 217, 57, 200, 73, 106, 219, 243, 193, 21, 245, 3, 96, 166, 138, 170, 54, 70,
                208, 0, 24, 11, 153, 161, 153, 188, 114, 199, 62, 224, 54, 204,
            ],
            version: 1,
            flag: 0,
            tx_in_count: 1,
            tx_in: [TxIn {
                previous_output: OutPoint {
                    hash: [
                        1, 0, 0, 0, 1, 123, 204, 137, 18, 138, 54, 143, 112, 41, 75, 105, 9, 20,
                        115, 168, 198, 197, 241, 39, 23, 24, 252, 55, 172, 80, 134, 255,
                    ],
                    index: 3865925980,
                },
                script_length: 107,
                signature_script: [
                    72, 48, 69, 2, 33, 0, 203, 253, 67, 149, 211, 148, 156, 140, 100, 15, 122, 117,
                    247, 249, 33, 236, 47, 140, 133, 58, 221, 62, 150, 10, 177, 115, 126, 64, 202,
                    57, 76, 34, 2, 32, 1, 204, 159, 233, 122, 6, 203, 175, 22, 6, 217, 125, 106,
                    91, 162, 199, 117, 104, 135, 14, 74, 240, 91, 3, 239, 161, 163, 163, 68, 92,
                    207, 179, 1, 33, 2, 20, 28, 142, 103, 244, 6, 181, 130, 126, 50, 140, 1, 132,
                    188, 50, 59, 67, 144, 104, 43, 227, 97, 153, 206, 105, 1, 12, 47, 189, 173,
                    128, 172,
                ]
                .to_vec(),
                sequence: 4294967295,
            }]
            .to_vec(),
            tx_out_count: 2,
            tx_out: [
                TxOut {
                    value: 100000,
                    pk_script_length: 25,
                    pk_script: [
                        118, 169, 20, 181, 51, 138, 19, 120, 118, 0, 187, 24, 163, 236, 151, 149,
                        117, 93, 82, 212, 10, 107, 236, 136, 172,
                    ]
                    .to_vec(),
                },
                TxOut {
                    value: 1102208,
                    pk_script_length: 25,
                    pk_script: [
                        118, 169, 20, 100, 227, 171, 27, 188, 160, 210, 116, 110, 81, 97, 65, 97,
                        169, 21, 128, 49, 207, 184, 237, 136, 172,
                    ]
                    .to_vec(),
                },
            ]
            .to_vec(),
            tx_witness: vec![],
            lock_time: 0,
        };
    }
}
