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
    fn create_tx() -> Result<(), String> {
        let priv_key_wif = "cSM1NQcoCMDP8jy2AMQWHXTLc9d4HjSr7H4AqxKk2bD1ykbaRw59".to_string();

        let messi = User::new("Messi".to_string(), priv_key_wif, false);

        // In this example, we will pay 0.1 testnet bitcoins (tBTC) to mx34LnwGeUD8tc7vR8Ua1tCq4t6ptbjWGb (nuestra otra cuenta)
        // we have an output denoted by a transaction ID and output index bce66d595cff8650ac37fc181727f1c5c6a8731409694b29708f368a1289cc7b:1
        // (0.01302208 tBTC) we’ll send the bitcoins back to outselves to mpiQbuypLNHoUCXeFtrS956jPSNhwmYwai (nuestra cuenta actual)
        // we’ll use 0.001 tBTC as our fee

        // 1 BTC = 100,000,000 SAT.

        // 0.01302208 BTC in wallet
        // 0.001 BTC for fee
        // 0.001 BTC to send
        // 0.01102208 BTC to receive

        let signature_script: Vec<u8> = vec![
            0x76, 0xa9, 0x14, 0x64, 0xe3, 0xab, 0x1b, 0xbc, 0xa0, 0xd2, 0x74, 0x6e, 0x51, 0x61,
            0x41, 0x61, 0xa9, 0x15, 0x80, 0x31, 0xcf, 0xb8, 0xed, 0x88, 0xac,
        ];

        let tx_in_1 = TxIn {
            previous_output: OutPoint {
                hash: [
                    0xbc, 0xe6, 0x6d, 0x59, 0x5c, 0xff, 0x86, 0x50, 0xac, 0x37, 0xfc, 0x18, 0x17,
                    0x27, 0xf1, 0xc5, 0xc6, 0xa8, 0x73, 0x14, 0x09, 0x69, 0x4b, 0x29, 0x70, 0x8f,
                    0x36, 0x8a, 0x12, 0x89, 0xcc, 0x7b,
                ],
                index: 1,
            },
            script_length: signature_script.len(),
            signature_script,
            sequence: 0,
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

        println!("{:?}", tx);
        println!("tx_bytes{:?}", tx_bytes);

        tx_bytes.extend([0x01, 0x00, 0x00, 0x00]);

        // let signature_hash = sha256::Hash::hash(&tx_bytes); // signature hash
        let signature_hash = double_sha256(&tx_bytes).to_byte_array(); // signature hash
        println!("signature_hash: {:?}", signature_hash);

        let private_key = messi.secret_key_bytes;
        println!("private_key: {:?}", private_key);

        // firmar la transaccion

        let secp = Secp256k1::new();
        let private_key = messi.secret_key;

        let message = Message::from_slice(&signature_hash).unwrap();

        let signature = secp.sign_ecdsa(&message.clone(), &private_key);

        // println!("signature: {:?}", signature);

        let signature_bytes = signature.clone().serialize_der().to_vec();
        // println!("signature_bytes: {:?}", signature_bytes);

        tx.tx_in[0].signature_script = signature_bytes.clone();
        tx.tx_in[0].script_length = signature_bytes.len();

        let final_tx_encode = tx.encode(&mut buffer);
        println!("final_tx_encode: {:?}", final_tx_encode);

        // Verifica la firma usando la clave pública correspondiente
        // let public_key = messi.secret_key.public_key(&secp);
        // let verification_result =
        //     secp.verify_ecdsa(&message.clone(), &signature.clone(), &public_key.clone()); // Devuelve OK(()) es que está verificada, es horrible esto
        // println!("verification_result: {:?}", verification_result);

        let mut offset: usize = 0;
        let tx_test = decode_internal_tx(&final_tx_encode, &mut offset);

        println!("tx: {:?}", tx);

        println!("tx_test: {:?}", tx_test);

        Ok(())
    }
}

// [1, 0, 0, 0, 1, 188, 230, 109, 89, 92, 255, 134, 80, 172, 55, 252, 24, 23, 39, 241, 197, 198, 168, 115, 20, 9, 105, 75, 41, 112, 143, 54, 138, 18, 137, 204, 123, 1, 0, 0, 0, 71, 48, 69, 2, 33, 0, 253, 227, 106, 209, 195, 168, 142, 86, 225, 135, 209, 172, 29, 149, 133, 168, 132, 96, 7, 130, 193, 97, 81, 169, 112, 141, 67, 194, 167, 4, 112, 10, 2, 32, 48, 13, 13, 125, 82, 223, 93, 137, 128, 65, 180, 250, 216, 141, 46, 239, 243, 27, 200, 242, 14, 189, 210, 0, 47, 128, 140, 32, 240, 33, 8, 137, 255, 255, 255, 255, 2, 160, 134, 1, 0, 0, 0, 0, 0, 24, 118, 169, 181, 51, 138, 19, 120, 118, 0, 187, 24, 163, 236, 151, 149, 117, 93, 82, 212, 10, 107, 236, 136, 172, 128, 209, 16, 0, 0, 0, 0, 0, 24, 118, 169, 100, 227, 171, 27, 188, 160, 210, 116, 110, 81, 97, 65, 97, 169, 21, 128, 49, 207, 184, 237, 136, 172, 0, 0, 0, 0]
