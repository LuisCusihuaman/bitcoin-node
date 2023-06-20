use crate::config::Config;
use crate::logger::log;
use crate::net::message::get_utxos::PayloadGetUtxos;
use crate::net::message::tx::{OutPoint, Tx, TxIn, TxOut};
use crate::net::message::MessagePayload;
use crate::net::p2p_connection::P2PConnection;
use crate::node::utxo::Utxo;
use bitcoin_hashes::hash160;
use bitcoin_hashes::Hash;
use rand::rngs::OsRng;
use rand::Rng;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use std::sync::mpsc::Sender;
use std::time::Duration;
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
                    self.send(MessagePayload::WalletTx(signed_tx));
                }

                _ => continue,
            }
        }
    }

    fn create_tx(&mut self, mut utxos: Vec<Utxo>) -> Option<Tx> {
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

    fn create_pending_tx(&mut self, mut from: User, to: String, amount: f64) {
        // PONELE
        // Create send utxo message
        let get_utxo_message = MessagePayload::GetUTXOs(PayloadGetUtxos {
            address: from.get_address(),
        });

        // Send message to node
        self.send(get_utxo_message);

        // Save the pending transaction
        let pending = PendingTx {
            from: from.pubkeyhash,
            to: to,
            amount: amount,
            created: false,
        };
        
        from.pending_tx.push(pending); // Otro nombre
    }
}

#[derive(Clone, Debug)]
pub struct PendingTx {
    from: [u8; 20],
    to: String, // TODO Esta en formato wallet address?
    amount: f64,
    created: bool,
}

#[derive(Clone, Debug)]
pub struct User {
    pub name: String,
    pub pubkeyhash: [u8; 20],
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
        let secret_key = match is_anonymous {
            true => {
                let mut private_key_bytes: [u8; 32] = [0; 32];
                rng.fill(&mut private_key_bytes);
                SecretKey::from_slice(&private_key_bytes).unwrap()
            }
            false => {
                let priv_key_bytes = bs58::decode(priv_key_wif)
                    .with_check(None)
                    .into_vec()
                    .unwrap();

                // Crea la secretKey a partir de los bytes de la clave privada
                // [0xef, secret_key (32 bytes), 0x01]
                SecretKey::from_slice(&priv_key_bytes[1..33]).unwrap()
            }
        };

        // Public key
        let public_key = secret_key.public_key(&secp).serialize();

        // Generate address
        let pubkeyhash = hash160::Hash::hash(&public_key).to_byte_array();

        User {
            name,
            pubkeyhash,
            secret_key,
            public_key,
            txns_hist: Vec::new(),
            pending_tx: Vec::new(),
        }
    }

    pub fn get_pub_key(&self) -> [u8; 33] {
        self.public_key
    }

    // Returns the address in base58Check (34 letras)
    pub fn get_address_base58(&self) -> String {
        let version = [0x6f];
        let pub_hash_key = self.get_address();
        let input = [&version[..], &pub_hash_key[..]].concat();
        
        bs58::encode(input).with_check().into_string()
    }

    // address = pubkeyHash
    pub fn get_address(&self) -> [u8; 20] {
        self.pubkeyhash
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
    use super::*;
    use crate::logger::Logger;
    use crate::net::message::ping_pong::PayloadPingPong;
    use crate::net::message::tx::{OutPoint, Tx, TxIn, TxOut};

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
        assert!(!user.get_address().is_empty());
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

        assert_eq!(user.get_address(), address_bytes[..]);
        assert_eq!(user.get_address_base58(), address_wif); // TODO: fix this
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

        // address bitcoin = "maksjhduyihjkdr232389748heiuy4ow8u"
        // address: [u8; 20] = hash160(pub_key)

        // TODO de una TxOut necesitamos el address bitcoin

        // TODO : chequear el to
        wallet.create_pending_tx(
            messi.clone(),
            "maksjhduyihjkdr232389748heiuy4ow8u".to_string(),
            10.0,
        );

        wallet.receive();

        Ok(())
    }
}
