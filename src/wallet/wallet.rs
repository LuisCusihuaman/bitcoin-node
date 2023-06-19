use crate::config::Config;
use crate::logger::log;
use crate::net::message::tx::{OutPoint, Tx, TxIn, TxOut};
use crate::net::message::MessagePayload;
use crate::net::p2p_connection::P2PConnection;
use crate::node::utxo::Utxo;
use bitcoin_hashes::hash160;
use bitcoin_hashes::Hash;
use rand::rngs::OsRng;
use rand::Rng;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use std::str::FromStr;
use std::sync::mpsc::Sender;
use std::vec;

pub struct Wallet {
    config: Config,
    logger_tx: Sender<String>,
    node_manager: String, // P2PConnection,
    users: Vec<User>,
}

impl Wallet {
    pub fn new(config: Config, sender: Sender<String>) -> Wallet {
        let logger_tx = sender.clone();
        // let node_manager = P2PConnection::connect("127.0.0.1:8080", sender.clone()).unwrap();

        Wallet {
            config,
            logger_tx,
            node_manager: String::new(),
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
        // self.node_manager.send(&message).unwrap();
    }

    fn createTx(&mut self, mut utxos: Vec<Utxo>) -> Option<Tx> {
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
    pub fn receive(&mut self) {
        // let (_addrs, messages) = self.node_manager.receive();
        // for message in messages {
        //     log(
        //         self.logger_tx.clone(),
        //         format!("Wallet received {:?} from nodo-rustico", message),
        //     );

        // Recibo la lista de UTXOs asociadas al address actual

        // let UTXOs_to_spend = match message {
        //     MessagePayload::UTXOS(tx) => tx,
        //     _ => continue,
        // };
        // let utxos: Vec<Utxo> = vec![];
        // let tx = self.createTx(utxos)?;

        // sign the Tx
        // let signed_tx = self.sign_tx(tx);

        // let serialized_tx = self.serialize(signed_tx);

        // send the Tx to the node
        //self.send(MessagePayload::sendTx(signed_tx));
        //}
    }

    // Verify that the ScriptSig successfully unlocks the previous ScriptPubKey.
    fn tx_verified(&mut self, utxo: &Utxo) -> bool {
        true
    }

    fn sign_tx(&mut self, tx: Tx) -> Tx {
        tx
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct User {
    pub name: String,
    pub bitcoin_address: [u8; 20],
    pub secret_key: SecretKey,
    pub public_key: [u8; 33],
    pub txns_hist: Vec<Tx>,
}

impl User {
    pub fn new(name: String, secret_key: SecretKey) -> User {
        let secp = Secp256k1::new();

        // Public key
        let public_key = secret_key.public_key(&secp).serialize();

        println!("public_key {:?}", public_key);

        // Generate address
        let bitcoin_address = hash160::Hash::hash(&public_key).to_byte_array();

        User {
            name,
            bitcoin_address,
            secret_key,
            public_key,
            txns_hist: Vec::new(),
        }
    }

    pub fn new_anonymous(name: String) -> User {
        let mut rng = OsRng::default();
        let secp = Secp256k1::new();

        // Secret key
        let mut private_key_bytes: [u8; 32] = [0; 32];
        rng.fill(&mut private_key_bytes);
        let secret_key = SecretKey::from_slice(&private_key_bytes).unwrap();

        // Public key
        let public_key = secret_key.public_key(&secp).serialize();

        let bitcoin_address = hash160::Hash::hash(&public_key).to_byte_array();

        User {
            name,
            bitcoin_address,
            secret_key,
            public_key,
            txns_hist: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use crate::logger::Logger;
    use crate::net::message::ping_pong::PayloadPingPong;
    use crate::net::message::tx::{OutPoint, Tx, TxIn, TxOut};

    #[test]
    fn test_create_user_correctly() {
        let user = User::new_anonymous("Alice".to_string());

        assert_eq!(user.name, "Alice");
        assert!(!user.bitcoin_address.is_empty());
        assert!(!user.secret_key.secret_bytes().is_empty());
        // assert!(!user.public_key.serialize().is_empty());
        assert!(user.txns_hist.is_empty());
    }

    #[test]
    fn test_wallet_save_multiple_users() {
        let logger = Logger::mock_logger();
        let config = Config::from_file("nodo.config")
            .map_err(|err| err.to_string())
            .unwrap();

        let mut wallet = Wallet::new(config, logger.tx);

        let user1 = User::new_anonymous("user1".to_string());
        let user2 = User::new_anonymous("user2".to_string());

        wallet.add_user(user1);
        wallet.add_user(user2);

        assert_eq!(wallet.users.len(), 2);
    }

    #[test]
    fn test_received_correctly_UTXOs() {
        let logger = Logger::mock_logger();
        let config = Config::from_file("nodo.config")
            .map_err(|err| err.to_string())
            .unwrap();

        let mut wallet = Wallet::new(config, logger.tx);

        let user = User::new_anonymous("user".to_string());

        wallet.add_user(user);

        // enviar get utxos
        // voy a enviar un msg Payload y quiero recibir una lista de UTXOs

        //let utxo = !vec[]
    }

    #[test]
    fn test_creates_user_from_priv_key_correctly() {
        let priv_key_wif = "cVK6pF1sfsvvmF9vGyq4wFeMywy1SMFHNpXa3d4Hi2evKHRQyTbn";
        let address_wif = "mx34LnwGeUD8tc7vR8Ua1tCq4t6ptbjWGb";

        let priv_key_bytes = bs58::decode(priv_key_wif)
            .with_check(None)
            .into_vec()
            .unwrap();

        // Crea la secretKey a partir de los bytes de la clave privada
        // [0xef, secret_key (32 bytes), 0x01]
        let secret_key = SecretKey::from_slice(&priv_key_bytes[1..33]).unwrap();

        let pub_addr_hashed = bs58::decode(address_wif)
            .with_check(None)
            .into_vec()
            .unwrap();

        let address_bytes = &pub_addr_hashed[1..];

        // [111, 181, 51, 138, 19, 120, 118, 0, 187, 24, 163, 236, 151, 149, 117, 93, 82, 212, 10, 107, 236]
        let user = User::new("bob".to_string(), secret_key);

        assert_eq!(user.bitcoin_address, address_bytes[..]);
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
        let secret_key = SecretKey::from_slice(&priv_key_bytes[1..33]).unwrap();

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
    fn test_wallet_create_tx() {}
}
