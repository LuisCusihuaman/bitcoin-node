use crate::config::Config;
use crate::logger::log;
use crate::net::message::tx::Tx;
use crate::net::message::MessagePayload;
use crate::net::p2p_connection::P2PConnection;
use rand::rngs::OsRng;
use rand::Rng;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use std::sync::mpsc::Sender;

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

    pub fn receive(&mut self) {
        let (_addrs, messages) = self.node_manager.receive();
        for message in messages {
            log(
                self.logger_tx.clone(),
                format!("Wallet received {:?} from nodo-rustico", message),
            );
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct User {
    pub name: String,
    pub address: String,
    pub secret_key: SecretKey,
    pub public_key: PublicKey,
    pub txns: Vec<Tx>,
    pub balance: u64,
}

impl User {
    pub fn new(name: String, address: String) -> User {
        let mut rng = OsRng::default();
        let secp = Secp256k1::new();

        // Secret key
        let mut private_key_bytes: [u8; 32] = [0; 32];
        rng.fill(&mut private_key_bytes);
        let secret_key = SecretKey::from_slice(&private_key_bytes).unwrap();

        // Public key
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);

        User {
            name,
            address,
            secret_key,
            public_key,
            txns: Vec::new(),
            balance: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logger::Logger;
    use crate::net::message::ping_pong::PayloadPingPong;
    use crate::net::message::tx::{OutPoint, Tx, TxIn, TxOut};

    #[test]
    fn test_create_user_with_keypair() {
        let user = User::new("Alice".to_string(), "address".to_string());

        let sk_bytes = user.secret_key.secret_bytes();
        let pk_bytes = user.public_key.serialize();

        assert!(!sk_bytes.is_empty());
        assert!(!pk_bytes.is_empty());
    }

    #[test]
    fn test_wallet_save_multiple_users() {
        let logger = Logger::mock_logger();
        let config = Config::from_file("nodo.config")
            .map_err(|err| err.to_string())
            .unwrap();

        let mut wallet = Wallet::new(config, logger.tx);

        let user1 = User::new("user1".to_string(), "address1".to_string());
        let user2 = User::new("user2".to_string(), "address2".to_string());

        wallet.add_user(user1);
        wallet.add_user(user2);

        assert_eq!(wallet.users.len(), 2);
    }

    #[test]
    fn test_wallet_sends_ping_to_node_manager() {
        let logger = Logger::mock_logger();
        let config = Config::from_file("nodo.config")
            .map_err(|err| err.to_string())
            .unwrap();

        let mut wallet = Wallet::new(config, logger.tx);

        let ping_message = MessagePayload::Ping(PayloadPingPong::new());

        wallet.send(ping_message);
        wallet.receive();
    }

    #[test]
    fn test_wallet_sends_tx_to_node_manager() {
        let logger = Logger::mock_logger();
        let config = Config::from_file("nodo.config")
            .map_err(|err| err.to_string())
            .unwrap();

        let mut wallet = Wallet::new(config, logger.tx);

        let tx = Tx {
            id: [
                161, 251, 15, 243, 199, 157, 168, 6, 195, 235, 91, 74, 146, 148, 81, 223, 31, 243,
                229, 60, 226, 24, 143, 213, 248, 206, 225, 62, 206, 204, 218, 240,
            ],
            version: 545259520,
            flag: 0,
            tx_in_count: 1,
            tx_in: [TxIn {
                previous_output: OutPoint {
                    hash: [
                        0, 0, 128, 32, 62, 120, 168, 216, 46, 128, 233, 64, 165, 172, 45, 232, 77,
                        114, 71, 79, 193, 186, 253, 99, 202, 10, 233, 74, 12, 0, 0, 0,
                    ],
                    index: 0,
                },
                script_length: 0,
                signature_script: [].to_vec(),
                sequence: 4294967294,
            }]
            .to_vec(),
            tx_out_count: 2,
            tx_out: [
                TxOut {
                    value: 228000,
                    pk_script_length: 22,
                    pk_script: [
                        0, 20, 93, 87, 106, 129, 244, 96, 231, 161, 237, 37, 79, 233, 191, 255, 7,
                        90, 179, 188, 69, 101,
                    ]
                    .to_vec(),
                },
                TxOut {
                    value: 1659498,
                    pk_script_length: 22,
                    pk_script: [
                        0, 20, 117, 35, 140, 67, 199, 254, 215, 158, 114, 44, 152, 242, 196, 38,
                        226, 237, 60, 92, 144, 193,
                    ]
                    .to_vec(),
                },
            ]
            .to_vec(),
            tx_witness: [].to_vec(),
            lock_time: 2437581,
        };

        let message = MessagePayload::Tx(tx.clone());

        wallet.send(message);
        wallet.receive();
    }
}
