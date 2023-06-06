use crate::config::Config;
use crate::logger::Logger;
use crate::node::message::tx::Tx;
use rand::rngs::OsRng;
use rand::Rng;
use secp256k1::{PublicKey, Secp256k1, SecretKey};

pub struct Wallet<'a> {
    config: Config,
    logger: &'a Logger,
    node_address: String,
    users: Vec<User>,
}

impl Wallet<'_> {
    pub fn new(config: Config, logger: &Logger) -> Wallet {
        Wallet {
            config,
            logger,
            node_address: "127.0.0.1".to_string(),
            users: Vec::new(),
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
