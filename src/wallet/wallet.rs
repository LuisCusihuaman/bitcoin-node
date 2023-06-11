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

    pub fn add_user(&mut self, user: User) {
        self.users.push(user);
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
        let logger = Logger::stdout();
        let config = Config::from_file("nodo.config")
            .map_err(|err| err.to_string())
            .unwrap();

        let mut wallet = Wallet::new(config, &logger);

        let user1 = User::new("user1".to_string(), "address1".to_string());
        let user2 = User::new("user2".to_string(), "address2".to_string());

        wallet.add_user(user1);
        wallet.add_user(user2);

        assert_eq!(wallet.users.len(), 2);
    }
}
