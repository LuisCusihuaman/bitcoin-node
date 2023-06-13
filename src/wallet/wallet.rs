use crate::config::Config;
use crate::logger::Logger;
use crate::node::message::tx::{Tx, TxIn, TxOut, self};
use bitcoin_hashes::Hash;
use rand::rngs::OsRng;
use rand::Rng;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use bs58;
use bitcoin_hashes::{hash160};


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

    // pub fn get_balance(&self, user: User) -> u64 {

    //     let mut balance = 0;

            // TODO Conectar con el nodo y pedirle las UTXO asociadas al address de user

    //     for tx in &user.txns {
    //        //balance += tx.amount; 
    //     }

    //     balance
    // }

    fn create_tx(&self, from:User , to_address:String, amount:u64) -> Tx{

        // Sacar este campo cuando encodeemos
        let id = [0; 32];
        let version = 1;
        let flag = 0;


        let tx_in = vec!();

        // TODO Conectar con el nodo y pedirle las UTXO asociadas al address de user
        // tx_in_count = len(utxos)
        let tx_in_count = tx_in.len();

        let tx_out = vec!();
        let tx_out_count = tx_out.len();

        // Omitimos el tx_witness porque el flag es 0
        let tx_witness = vec!();

        let lock_time = 0; // 0 significa que se procesa instantaneamente

        Tx{
            id,
            version,
            flag,
            tx_in_count,
            tx_in,
            tx_out_count,
            tx_out,
            tx_witness,
            lock_time,}
        }


    pub fn send_tx(&self, from:User , to_address:String, amount:u64, tx_in: Vec<TxIn>){

        let tx = self.create_tx(from, to_address, amount);

        // wallet ::  payloadSendTx -> Nodo
        // Nodo :: payloadAQuien? -> wallet
        // wallet :: payloadInfo (address, amount) -> Nodo
        // Nodo :: payloadTx -> wallet
        // wallet la firma

        // nodo::payloadSendTxToAddress(address)

        let mut tx_out = vec!();

        // aca creo la transaccion real
        // Pedirsela al nodo?
        
        let mut tx = Tx::new(1,  0, tx_in, tx_out ,  0);


        //let mut Tx

        //self.sign(Tx);

    }
        
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct User {
    pub name: String,
    pub bitcoin_address: String,
    pub secret_key: SecretKey,
    pub public_key: PublicKey,
    pub txns_hist: Vec<Tx>,
}

impl User {

    pub fn new(name:String, secret_key:SecretKey) -> User{

        let secp = Secp256k1::new();

         // Public key
         let public_key = PublicKey::from_secret_key(&secp, &secret_key);

         // Generate address

         // Version de testNet
         let version = "0x6f"; // 111
 
         // Key hash = Version concatenated with RIPEMD-160(SHA-256(public key))
         let key_hash =  format!("{}{}", version, hash160::Hash::hash(&public_key.to_string().as_bytes()).to_string());
 
         let bitcoin_address = bs58::encode(key_hash.as_bytes())
                                         .with_check()
                                         .into_string();
 
         User {
             name,
             bitcoin_address,
             secret_key,
             public_key,
             txns_hist: Vec::new(),
         }
    }


    pub fn new_anonimous(name: String) -> User {

        let mut rng = OsRng::default();
        let secp = Secp256k1::new();

        // Secret key
        let mut private_key_bytes: [u8; 32] = [0; 32];
        rng.fill(&mut private_key_bytes);
        let secret_key = SecretKey::from_slice(&private_key_bytes).unwrap();

        // Public key
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);

        // Generate address

        // Version = 1 byte of 0 (zero); on the test network, this is 1 byte of 111
        // Key hash = Version concatenated with RIPEMD-160(SHA-256(public key))
        // Checksum = 1st 4 bytes of SHA-256(SHA-256(Key hash))
        // Bitcoin Address = Base58Encode(Key hash concatenated with Checksum)

        // Version de testNet
        let version = "0x6f"; // 111

        // Key hash = Version concatenated with RIPEMD-160(SHA-256(public key))
        let key_hash =  format!("{}{}", version, hash160::Hash::hash(&public_key.to_string().as_bytes()).to_string());

        let bitcoin_address = bs58::encode(key_hash.as_bytes())
                                        .with_check()
                                        .into_string();

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

    #[test]
    fn test_create_tx_from_bob_to_alice(){

        let user = User::new("Alice".to_string());

    }


    // #[test]
    // fn test_create_user_with_keypair() {
    //     let user = User::new("Alice".to_string(), "address".to_string());

    //     let sk_bytes = user.secret_key.secret_bytes();
    //     let pk_bytes = user.public_key.serialize();

    //     assert!(!sk_bytes.is_empty());
    //     assert!(!pk_bytes.is_empty());
    // }

    // #[test]
    // fn test_wallet_save_multiple_users() {
    //     let logger = Logger::stdout();
    //     let config = Config::from_file("nodo.config")
    //         .map_err(|err| err.to_string())
    //         .unwrap();

    //     let mut wallet = Wallet::new(config, &logger);

    //     let user1 = User::new("user1".to_string(), "address1".to_string());
    //     let user2 = User::new("user2".to_string(), "address2".to_string());

    //     wallet.add_user(user1);
    //     wallet.add_user(user2);

    //     assert_eq!(wallet.users.len(), 2);
    // }

    // #[test]
    // fn test_wallet_creates_tx(){
    //     let logger = Logger::stdout();

    //     let config = Config::from_file("wallet.config")
    //         .map_err(|err| err.to_string())
    //         .unwrap();

    //     let mut wallet = Wallet::new(config, &logger);

    //     let priv_key = SecretKey::from_str("cVK6pF1sfsvvmF9vGyq4wFeMywy1SMFHNpXa3d4Hi2evKHRQyTbn").unwrap();
    //     let address = "mx34LnwGeUD8tc7vR8Ua1tCq4t6ptbjWGb";
        
    //     let user = User::new("bob".to_string(),priv_key, address.to_string());

    //     wallet.add_user(user);




    //     let tx = wallet.create_tx("user1".to_string(), "user2".to_string(), 100);

    //     assert_eq!(tx.sender, "user1".to_string());
    //     assert_eq!(tx.receiver, "user2".to_string());
    //     assert_eq!(tx.amount, 100);

    // }

    // #[test]
    // fn test_wallet_creates_and_sings_tx(){


    // }
}