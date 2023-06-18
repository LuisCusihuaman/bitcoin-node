use crate::config::Config;
use crate::logger::log;
use crate::net::message::tx::Tx;
use crate::node::utxo::Utxo;
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

            // Recibo la lista de UTXOs asociadas al address actual
            
            // let UTXOs_to_spend = match message {
            //     MessagePayload::UTXOS(tx) => tx,
            //     _ => continue,
            // };

            // decode UTXO
            let mut utxos:Vec<Utxo> = vec![];

            
            // Validating Transactions
            
            // 1. The inputs of the transaction are previously unspent.

                // The fact that we ask the node for the UTXOs associated with the address means that they are unspent.


            // 2. The sum of the inputs is greater than or equal to the sum of the outputs.
            let count = 0;
            for i in utxos.iter() {
                count += i.value;
            }
            
            // Fix this numbers
            let amount = 10.0; // amount if the amount of money to send
            let fee = 0.1; // fee for the Tx
            
            if (count as f64) < (amount+fee) { 
                log(
                    self.logger_tx.clone(),
                    format!("Error: Insufficient funds"),
                );
                return;
            }
            
            // 3. The ScriptSig successfully unlocks the previous ScriptPubKey.
            


        }
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
                                         .|ng();
 
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
    use crate::logger::Logger;
    use crate::net::message::ping_pong::PayloadPingPong;
    use crate::net::message::tx::{OutPoint, Tx, TxIn, TxOut};



    #[test]
    fn test_create_user_correctly() {

        let user = User::new_anonymous("Alice".to_string());

        assert_eq!(user.name, "Alice");
        assert!(!user.bitcoin_address.is_empty());
        assert!(!user.secret_key.secret_bytes().is_empty());
        assert!(!user.public_key.serialize().is_empty());
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
    fn test_received_correctly_UTXOs(){

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
    fn test_creates_user_from_priv_key_correctly(){
        
        //TODO  Intentar que sea algo asi

        
        //let priv_key = SecretKey::from("000000000000cVK6pF1sfsvvmF9vGyq4wFeMywy1SMFHNpXa3d4Hi2evKHRQyTbn");
        // let address = "mx34LnwGeUD8tc7vR8Ua1tCq4t6ptbjWGb";
        
        // let user = User::new("bob".to_string(),priv_key);

        // assert!(user.bitcoin_address == address);

 /////////////////////77////////////////
 
    //     let base58_alphabet: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    //     let priv_key_str = "cVK6pF1sfsvvmF9vGyq4wFeMywy1SMFHNpXa3d4Hi2evKHRQyTbn";
    
    //     // Decodifica la clave privada de Base58 a bytes
    //     let mut priv_key_bytes: Vec<u8> = Vec::new();
    //     let mut leading_zeros: usize = 0;
    //     for c in priv_key_str.chars() {
    //         match base58_alphabet.iter().position(|&x| x == c as u8) {
    //             Some(index) => {
    //                 for _ in 0..leading_zeros {
    //                     priv_key_bytes.push(0);
    //                 }
    //                 priv_key_bytes.push(index as u8);
    //                 leading_zeros = 0;
    //             },
    //             None => {
    //                 leading_zeros += 1;
    //             }
    //         }
    //     }

    // // Crea la SecretKey a partir de los bytes de la clave privada
    // let secret_key = SecretKey::from_slice(&priv_key_bytes);
        
        

        //let priv_key = SecretKey::from("000000000000cVK6pF1sfsvvmF9vGyq4wFeMywy1SMFHNpXa3d4Hi2evKHRQyTbn");
        // let address = "mx34LnwGeUD8tc7vR8Ua1tCq4t6ptbjWGb";
        
        // let user = User::new("bob".to_string(),priv_key);

        // assert!(user.bitcoin_address == address);

    }

    // #[test]
    // fn test_wallet_creates_tx(){
    //     let logger = Logger::stdout();

    //     let config = Config::from_file("wallet.config")
    //         .map_err(|err| err.to_string())
    //         .unwrap();

    //     let mut wallet = Wallet::new(config, &logger);

    //     let priv_key = SecretKey::from_str("cVK6pF1sfsvvmF9vGyq4wFeMywy1SMFHNpXa3d4Hi2evKHRQyTbn").unwrap();
    //     let address = "mx34LnwGeUD8tc7vR8Ua1tCq4t6ptbjWGb";
        
    //     let user = User::new("bob".to_string(),priv_key);

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
