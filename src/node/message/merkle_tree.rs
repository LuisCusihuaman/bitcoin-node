use std::hash;

// Implementacion de merkle tree
use crate::error::Error;
use bitcoin_hashes::{sha256, Hash, HashEngine};

use super::tx::Tx;

pub struct MerkleTree {
    root: sha256::Hash,
    hashed_leaves: Vec<sha256::Hash>,
}

impl MerkleTree {
    pub fn new() -> Self {
        Self {
            root: sha256::Hash::hash("".as_bytes()),
            hashed_leaves: Vec::new(),
        }
    }

    pub fn get_root(&self) -> Result<sha256::Hash, Error> {
        if self.root == sha256::Hash::hash("".as_bytes()) {
            return Err(Error::MerkleTreeNotGenerated(String::from(
                "No se ha generado el Merkle Tree",
            )));
        }
        Ok(self.root)
    }

    fn get_hashed_nodes(&self) -> Result<Vec<sha256::Hash>, Error> {
        if self.hashed_leaves.is_empty() {
            return Err(Error::MerkleTreeNotGenerated(String::from(
                "No se ha generado el Merkle Tree",
            )));
        }

        Ok(self.hashed_leaves.clone())
    }

    fn add_hashes(&mut self, hashes: Vec<sha256::Hash>) {
        for h in hashes {
            self.hashed_leaves.push(h);
        }
    }

    // Generates the merkle root from the vector of leaves
    pub fn generate_merkle_tree(&mut self, data: Vec<&[u8]>) {
        if data.len() == 0 {
            return;
        }
        if data.len() == 1 {
            self.root = sha256::Hash::from_slice(data[0]).unwrap();
            return;
        }
        let mut hashed_leaves = Vec::new();

        // Convierto las hojas a hashes
        for l in data {
            let hash = self.hash256(l);
            hashed_leaves.push(hash);
        }
        if hashed_leaves.len() % 2 == 1 {
            hashed_leaves.push(hashed_leaves.last().unwrap().clone());
        }
        self.add_hashes(hashed_leaves.clone());

        self.root = match self.merkle_root(hashed_leaves) {
            Ok(root) => root,
            Err(_) => sha256::Hash::hash("".as_bytes()),
        }
    }

    // Convierte el input en un hash
    fn hash256(&self, data: &[u8]) -> sha256::Hash {
        sha256::Hash::hash(data)
    }

    // Takes the binary hashes and calculates the hash256
    // this implementation assumes that the child node hashes are already in SHA-256
    fn merkle_parent(&self, left: &sha256::Hash, right: &sha256::Hash) -> sha256::Hash {
        let mut hasher = sha256::Hash::engine();
        hasher.input(left.as_ref());
        hasher.input(right.as_ref());
        sha256::Hash::from_engine(hasher)
    }

    // Recibe una lista de hashes y devuelve una lista que es la mitad de largo
    // Estos hashes pueden ser hojas o nodos
    fn merkle_parent_level(
        &mut self,
        mut hashes: Vec<sha256::Hash>,
    ) -> Result<Vec<sha256::Hash>, Error> {
        if hashes.len() % 2 == 1 {
            // Si la cantidad de hashes es impar, duplico el ultimo
            let last = match hashes.last() {
                Some(last) => last,
                None => {
                    return Err(Error::CantInvalidaNodos(String::from(
                        "No se puede tener un unico nodo como hijo",
                    )))
                }
            };
            hashes.push(last.clone());
        }

        let mut parent_level = Vec::new();
        let mut i = 0;

        while i < hashes.len() {
            let parent = self.merkle_parent(&hashes[i], &hashes[i + 1]);
            println!("Parent: {:?}", parent.to_string());
            parent_level.push(parent);
            i += 2;
        }
        Ok(parent_level)
    }

    // To get the Merkle root we calculate successive Merkle parent levels until we get a single hash
    fn merkle_root(&mut self, mut hashes: Vec<sha256::Hash>) -> Result<sha256::Hash, Error> {
        while hashes.len() > 1 {
            match self.merkle_parent_level(hashes) {
                Ok(parent_level) => {
                    hashes = parent_level;
                }
                Err(_) => {
                    return Err(Error::CantInvalidaNodos(String::from(
                        "No se puede tener un unico nodo como hijo",
                    )))
                }
            }
        }

        Ok(hashes[0])
    }

    // Indica si la transaccion pertenece al merkle tree
    pub fn proof_of_inclusion(&self, tx: &[u8]) -> bool {
        let tx_hash = self.hash256(tx);
        let mut proof = false;

        for h in &self.hashed_leaves {
            if tx_hash == *h {
                proof = true;
                break;
            }
        }

        proof
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // #[test]
    // #[should_panic]
    // fn test_create_merkle_tree_with_empty_root() {
    //     let merkle_tree = MerkleTree::new();
    //     let expected = "";

    //     merkle_tree.get_root().unwrap();
    // }

    // #[test]
    // #[should_panic]
    // fn test_create_merkle_tree_with_empty_leaves() {
    //     let merkle_tree = MerkleTree::new();

    //     merkle_tree.get_hashed_nodes().unwrap();
    // }

    // // Relleno las hojas hasta que tengan multiplo de 2
    // #[test]
    // fn test_create_merkle_tree_with_five_leaves() {
    //     let mut merkle_tree = MerkleTree::new();

    //     let data = vec![
    //         "1".as_bytes(),
    //         "2".as_bytes(),
    //         "3".as_bytes(),
    //         "4".as_bytes(),
    //         "5".as_bytes(),
    //     ];

    //     merkle_tree.generate_merkle_tree(data);

    //     assert_eq!(merkle_tree.get_hashed_nodes().unwrap().len(), 6);
    // }

    // #[test]
    // fn test_merkle_tree_with_four_leaves_has_seven_nodes_in_total() {
    //     let mut merkle_tree = MerkleTree::new();

    //     let data = vec![
    //         "1".as_bytes(),
    //         "2".as_bytes(),
    //         "3".as_bytes(),
    //         "5".as_bytes(),
    //     ];

    //     merkle_tree.generate_merkle_tree(data);

    //     assert_eq!(merkle_tree.get_hashed_nodes().unwrap().len(), 4);
    // }

    // #[test]
    // fn test_generates_hash_number_correctly() {
    //     let hash = MerkleTree::new().hash256("1".as_bytes());

    //     assert!(hash.to_string().is_empty() == false);
    // }

    // #[test]
    // fn test_generates_merkle_node_parent_correctly() {
    //     let merkle_tree = MerkleTree::new();

    //     let left_hash = merkle_tree.hash256("1".as_bytes());
    //     let right_hash = merkle_tree.hash256("2".as_bytes());

    //     // concatenate right and left hashes
    //     let owned_string = format!("{}{}", left_hash.to_string(), right_hash.to_string());

    //     let expected_hash = merkle_tree.hash256(&owned_string.as_bytes());

    //     let parent = merkle_tree.merkle_parent(&left_hash.to_string(), &right_hash.to_string());

    //     assert_eq!(parent, expected_hash);
    // }

    // #[test]
    // fn test_merkle_parent_level_returns_hash_vector_half_its_even_size() {
    //     let mut merkle_tree = MerkleTree::new();
    //     let mut hashes = Vec::new();
    //     hashes.push(merkle_tree.hash256("1".as_bytes()));
    //     hashes.push(merkle_tree.hash256("2".as_bytes()));
    //     hashes.push(merkle_tree.hash256("3".as_bytes()));
    //     hashes.push(merkle_tree.hash256("4".as_bytes()));

    //     let expected_len = hashes.len() / 2;

    //     let parent_level = merkle_tree.merkle_parent_level(hashes).unwrap();

    //     assert_eq!(parent_level.len(), expected_len);
    // }

    // #[test]
    // fn test_merkle_parent_level_returns_hash_vector_half_its_un_even_size() {
    //     let mut merkle_tree = MerkleTree::new();
    //     let mut hashes = Vec::new();
    //     hashes.push(merkle_tree.hash256("1".as_bytes()));
    //     hashes.push(merkle_tree.hash256("2".as_bytes()));
    //     hashes.push(merkle_tree.hash256("3".as_bytes()));
    //     hashes.push(merkle_tree.hash256("4".as_bytes()));
    //     hashes.push(merkle_tree.hash256("5".as_bytes()));

    //     let expected_len = (hashes.len() + 1) / 2;

    //     let parent_level = merkle_tree.merkle_parent_level(hashes).unwrap();

    //     assert_eq!(parent_level.len(), expected_len);
    // }

    // #[test]
    // fn test_parent_root_returns_correctly_with_letters() {
    //     let mut merkle_tree = MerkleTree::new();

    //     //let expected_root = "14ede5e8e97ad9372327728f5099b95604a39593cac3bd38a343ad76205213e7";

    //     // Resultado sacado de https://blockchain-academy.hs-mittweida.de/merkle-tree/
    //     let expected_root = "58c89d709329eb37285837b042ab6ff72c7c8f74de0446b091b6a0131c102cfd";

    //     let hex_hashes = vec![
    //         "a".as_bytes(),
    //         "b".as_bytes(),
    //         "c".as_bytes(),
    //         "d".as_bytes(),
    //     ];

    //     merkle_tree.generate_merkle_tree(hex_hashes);

    //     assert_eq!(merkle_tree.get_root().unwrap().to_string(), expected_root);
    // }

    // #[test]
    // fn test_parent_root_returns_correctly_with_numbers() {
    //     let mut merkle_tree = MerkleTree::new();

    //     //let expected_root = "14ede5e8e97ad9372327728f5099b95604a39593cac3bd38a343ad76205213e7";

    //     // Resultado sacado de https://blockchain-academy.hs-mittweida.de/merkle-tree/
    //     let expected_root = "85df8945419d2b5038f7ac83ec1ec6b8267c40fdb3b1e56ff62f6676eb855e70";

    //     let hex_hashes = vec![
    //         "1".as_bytes(),
    //         "2".as_bytes(),
    //         "3".as_bytes(),
    //         "4".as_bytes(),
    //     ];

    //     merkle_tree.generate_merkle_tree(hex_hashes);

    //     assert_eq!(merkle_tree.get_root().unwrap().to_string(), expected_root);
    // }

    // // Genero el root correctamente
    // #[test]
    // fn test_creates_root_correctly() {
    //     let mut merkle_tree = MerkleTree::new();

    //     let hashes = vec![
    //         merkle_tree.hash256("1".as_bytes()),
    //         merkle_tree.hash256("2".as_bytes()),
    //         merkle_tree.hash256("3".as_bytes()),
    //         merkle_tree.hash256("4".as_bytes()),
    //     ];

    //     let root = merkle_tree.merkle_root(hashes).unwrap().to_string();

    //     assert_eq!(root.is_empty(), false);
    // }

    // #[test]
    // fn test_generates_root_merkle_tree_from_leaves() {
    //     let mut merkle_tree = MerkleTree::new();

    //     let data = vec![
    //         "1".as_bytes(),
    //         "2".as_bytes(),
    //         "3".as_bytes(),
    //         "5".as_bytes(),
    //     ];

    //     merkle_tree.generate_merkle_tree(data);

    //     assert_eq!(
    //         merkle_tree.get_root().unwrap().to_string().is_empty(),
    //         false
    //     );
    // }

    // // Ejemplo del libro
    // #[test]
    // fn test_merkle_tree_generates_correct_root_ex1() {
    //     let mut merkle_tree = MerkleTree::new();

    //     let expected_root = "03bbf047aef6a41e8d19f5d85425f965e8c59d0fe1fc9dca02dd79754edf3451";

    //     let hex_hashes = vec![
    //         "c117ea8ec828342f4dfb0ad6bd140e03a50720ece40169ee38bdc15d9eb64cf5".as_bytes(),
    //         "c131474164b412e3406696da1ee20ab0fc9bf41c8f05fa8ceea7a08d672d7cc5".as_bytes(),
    //         "f391da6ecfeed1814efae39e7fcb3838ae0b02c02ae7d0a5848a66947c0727b0".as_bytes(),
    //         "3d238a92a94532b946c90e19c49351c763696cff3db400485b813aecb8a13181".as_bytes(),
    //     ];

    //     merkle_tree.generate_merkle_tree(hex_hashes);

    //     assert_eq!(merkle_tree.get_root().unwrap().to_string(), expected_root);
    // }

    // #[test]
    // fn test_proof_of_inclution() {
    //     let mut merkle_tree = MerkleTree::new();

    //     let data = vec![
    //         "1".as_bytes(),
    //         "2".as_bytes(),
    //         "3".as_bytes(),
    //         "5".as_bytes(),
    //     ];
    //     let tx = "1".as_bytes();

    //     merkle_tree.generate_merkle_tree(data);

    //     assert_eq!(merkle_tree.proof_of_inclusion(tx), true)
    // }

    // #[test]
    // fn test_proof_of_inclution_does_not_contain_foul_transaction() {
    //     let mut merkle_tree = MerkleTree::new();

    //     let data = vec![
    //         "1".as_bytes(),
    //         "2".as_bytes(),
    //         "3".as_bytes(),
    //         "5".as_bytes(),
    //     ];
    //     let tx = "10".as_bytes();

    //     merkle_tree.generate_merkle_tree(data);

    //     assert_eq!(merkle_tree.proof_of_inclusion(tx), false)
    // }

    // #[test]
    // fn test_hash_produces_orignal_merkel_root() {
    //     let mut merkle_tree = MerkleTree::new();
    //     let origin_merkle_root: [u8; 32] = [
    //         240, 49, 95, 252, 56, 112, 157, 112, 173, 86, 71, 226, 32, 72, 53, 141, 211, 116, 95,
    //         60, 227, 135, 66, 35, 200, 10, 124, 146, 250, 176, 200, 186,
    //     ];
    //     let respuesta = merkle_tree.hash256(&origin_merkle_root);

    //     println!("Respuesta: {:?}", respuesta.to_string());
    // }
}
