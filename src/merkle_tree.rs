// Implementacion de merkle tree
use bitcoin_hashes::{sha256, Hash, HashEngine};

pub struct MerkleTree {
    root: String,
    leaves: Vec<String>,
}

impl MerkleTree{
    pub fn new() -> Self {
        Self {
            root: "".to_owned(),
            leaves: Vec::new(),
        }
    }

    pub fn get_root(&self) -> String {
        String::from(&self.root)
    }

    pub fn get_leaves(&self) -> Vec<String> {
        self.leaves[..].to_vec()
    }

     // Basado de aca https://stackoverflow.com/questions/108318/how-can-i-test-whether-a-number-is-a-power-of-2
     fn is_power_of_two(&self, n: usize) -> bool {
        if n == 0 {
            return false;
        }
        (n & (n - 1)) == 0
    }

    pub fn generate_leaves(&mut self, data: Vec<&str>) {
       
        // Guardo las hojas
        for d in data {
            self.leaves.push(d.to_string());
        }

        // Lleno el arbol con hojas hasta que sea potencia de 2
        if !self.is_power_of_two(self.leaves.len()) {
            let last_leave = match self.leaves.last() {
                Some(last) => last.to_string(),
                None => "".to_string(),
            };

            while !self.is_power_of_two(self.leaves.len()) {
                self.leaves.push(String::from(&last_leave));
            }
        } 
    }
/*
        // Creo el arbol
        let mut tree = Vec::new();
        let mut i = 0;
        while (i < self.leaves.len()) {
            tree.push(self.leaves[i].clone());
            i += 1;
        }

        // Creo el arbol
        while (tree.len() > 1) {
            let mut new_tree = Vec::new();
            let mut i = 0;
            while (i < tree.len()) {
                let mut hash = Sha256::new();
                hash.input_str(&tree[i]);
                let mut hash = hash.result_str();
                new_tree.push(hash);
                i += 2;
            }
            tree = new_tree;       
        }
    }

    */

    // Convierte el input en un hash
    fn hash256(&self, data: &str) -> sha256::Hash {
        sha256::Hash::hash(data.as_bytes())
    }

    // Takes the binary hashes and calculates the hash256
    // this implementation assumes that the child node hashes are already in SHA-256 
    pub fn merkle_parent(&self, left: &[u8], right: &[u8]) -> sha256::Hash{
        let mut hasher = sha256::Hash::engine();
        hasher.input(left);
        hasher.input(right);
        sha256::Hash::from_engine(hasher)
    }

    // Indica si la transaccion pertenece al arbol
    pub fn proof_of_inclusion(&self, data: &str) -> bool {
        // TODO
        true
    }
   
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_merkle_tree_with_empty_root() {

        let merkle_tree = MerkleTree::new();
        let expected = "";

        assert_eq!(merkle_tree.get_root(), expected );
    }

    #[test]
    fn test_create_merkle_tree_with_empty_leaves(){
        let merkle_tree = MerkleTree::new();
        let expected = 0;

        assert_eq!(merkle_tree.get_leaves().len(), expected );
    }


    // No relleno hojas cuando ya tengo potencia de 2
    #[test]
    fn test_create_merkle_tree_with_four_leaves() {

        let mut merkle_tree = MerkleTree::new();

        let data = vec!["1","2", "3", "5"];
        
        merkle_tree.generate_leaves(data);

        assert_eq!(merkle_tree.get_leaves().len(),4 );
    }

    // Relleno las hojas hasta que tengan potencia de 2
    #[test]
    fn test_create_merkle_tree_with_five_leaves() {

        let mut merkle_tree = MerkleTree::new();

        let data = vec!["1","2", "3", "4", "5"];
        
        merkle_tree.generate_leaves(data);

        assert_eq!(merkle_tree.get_leaves().len(), 8 );
    }

    #[test]
    fn test_generates_hash_number_correctly(){
        let hash = MerkleTree::new().hash256("1");

        assert!(hash.to_string().is_empty() == false);
    }

    #[test]
    fn test_generates_merkle_parent_correctly(){
        let merkle_tree = MerkleTree::new();
        let left_hash = merkle_tree.hash256("1");
        let right_hash = merkle_tree.hash256("2");


        let parent = merkle_tree.merkle_parent(left_hash.as_ref(), right_hash.as_ref());

        
        let expected_hash = merkle_tree.hash256("12");

        assert_eq!(parent, expected_hash);
    }

/*
    // Genero el root correctamente
    #[test]
    fn test_creates_root_correctly(){
        let mut merkle_tree = MerkleTree::new();
        
        let data = vec!["1","2", "3", "4"];
        
        merkle_tree.generate_leaves(data);

        assert_eq!(merkle_tree.get_root().is_empty(), false );
    }

    */
}