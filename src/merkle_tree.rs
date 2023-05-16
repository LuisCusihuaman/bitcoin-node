// Implementacion de merkle tree
use bitcoin_hashes::{sha256, Hash, HashEngine};

pub struct MerkleTree {
    root: String,
    leaves: Vec<String>,
    hashed_leaves: Vec<sha256::Hash>,
}

impl MerkleTree{
    pub fn new() -> Self {
        Self {
            root: "".to_owned(),
            leaves: Vec::new(),
            hashed_leaves: Vec::new(),
        }
    }

    pub fn get_root(&self) -> String {
        String::from(&self.root)
    }

    pub fn get_leaves(&self) -> Vec<String> {
        self.leaves[..].to_vec()
    }

     // Basado de aca https://stackoverflow.com/questions/108318/how-can-i-test-whether-a-number-is-a-power-of-2
     // Borrar si al final no se usa
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

        // Lleno el arbol con hojas hasta que tenga multiplo de 2 hojas
        if self.leaves.len() % 2 == 1 {
            let last_leave = match self.leaves.last() {
                Some(last) => last.to_string(),
                None => "".to_string(),
            };

            self.leaves.push(String::from(&last_leave));
            
        } 

        // Convierto las hojas a hashes
        for l in &self.leaves {
            let hash = self.hash256(l.as_bytes());
            self.hashed_leaves.push(hash);
        }

        //self.armar_arbol_rec();

    }

       // Convierte el input en un hash
       fn hash256(&self, data: &[u8]) -> sha256::Hash {
        sha256::Hash::hash(data)
    }

    // Takes the binary hashes and calculates the hash256
    // this implementation assumes that the child node hashes are already in SHA-256 
    pub fn merkle_parent(&self, left: &[u8], right: &[u8]) -> sha256::Hash{
        let mut hasher = sha256::Hash::engine();
        hasher.input(left);
        hasher.input(right);
        sha256::Hash::from_engine(hasher)
    }

    // Recibe una lista de hashes y devuelve una lista que es la mitad de largo
    // Estos hashes pueden ser hojas o nodos
    pub fn merkle_parent_level(&self, mut hashes: Vec<sha256::Hash>)-> Vec<sha256::Hash>{
        if hashes.len() == 1 {
            panic!("Cannot take a parent level with only 1 item"); // ARREGLAR
        }

        if hashes.len() % 2 == 1 {
            // Si la cantidad de hashes es impar, duplico el ultimo
            let last = match hashes.last() {
                Some(last) => last,
                None => panic!("No last element"), // ARREGLAR
            };
            hashes.push(last.clone());
        }

        let mut parent_level = Vec::new();
        let mut i = 0;

        while i < hashes.len() {
            let parent = self.merkle_parent(&hashes[i].as_ref(), &hashes[i + 1].as_ref());
            parent_level.push(parent);
            i += 2;
        }

        parent_level
    }

/* 
    def merkle_parent_level(hashes):
        '''Takes a list of binary hashes and returns a list that's half
        the length'''
        if len(hashes) == 1:
        raise RuntimeError('Cannot take a parent level with only 1 item')
        if len(hashes) % 2 == 1:
        hashes.append(hashes[-1])
        parent_level = []
        for i in range(0, len(hashes), 2):
        parent = merkle_parent(hashes[i], hashes[i + 1])
        parent_level.append(parent)
        return parent_level
*/
/*
    fn armar_arbol_rec(&self){
        let mut new_tree = Vec::new();
        let mut i = 0;
        while (i < self.hashed_leaves.len()) {
            let mut hash = Sha256::new();
            hash.input_str(&self.hashed_leaves[i]);
            let mut hash = hash.result_str();
            new_tree.push(hash);
            i += 2;
        }
        tree = new_tree;
    }

*/
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

    // Relleno las hojas hasta que tengan multiplo de 2
    #[test]
    fn test_create_merkle_tree_with_five_leaves() {

        let mut merkle_tree = MerkleTree::new();

        let data = vec!["1","2", "3", "4", "5"];
        
        merkle_tree.generate_leaves(data);

        assert_eq!(merkle_tree.get_leaves().len(), 6 );
    }

    #[test]
    fn test_generates_hash_number_correctly(){
        let hash = MerkleTree::new().hash256("1".as_bytes());

        assert!(hash.to_string().is_empty() == false);
    }

    #[test]
    fn test_generates_merkle_node_parent_correctly(){
        let merkle_tree = MerkleTree::new();
        let left_hash = merkle_tree.hash256("1".as_bytes());
        let right_hash = merkle_tree.hash256("2".as_bytes());

        // Concatenated va a tener el resultado de concatenar en bytes Hash(1)+Hash(2)
        let mut concatenated = Vec::new();
        concatenated.extend_from_slice(left_hash.as_ref());
        concatenated.extend_from_slice(right_hash.as_ref());

        let expected_hash = merkle_tree.hash256(&concatenated);

        let parent = merkle_tree.merkle_parent(&left_hash.as_ref(), &right_hash.as_ref());
        
        assert_eq!(parent, expected_hash);
    }

    #[test]
    fn test_merkle_parent_level_returns_hash_vector_half_its_even_size(){
        let merkle_tree = MerkleTree::new();
        let mut hashes = Vec::new();
        hashes.push(merkle_tree.hash256("1".as_bytes()));
        hashes.push(merkle_tree.hash256("2".as_bytes()));
        hashes.push(merkle_tree.hash256("3".as_bytes()));
        hashes.push(merkle_tree.hash256("4".as_bytes()));

        let expected_len = hashes.len() / 2;

        let parent_level = merkle_tree.merkle_parent_level(hashes);


        assert_eq!(parent_level.len(), expected_len);
    } 

    #[test]
    fn test_merkle_parent_level_returns_hash_vector_half_its_un_even_size(){
        let merkle_tree = MerkleTree::new();
        let mut hashes = Vec::new();
        hashes.push(merkle_tree.hash256("1".as_bytes()));
        hashes.push(merkle_tree.hash256("2".as_bytes()));
        hashes.push(merkle_tree.hash256("3".as_bytes()));
        hashes.push(merkle_tree.hash256("4".as_bytes()));
        hashes.push(merkle_tree.hash256("5".as_bytes()));

        let expected_len = (hashes.len()+1) / 2;

        let parent_level = merkle_tree.merkle_parent_level(hashes);

        assert_eq!(parent_level.len(), expected_len);
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