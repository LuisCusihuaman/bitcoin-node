#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Block {
    version: u32,
    prev_block: [u8; 32], // Hash prev block
    merkle_root: [u8; 32], // Hash merkle root
    timestamp: u64,
    bits: u32,
    nonce: u32,
    tx_hashes: Vec<[u8; 32]>, // Vec de hashes de tx
}

impl Block {
    pub fn new(
        version: u32, 
        prev_block: [u8; 32], 
        merkle_root: [u8; 32], 
        timestamp: u64,
        bits: u32,
        nonce: u32,
        tx_hashes: Vec<[u8; 32]>,
    ) -> Self {
        Self {
            version, 
            prev_block, 
            merkle_root, 
            timestamp,
            bits,
            nonce,
            tx_hashes
        }
    }
}
