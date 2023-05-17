#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Block {
    version: u32,
    previous_block_header_hash: [u8; 32],
    merkle_root_hash: [u8; 32],
    timestamp: u32,
    n_bits: u32,
    nonce: u32,
    tx_hashes: Vec<[u8; 32]>,
}

impl Block {
    pub fn new(
        version: u32,
        previous_block_header_hash: [u8; 32],
        merkle_root_hash: [u8; 32],
        timestamp: u32,
        n_bits: u32,
        nonce: u32,
        tx_hashes: Vec<[u8; 32]>,
    ) -> Self {
        Self {
            version,
            previous_block_header_hash,
            merkle_root_hash,
            timestamp,
            n_bits,
            nonce,
            tx_hashes,
        }
    }

    pub fn get_prev(&self) -> [u8; 32] {
        self.previous_block_header_hash
    }
}
