#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Block {
    block_header: BlockHeader,
    tx_hashes: Vec<[u8; 32]>, // Vec de hashes de tx
                              // TODO check if add more fields
}

impl Block {
    pub fn new(tx_hashes: Vec<[u8; 32]>, block_header: BlockHeader) -> Self {
        Self {
            tx_hashes,
            block_header,
        }
    }

    pub fn get_prev(&self)-> [u8; 32]{
        self.block_header.previous_block_header_hash
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockHeader {
    pub version: u32,
    pub previous_block_header_hash: [u8; 32],
    pub merkle_root_hash: [u8; 32],
    pub timestamp: u32,
    pub n_bits: u32,
    pub nonce: u32,
}

impl BlockHeader {
    pub fn new(
        version: u32,
        previous_block_header_hash: [u8; 32],
        merkle_root_hash: [u8; 32],
        timestamp: u32,
        n_bits: u32,
        nonce: u32,
    ) -> Self {
        Self {
            version,
            previous_block_header_hash,
            merkle_root_hash,
            timestamp,
            n_bits,
            nonce,
        }
    }
}
