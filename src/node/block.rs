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
    pub fn size_of(&self) -> usize {
        let version_size = std::mem::size_of::<u32>();
        let previous_block_header_hash_size = self.previous_block_header_hash.len();
        let merkle_root_hash_size = self.merkle_root_hash.len();
        let timestamp_size = std::mem::size_of::<u32>();
        let n_bits_size = std::mem::size_of::<u32>();
        let nonce_size = std::mem::size_of::<u32>();
        let tx_hashes_size = self.tx_hashes.len() * std::mem::size_of::<[u8; 32]>();

        version_size
            + previous_block_header_hash_size
            + merkle_root_hash_size
            + timestamp_size
            + n_bits_size
            + nonce_size
            + tx_hashes_size
    }
    pub fn encode(&self, buffer: &mut [u8]) {
        let mut offset = 0;

        // Encode version
        buffer[offset..offset + 4].copy_from_slice(&self.version.to_le_bytes());
        offset += 4;

        // Encode previous_block_header_hash
        let mut previous_block_header_hash = self.previous_block_header_hash;
        previous_block_header_hash.reverse();
        buffer[offset..offset + 32].copy_from_slice(&previous_block_header_hash);
        offset += 32;

        // Encode merkle_root_hash
        // Encode merkle_root_hash
        let mut merkle_root_hash = self.merkle_root_hash;
        merkle_root_hash.reverse();
        buffer[offset..offset + 32].copy_from_slice(&merkle_root_hash);
        offset += 32;

        // Encode timestamp
        buffer[offset..offset + 4].copy_from_slice(&self.timestamp.to_le_bytes());
        offset += 4;

        // Encode n_bits
        buffer[offset..offset + 4].copy_from_slice(&self.n_bits.to_le_bytes());
        offset += 4;

        // Encode nonce
        buffer[offset..offset + 4].copy_from_slice(&self.nonce.to_le_bytes());
        offset += 4;

        // Encode tx_hashes
        for hash in &self.tx_hashes {
            buffer[offset..offset + 32].copy_from_slice(hash);
            offset += 32;
        }
    }

    pub fn get_prev(&self) -> [u8; 32] {
        self.previous_block_header_hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_size_of() {
        let block = Block::new(
            1,
            [0; 32],
            [1; 32],
            1621285321,
            12345,
            67890,
            vec![[2; 32], [3; 32]],
        );

        let expected_size = std::mem::size_of::<u32>() // version
            + block.previous_block_header_hash.len()
            + block.merkle_root_hash.len()
            + std::mem::size_of::<u32>() // timestamp
            + std::mem::size_of::<u32>() // n_bits
            + std::mem::size_of::<u32>() // nonce
            + block.tx_hashes.len() * std::mem::size_of::<[u8; 32]>(); // tx_hashes

        assert_eq!(block.size_of(), expected_size);
    }

    #[test]

    fn test_block_encode() {
        let block = Block::new(
            1,
            [
                0, 0, 0, 0, 9, 51, 234, 1, 173, 14, 233, 132, 32, 151, 121, 186, 174, 195, 206,
                217, 15, 163, 244, 8, 113, 149, 38, 248, 215, 127, 73, 67,
            ],
            [
                240, 49, 95, 252, 56, 112, 157, 112, 173, 86, 71, 226, 32, 72, 53, 141, 211, 116,
                95, 60, 227, 135, 66, 35, 200, 10, 124, 146, 250, 176, 200, 186,
            ],
            1296688928,
            486604799,
            1924588547,
            vec![],
        );

        let block_size = block.size_of();
        let mut buffer_encoded = vec![0; block_size];
        block.encode(&mut buffer_encoded);

        let expected_buffer = [
            1, 0, 0, 0, 67, 73, 127, 215, 248, 38, 149, 113, 8, 244, 163, 15, 217, 206, 195, 174,
            186, 121, 151, 32, 132, 233, 14, 173, 1, 234, 51, 9, 0, 0, 0, 0, 186, 200, 176, 250,
            146, 124, 10, 200, 35, 66, 135, 227, 60, 95, 116, 211, 141, 53, 72, 32, 226, 71, 86,
            173, 112, 157, 112, 56, 252, 95, 49, 240, 32, 231, 73, 77, 255, 255, 0, 29, 3, 228,
            182, 114,
        ];
        assert_eq!(buffer_encoded, expected_buffer);
    }
}
