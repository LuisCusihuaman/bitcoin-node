use crate::utils::get_le_varint;
use std::mem;
// The “getheaders” message is nearly identical to the “getblocks” message, with one minor difference:
// the inv reply to the “getblocks” message will include no more than 500 block header hashes;
// the headers reply to the “getheaders” message will include as many as 2,000 block headers.

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PayloadGetBlocks {
    pub version: u32,
    pub hash_count: usize,            // variable size
    pub block_header_hashes: Vec<u8>, // variable size
    pub stop_hash: Vec<u8>,
}

impl PayloadGetBlocks {
    pub fn size(&self) -> usize {
        let mut size = 0;
        let hash_count_bytes = get_le_varint(self.hash_count);

        size += mem::size_of::<u32>(); // version
        size += hash_count_bytes.len(); // variable size
        size += self.block_header_hashes.len(); // variable size
        size += self.stop_hash.len(); // stop_hash

        size
    }

    pub fn encode(&self, buffer: &mut [u8]) {
        let hash_count_bytes = get_le_varint(self.hash_count);
        let mut offset = 0;

        buffer[0..4].copy_from_slice(&self.version.to_le_bytes()); // 4 bytes
        offset += 4;

        let count_size = hash_count_bytes.len();
        buffer[offset..offset + count_size].copy_from_slice(&hash_count_bytes); // variable size
        offset += count_size;

        buffer[offset..offset + self.block_header_hashes.len()]
            .copy_from_slice(&self.block_header_hashes); // variable size
        offset += self.block_header_hashes.len();

        buffer[offset..].copy_from_slice(&self.stop_hash); // 8 bytes
    }
}
