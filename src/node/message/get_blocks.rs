// The “getheaders” message is nearly identical to the “getblocks” message, with one minor difference:
// the inv reply to the “getblocks” message will include no more than 500 block header hashes;
// the headers reply to the “getheaders” message will include as many as 2,000 block headers.

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PayloadGetBlocks {
    version: u32,
    hash_count: u8,                // TODO Variable size
    block_header_hashes: [u8; 32], // TODO Variable size
    stop_hash: [u8; 32],
}

impl PayloadGetBlocks {
    pub fn size(&self) -> u64 {
        let mut size = 0;
        size += 4; // version
        size += 1; // TODO Variable size
        size += 32; // TODO Variable size
        size += 32; // stop_hash

        size
    }

    pub fn encode(&self, buffer: &mut [u8]) {
        buffer[0..4].copy_from_slice(&self.version.to_le_bytes()); // 4 bytes
        buffer[4..5].copy_from_slice(&self.hash_count.to_le_bytes()); // TODO Variable size
        buffer[5..37].copy_from_slice(&self.block_header_hashes); // 8 bytes
        buffer[37..].copy_from_slice(&self.stop_hash); // 8 bytes
    }

    pub fn new(
        version: u32,
        hash_count: u8,
        block_header_hashes: [u8; 32],
        stop_hash: [u8; 32],
    ) -> Self {
        Self {
            version,
            hash_count,
            block_header_hashes,
            stop_hash,
        }
    }
}
