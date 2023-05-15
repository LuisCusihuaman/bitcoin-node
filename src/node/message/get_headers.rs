use crate::utils::{get_offset, read_be, read_le};

type CompactSizeUint = String;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PayloadGetHeaders {
    version: u32,
    hash_count: u8,                // TODO VARIABLE
    block_header_hashes: [u8; 32], // TODO VARIABLE
    stop_hash: [u8; 32],
}

impl PayloadGetHeaders {
    pub fn size(&self) -> u64 {
        let mut size = 0;

        size += 4; // version
        size += 1; // TODO VARIABLE hash_count
        size += 32; // TODO VARIABLE block_header_hashes
        size += 32; // stop_hash

        size
    }

    pub fn encode(&self, buffer: &mut [u8]) -> Result<(), String> {
        buffer[0..4].copy_from_slice(&self.version.to_le_bytes()); // 4 bytes
        buffer[4..5].copy_from_slice(&self.hash_count.to_le_bytes()); // TODO ES VARIABLE
        buffer[5..37].copy_from_slice(&self.block_header_hashes); // 8 bytes
        buffer[37..].copy_from_slice(&self.stop_hash); // 8 bytes
        Ok(())
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
