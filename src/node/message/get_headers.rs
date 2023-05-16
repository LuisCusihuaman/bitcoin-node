use std::vec;

use crate::node::block::{Block, BlockHeader};
use crate::utils::*;

use super::MessagePayload;

type CompactSizeUint = String;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PayloadGetHeaders {
    version: u32,
    hash_count: u8,                // TODO Variable size
    block_header_hashes: [u8; 32], // TODO Variable size
    stop_hash: [u8; 32],
}

impl PayloadGetHeaders {
    pub fn size(&self) -> u64 {
        let mut size = 0;

        size += 4; // version
        size += 1; // TODO Variable size
        size += 32; // TODO Variable size
        size += 32; // stop_hash

        size
    }

    pub fn encode(&self, buffer: &mut [u8]) -> Result<(), String> {
        buffer[0..4].copy_from_slice(&self.version.to_le_bytes()); // 4 bytes
        buffer[4..5].copy_from_slice(&self.hash_count.to_le_bytes()); // TODO Variable size
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

pub fn decode_headers(buffer: &[u8]) -> Result<MessagePayload, String> {
    let chunked = buffer.chunks(80);

    let mut blocks = vec![];
    let mut block;

    for bufercito in chunked.clone() {
        match decode_header(bufercito) {
            Some(header) => {
                block = new_block(header);
                blocks.push(block);
            }
            None => continue,
        }
    }
    Ok(MessagePayload::BlockHeader(blocks))
}

fn decode_header(buffer: &[u8]) -> Option<BlockHeader> {
    if buffer.len() != 80 {
        return None;
    }

    let version = read_u32_le(&buffer, 0);

    let mut previous_block_header_hash: [u8; 32] = [0u8; 32];
    copy_bytes_to_array(&buffer[4..36], &mut previous_block_header_hash);

    let mut merkle_root_hash: [u8; 32] = [0u8; 32];
    copy_bytes_to_array(&buffer[36..68], &mut merkle_root_hash);

    let timestamp = read_le(&buffer[68..72]) as u32;
    let n_bits = read_le(&buffer[72..76]) as u32;
    let nonce = read_le(&buffer[76..80]) as u32;

    Some(BlockHeader::new(
        version,
        previous_block_header_hash,
        merkle_root_hash,
        timestamp,
        n_bits,
        nonce,
    ))
}

fn new_block(block_header: BlockHeader) -> Block {
    let tx_hashes: Vec<[u8; 32]> = Vec::new();

    Block::new(tx_hashes, block_header)
}
