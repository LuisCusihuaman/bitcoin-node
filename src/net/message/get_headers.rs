use super::block::Block;
use super::MessagePayload;

use crate::utils::*;
use bitcoin_hashes::Hash;
use std::{mem, vec};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PayloadGetHeaders {
    version: u32,
    hash_count: usize,            // variable size
    block_header_hashes: Vec<u8>, // variable size
    stop_hash: Vec<u8>,
}

impl PayloadGetHeaders {
    pub fn size(&self) -> usize {
        let mut size = 0;

        let hash_count = get_le_varint(self.hash_count);

        size += mem::size_of::<u32>(); // version
        size += hash_count.len(); // variable size
        size += self.block_header_hashes.len(); // variable size
        size += self.stop_hash.len(); // stop_hash

        size
    }

    pub fn encode(&self, buffer: &mut [u8]) {
        let mut offset = 0;
        let hash_count = get_le_varint(self.hash_count);

        buffer[offset..4].copy_from_slice(&self.version.to_le_bytes()); // 4 bytes
        offset += 4;

        buffer[offset..offset + hash_count.len()].copy_from_slice(&hash_count); // variable size
        offset += hash_count.len();

        buffer[offset..37].copy_from_slice(&self.block_header_hashes); // variable size
        offset += self.block_header_hashes.len();

        buffer[offset..].copy_from_slice(&self.stop_hash); // 8 bytes
    }

    pub fn new(
        version: u32,
        hash_count: usize,
        block_header_hashes: Vec<u8>,
        stop_hash: Vec<u8>,
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
    let _count = read_varint(&buffer[0..]);
    let offset = get_offset(buffer);

    let chunked = buffer[offset..].chunks(81);
    let mut blocks = vec![];

    for bufercito in chunked.clone() {
        match decode_header(bufercito) {
            Some(block) => {
                blocks.push(block);
            }
            None => continue,
        }
    }

    Ok(MessagePayload::BlockHeader(blocks))
}

pub fn decode_header(buffer: &[u8]) -> Option<Block> {
    if buffer.len() != 81 {
        return None;
    }

    let version = read_u32_le(buffer, 0);

    let raw_hash = double_sha256(&buffer[0..80]).to_byte_array();
    let mut hash: [u8; 32] = [0u8; 32];
    copy_bytes_to_array(&raw_hash, &mut hash);
    hash.reverse();

    let mut previous_block: [u8; 32] = [0u8; 32];
    copy_bytes_to_array(&buffer[4..36], &mut previous_block);
    previous_block.reverse();

    let mut merkle_root_hash: [u8; 32] = [0u8; 32];
    copy_bytes_to_array(&buffer[36..68], &mut merkle_root_hash);
    merkle_root_hash.reverse();

    let timestamp = read_le(&buffer[68..72]) as u32;
    let n_bits = read_le(&buffer[72..76]) as u32;
    let nonce = read_le(&buffer[76..80]) as u32;

    let txn_count = read_varint(&buffer[80..]);

    Some(Block {
        version,
        hash,
        previous_block,
        merkle_root_hash,
        timestamp,
        n_bits,
        nonce,
        txn_count,
        txns: vec![],
    })
}
