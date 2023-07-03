use super::block::Block;
use super::MessagePayload;

use crate::utils::*;
use bitcoin_hashes::Hash;
use std::{mem, vec};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PayloadGetHeaders {
    version: u32,
    hash_count: usize,                // variable size
    pub block_header_hashes: Vec<u8>, // variable size
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

        let mut aux = 0;
        for _ in 0..self.hash_count {
            let mut hash = [0u8; 32];

            hash.copy_from_slice(&self.block_header_hashes[aux..aux + 32]);
            hash.reverse();
            aux += 32;

            buffer[offset..offset + 32].copy_from_slice(&hash); // variable size
            offset += 32;
        }

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

pub fn decode_get_headers(buffer: &[u8]) -> Result<MessagePayload, String> {
    let mut offset = 0;

    let version = read_u32_le(buffer, offset);
    offset += 4;

    let hash_count = read_varint(&buffer[offset..]);
    offset += get_offset(&buffer[offset..]);

    let mut block_header_hashes: Vec<u8> = Vec::new();
    for _ in 0..hash_count {
        let mut header = buffer[offset..offset + 32].to_vec();
        header.reverse();

        block_header_hashes.extend(header);
        offset += 32;
    }

    let mut stop_hash = buffer[offset..offset + 32].to_vec();
    stop_hash.reverse();

    let payload = PayloadGetHeaders {
        version,
        hash_count,
        block_header_hashes,
        stop_hash,
    };

    Ok(MessagePayload::GetHeaders(payload))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PayloadHeaders {
    pub count: usize,        // variable size
    pub headers: Vec<Block>, // variable size
}

impl PayloadHeaders {
    pub fn size(&self) -> usize {
        let mut size = 0;

        size += get_le_varint(self.count).len();
        size += self.headers.len() * 81;

        size
    }

    pub fn encode(&self, buffer: &mut [u8]) {
        let mut offset = 0;

        let count = get_le_varint(self.count);
        buffer[offset..offset + count.len()].copy_from_slice(&count);
        offset += count.len();

        for header in &self.headers {
            let mut aux = header.clone();

            aux.txn_count = 0;
            aux.txns = vec![];

            aux.encode(&mut buffer[offset..]);
            offset += aux.size();
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

    let payload = PayloadHeaders {
        count: blocks.len(),
        headers: blocks,
    };

    Ok(MessagePayload::Headers(payload))
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
