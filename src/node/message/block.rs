
use super::MessagePayload;
use crate::utils::*;
use std::vec;

use std::{
    fs::{File, OpenOptions},
    io::Read,
    io::Write,
};

use super::get_headers::decode_header;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Block {
    version: u32,
    previous_block_header_hash: [u8; 32],
    merkle_root_hash: [u8; 32],
    timestamp: u32,
    n_bits: u32,
    nonce: u32,
    tx_hashes: Vec<[u8; 32]>, // "tx"
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

        // Encode tx_hashes, for complete initial download is zero.
        buffer[offset..offset + 1].copy_from_slice(&[0]);
    }

    pub fn get_prev(&self) -> [u8; 32] {
        self.previous_block_header_hash
    }
    pub fn decode_blocks_from_file(file_path: &str) -> Vec<Block> {
        let mut file = File::open(file_path).expect("Failed to open file");

        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer).expect("Failed to read file");

        let mut blocks = Vec::new();
        let mut offset = 0;
        while offset < buffer.len() {
            if let Some(block) = decode_header(&buffer[offset..offset + 81]) {
                offset += 81;
                blocks.push(block);
            } else {
                // Handle the case where decoding fails
                break;
            }
        }

        blocks
    }

    pub fn encode_blocks_to_file(blocks: &Vec<Block>, file_path: &str) {
        // Get the total size of blocks
        let total_size = blocks.len() * 81;

        // Create a buffer to hold all the encoded blocks
        let mut buffer = vec![0; total_size];

        // Encode each block and append it to the buffer
        let mut offset: usize = 0;
        for block in blocks {
            block.encode(&mut buffer[offset..]);
            offset += 81;
        }

        // Open the file in append mode
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(file_path)
            .expect("Failed to open file");

        // Write the buffer to the file
        file.write_all(&buffer).expect("Failed to write to file");
    }
}

pub fn decode_block(buffer: &[u8]) -> Result<MessagePayload, String> {
    
    let _count = read_varint(&mut &buffer[0..])?;
    let offset = get_offset(&buffer[..]);

    let chunked = buffer[offset..].chunks(36);
    let mut inv = vec![];

    for bufercito in chunked.clone() {
        match decode_internal_block(bufercito) {
            Some(block) => {
                inv.push(block);
            }
            None => continue,
        }
    }

    Ok(MessagePayload::Block(inv))
}

fn decode_internal_block(buffer: &[u8]) -> Option<Block> {
    if buffer.len() != 36 {
        return None;
    }

    // let type_inv = read_u32_le(&buffer, 0);
    // let mut hash: [u8; 32] = [0u8; 32];
    // copy_bytes_to_array(&buffer[4..36], &mut hash);
    // hash.reverse();

    Some(Block::new(
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
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

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

        let mut buffer_encoded = vec![0; 81];
        block.encode(&mut buffer_encoded);

        let expected_buffer = [
            1, 0, 0, 0, 67, 73, 127, 215, 248, 38, 149, 113, 8, 244, 163, 15, 217, 206, 195, 174,
            186, 121, 151, 32, 132, 233, 14, 173, 1, 234, 51, 9, 0, 0, 0, 0, 186, 200, 176, 250,
            146, 124, 10, 200, 35, 66, 135, 227, 60, 95, 116, 211, 141, 53, 72, 32, 226, 71, 86,
            173, 112, 157, 112, 56, 252, 95, 49, 240, 32, 231, 73, 77, 255, 255, 0, 29, 3, 228,
            182, 114, 0,
        ];
        assert_eq!(buffer_encoded, expected_buffer);
    }
    #[test]
    fn test_decode_blocks_from_file() {
        // Create a temporary file with encoded blocks
        let file_path = "block_headers.bin";
        let blocks = vec![
            Block::new(
                1,
                [
                    0, 0, 0, 0, 9, 51, 234, 1, 173, 14, 233, 132, 32, 151, 121, 186, 174, 195, 206,
                    217, 15, 163, 244, 8, 113, 149, 38, 248, 215, 127, 73, 67,
                ],
                [
                    240, 49, 95, 252, 56, 112, 157, 112, 173, 86, 71, 226, 32, 72, 53, 141, 211,
                    116, 95, 60, 227, 135, 66, 35, 200, 10, 124, 146, 250, 176, 200, 186,
                ],
                1296688928,
                486604799,
                1924588547,
                vec![],
            ),
            Block::new(
                1,
                [
                    0, 0, 0, 0, 9, 51, 234, 1, 173, 14, 233, 132, 32, 151, 121, 186, 174, 195, 206,
                    217, 15, 163, 244, 8, 113, 149, 38, 248, 215, 127, 73, 67,
                ],
                [
                    240, 49, 95, 252, 56, 112, 157, 112, 173, 86, 71, 226, 32, 72, 53, 141, 211,
                    116, 95, 60, 227, 135, 66, 35, 200, 10, 124, 146, 250, 176, 200, 186,
                ],
                1296688928,
                486604799,
                1924588547,
                vec![],
            ),
        ];
        Block::encode_blocks_to_file(&blocks, file_path);

        // Decode blocks from the file
        let decoded_blocks = Block::decode_blocks_from_file(file_path);

        // Ensure the decoded blocks match the original blocks
        assert_eq!(decoded_blocks, blocks);

        // Cleanup: delete the temporary file
        std::fs::remove_file(file_path).unwrap();
    }
}
