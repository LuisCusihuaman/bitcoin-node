use super::merkle_tree::MerkleTree;
use super::tx::Tx;
use super::MessagePayload;
use crate::error::Error;
use crate::node::message::tx::decode_tx;
use crate::utils::*;
use bitcoin_hashes::Hash;
use std::vec;

use std::{
    fs::{File, OpenOptions},
    io::Read,
    io::Write,
};

use super::get_headers::decode_header;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Block {
    pub version: u32,
    pub hash: [u8; 32],
    pub previous_block: [u8; 32],
    pub merkle_root_hash: [u8; 32],
    pub timestamp: u32,
    pub n_bits: u32,
    pub nonce: u32,
    pub txn_count: usize, // variable size
    pub txns: Vec<Tx>,    // variable size
}

impl Block {
    // // generates the target to validate proof of work using this formula
    // // target = coefficient * 256**(exponent - 3)
    pub fn target(&self) -> u64 {
        let bits = self.n_bits.to_le_bytes();
        let exponent = bits[3] as u32;
        let coefficient = u32::from_le_bytes([bits[0], bits[1], bits[2], 0]);

        coefficient as u64 * 256u64.pow(exponent - 3)
    }

    // generates the target to validate proof of work
    // // target = coefficient * 256**(exponent - 3)
    // pub fn target(&self) -> u32 {

    //     let bits = self.n_bits.to_le_bytes();
    //     let exponent = bits[3] as u32;
    //     let coefficient = read_le(&[bits[0], bits[1], bits[2]]) as u32;

    //     coefficient * 256u32.pow((exponent - 3) as u32)
    // }

    /*
       Otra opcion

       pub fn target(&self) -> [u8,32] {

           let bits = self.n_bits.to_le_bytes();
           let exponent = (bits[3] >> 3) as usize;
           let mantissa = u32::from_le_bytes([bits[0], bits[1], bits[2], 0]) >> exponent;

           let mut target = [0u8; 32];
           target[31] = (mantissa & 0xff) as u8;
           target[30] = ((mantissa >> 8) & 0xff) as u8;
           target[29] = ((mantissa >> 16) & 0xff) as u8;
           target

           // coefficient * 256**(exponent - 3)
       }

    */

    pub fn validate_pow(&self) -> bool {
        let _target = self.target() as u128;

        let target: u128 = 0x00000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF;

        println!("Target: {}\n", target);

        // little_endian_to_int(sha(required_target));
        let sha = self.hash;
        let sha_num = little_endian_to_int(&sha);
        println!("sha_num: {}\n", sha_num);

        sha_num < target
    }

    fn init_merkle_tree(&self) -> MerkleTree {
        let tx_ids: Vec<&[u8]> = self.txns.iter().map(|tx| &tx.id[..]).collect();
        let tx_ids_reverse: Vec<Vec<u8>> = tx_ids
            .iter()
            .map(|id| id.iter().rev().copied().collect())
            .collect();
        let tx_ids_reverse_refs: Vec<&[u8]> = tx_ids_reverse.iter().map(|id| id.as_ref()).collect();

        let mut merkle_tree = MerkleTree::new();
        merkle_tree.generate_merkle_tree(tx_ids_reverse_refs);

        merkle_tree
    }

    pub fn get_merkle_tree_root(&self) -> Result<[u8; 32], Error> {
        let merkle_tree = self.init_merkle_tree();

        let hash_root = merkle_tree.get_root()?;
        let mut hash_root_array = [0u8; 32];
        hash_root_array.copy_from_slice(&hash_root[..]);
        hash_root_array.reverse();
        Ok(hash_root_array)
    }

    //let mut merkle_tree = MerkleTree::new();
    //merkle_tree.generate_merkle_tree(raw_trxs);

    pub fn proof_of_inclusion(&self, tx_req: Tx) -> bool {
        let merkle_tree = self.init_merkle_tree();
        let mut tx_id = tx_req.id;
        tx_id.reverse();
        merkle_tree.proof_of_inclusion(&tx_id)
    }

    pub fn encode(&self, buffer: &mut [u8]) {
        let mut offset = 0;

        // Encode version
        buffer[offset..offset + 4].copy_from_slice(&self.version.to_le_bytes());
        offset += 4;

        // Encode previous_block_header_hash
        let mut previous_block_header_hash = self.previous_block;
        previous_block_header_hash.reverse();
        buffer[offset..offset + 32].copy_from_slice(&previous_block_header_hash);
        offset += 32;

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

        // txn_count
        let tx_count = get_le_varint(self.txn_count);
        buffer[offset..offset + tx_count.len()].copy_from_slice(&tx_count);

        // Encode txns, for complete initial download is zero.
        // buffer[offset..offset + 1].copy_from_slice(&[0]);
    }

    pub fn get_prev(&self) -> [u8; 32] {
        self.previous_block
    }

    pub fn get_hash(&self) -> [u8; 32] {
        self.hash
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
    if buffer.is_empty() {
        return Err("Empty buffer".to_string());
    }

    let mut block = decode_internal_block(buffer).unwrap();
    let mut transactions = Vec::new();

    let tnx_count = read_varint(&mut &buffer[80..]);
    let mut offset = 80 + get_offset(&buffer[80..]);

    for _ in 0..tnx_count {
        if let Some(tx) = decode_tx(buffer, &mut offset) {
            transactions.push(tx);
        } else {
            return Err("Failed to decode transaction".to_string());
        }
    }
    block.txn_count = tnx_count;
    block.txns = transactions;

    Ok(MessagePayload::Block(block))
}

pub fn decode_internal_block(buffer: &[u8]) -> Option<Block> {
    let version = read_u32_le(buffer, 0);

    let mut previous_block: [u8; 32] = [0u8; 32];
    copy_bytes_to_array(&buffer[4..36], &mut previous_block);
    previous_block.reverse();

    let mut merkle_root_hash: [u8; 32] = [0u8; 32];
    copy_bytes_to_array(&buffer[36..68], &mut merkle_root_hash);
    merkle_root_hash.reverse();

    let timestamp = read_le(&buffer[68..72]) as u32;
    let n_bits = read_le(&buffer[72..76]) as u32;
    let nonce = read_le(&buffer[76..80]) as u32;

    let raw_hash = double_sha256(&buffer[0..80]).to_byte_array();
    let mut hash: [u8; 32] = [0u8; 32];
    copy_bytes_to_array(&raw_hash, &mut hash);
    hash.reverse();

    Some(Block {
        version,
        hash,
        previous_block,
        merkle_root_hash,
        timestamp,
        n_bits,
        nonce,
        txn_count: 0,
        txns: Vec::new(),
    })
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::node::message::tx::{Tx, TxIn, TxOut};

    #[test]
    fn test_proof_of_inclution_doesnt_have_invalid_tx() {
        let mut block = Block {
            version: 1,
            hash: [
                0, 0, 0, 0, 9, 51, 234, 1, 173, 14, 233, 132, 32, 151, 121, 186, 174, 195, 206,
                217, 15, 163, 244, 8, 113, 149, 38, 248, 215, 127, 73, 67,
            ],
            previous_block: [
                0, 0, 0, 0, 9, 51, 234, 1, 173, 14, 233, 132, 32, 151, 121, 186, 174, 195, 206,
                217, 15, 163, 244, 8, 113, 149, 38, 248, 215, 127, 73, 67,
            ],
            merkle_root_hash: [
                240, 49, 95, 252, 56, 112, 157, 112, 173, 86, 71, 226, 32, 72, 53, 141, 211, 116,
                95, 60, 227, 135, 66, 35, 200, 10, 124, 146, 250, 176, 200, 186,
            ],
            timestamp: 1296688928,
            n_bits: 486604799,
            nonce: 1924588547,
            txn_count: 3,
            txns: Vec::new(),
        };

        let tx_1 = Tx {
            id: [0u8; 32],
            version: 1,
            flag: 0,
            tx_in_count: 2, // varint
            tx_in: vec![
                TxIn {
                    previous_output: [0; 36],
                    script_length: 0, // varint
                    signature_script: vec![],
                    sequence: 0,
                },
                TxIn {
                    previous_output: [0; 36],
                    script_length: 0, // varint
                    signature_script: vec![],
                    sequence: 0,
                },
            ],
            tx_out_count: 1, // varint
            tx_out: vec![TxOut {
                value: 100_000_000,
                pk_script_length: 0, // varint
                pk_script: vec![],
            }],
            tx_witness: vec![],
            lock_time: 0,
        };

        let tx_2 = Tx {
            id: [0u8; 32],
            version: 1,
            flag: 0,
            tx_in_count: 2, // varint
            tx_in: vec![
                TxIn {
                    previous_output: [0; 36],
                    script_length: 0, // varint
                    signature_script: vec![],
                    sequence: 0,
                },
                TxIn {
                    previous_output: [0; 36],
                    script_length: 0, // varint
                    signature_script: vec![],
                    sequence: 0,
                },
            ],
            tx_out_count: 1, // varint
            tx_out: vec![TxOut {
                value: 100_000_000,
                pk_script_length: 0, // varint
                pk_script: vec![],
            }],
            tx_witness: vec![],
            lock_time: 0,
        };

        let not_expected_tnx = Tx {
            id: [1u8; 32],
            version: 1,
            flag: 0,
            tx_in_count: 1, // varint
            tx_in: vec![TxIn {
                previous_output: [0; 36],
                script_length: 0, // varint
                signature_script: vec![],
                sequence: 0,
            }],
            tx_out_count: 1, // varint
            tx_out: vec![TxOut {
                value: 100_000_000,
                pk_script_length: 0, // varint
                pk_script: vec![],
            }],
            tx_witness: vec![],
            lock_time: 0,
        };

        block.txns = vec![tx_1, tx_2];

        assert_eq!(block.proof_of_inclusion(not_expected_tnx), false);
    }

    #[test]
    fn test_proof_of_inclusion_is_included() {
        let mut block = Block {
            version: 2,
            hash: [
                0, 0, 0, 0, 9, 51, 234, 1, 173, 14, 233, 132, 32, 151, 121, 186, 174, 195, 206,
                217, 15, 163, 244, 8, 113, 149, 38, 248, 215, 127, 73, 67,
            ],
            previous_block: [
                0, 0, 0, 0, 0, 2, 60, 60, 152, 89, 35, 223, 255, 89, 74, 130, 64, 234, 30, 151, 40,
                37, 10, 91, 84, 236, 23, 192, 158, 144, 91, 89,
            ],
            merkle_root_hash: [
                136, 122, 27, 116, 246, 94, 78, 137, 248, 236, 162, 104, 55, 210, 207, 205, 139,
                16, 92, 241, 228, 96, 167, 60, 7, 168, 155, 54, 29, 202, 64, 99,
            ],
            timestamp: 1384047529,
            n_bits: 486604799,
            nonce: 2442677017,
            txn_count: 2,
            txns: Vec::new(),
        };

        let tx1 = Tx {
            id: [
                163, 249, 79, 52, 224, 98, 202, 218, 50, 159, 58, 108, 242, 175, 222, 216, 208, 9,
                229, 154, 123, 49, 21, 38, 108, 225, 75, 56, 80, 72, 169, 157,
            ],
            version: 2,
            flag: 0,
            tx_in_count: 1,
            tx_in: vec![TxIn {
                previous_output: [
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 255, 255, 255, 255,
                ],
                script_length: 18,
                signature_script: vec![
                    3, 206, 247, 1, 5, 82, 126, 227, 169, 4, 0, 0, 0, 0, 14, 0, 0, 0,
                ],
                sequence: 4294967295,
            }],
            tx_out_count: 1,
            tx_out: vec![TxOut {
                value: 5000020000,
                pk_script_length: 25,
                pk_script: vec![
                    118, 169, 20, 195, 208, 147, 199, 86, 220, 79, 141, 216, 23, 181, 3, 198, 78,
                    203, 128, 39, 118, 33, 52, 136, 172,
                ],
            }],
            tx_witness: vec![],
            lock_time: 0,
        };

        let tx2 = Tx {
            id: [
                72, 132, 120, 96, 171, 214, 128, 219, 33, 157, 16, 192, 174, 101, 128, 69, 181,
                126, 185, 38, 161, 37, 17, 65, 92, 229, 106, 55, 131, 235, 133, 202,
            ],
            version: 2,
            flag: 0,
            tx_in_count: 7,
            tx_in: vec![
                TxIn {
                    previous_output: [
                        226, 186, 153, 202, 133, 201, 191, 217, 242, 20, 228, 81, 115, 195, 78,
                        140, 34, 173, 40, 212, 252, 161, 254, 59, 118, 110, 113, 203, 95, 194, 15,
                        31, 1, 0, 0, 0,
                    ],
                    script_length: 108,
                    signature_script: vec![
                        73, 48, 70, 2, 33, 0, 186, 116, 152, 184, 8, 221, 93, 28, 177, 136, 228,
                        20, 140, 153, 52, 84, 129, 0, 53, 247, 167, 210, 132, 236, 111, 18, 230,
                        22, 184, 157, 248, 68, 2, 33, 0, 228, 96, 137, 98, 40, 71, 186, 241, 162,
                        226, 222, 5, 21, 235, 53, 85, 46, 23, 162, 171, 237, 37, 108, 133, 186,
                        197, 192, 99, 165, 197, 28, 248, 1, 33, 3, 90, 249, 72, 176, 24, 177, 15,
                        244, 242, 166, 91, 179, 107, 118, 10, 227, 196, 58, 243, 29, 62, 197, 90,
                        196, 208, 42, 212, 228, 208, 29, 40, 68,
                    ],
                    sequence: 4294967295,
                },
                TxIn {
                    previous_output: [
                        87, 11, 145, 133, 166, 10, 91, 198, 242, 120, 93, 28, 141, 156, 172, 229,
                        167, 78, 2, 4, 36, 136, 23, 48, 7, 126, 253, 166, 170, 52, 117, 44, 0, 0,
                        0, 0,
                    ],
                    script_length: 106,
                    signature_script: vec![
                        71, 48, 68, 2, 32, 11, 179, 179, 252, 228, 62, 6, 213, 107, 68, 198, 255,
                        74, 179, 57, 210, 58, 128, 130, 231, 153, 227, 15, 162, 228, 59, 217, 16,
                        136, 205, 178, 163, 2, 32, 55, 79, 199, 51, 230, 226, 197, 138, 149, 59,
                        180, 46, 57, 174, 142, 38, 0, 166, 144, 155, 122, 34, 211, 127, 94, 94,
                        159, 188, 187, 36, 135, 41, 1, 33, 3, 90, 249, 72, 176, 24, 177, 15, 244,
                        242, 166, 91, 179, 107, 118, 10, 227, 196, 58, 243, 29, 62, 197, 90, 196,
                        208, 42, 212, 228, 208, 29, 40, 68,
                    ],
                    sequence: 4294967295,
                },
                TxIn {
                    previous_output: [
                        32, 147, 198, 194, 94, 20, 50, 221, 56, 255, 251, 30, 188, 120, 121, 159,
                        94, 103, 113, 8, 92, 223, 73, 28, 93, 246, 131, 233, 78, 185, 135, 74, 1,
                        0, 0, 0,
                    ],
                    script_length: 108,
                    signature_script: vec![
                        73, 48, 70, 2, 33, 0, 240, 181, 236, 200, 22, 39, 131, 90, 11, 7, 31, 63,
                        23, 150, 223, 11, 124, 117, 103, 71, 72, 58, 43, 126, 35, 203, 163, 3, 190,
                        61, 167, 15, 2, 33, 0, 166, 238, 85, 92, 155, 22, 40, 70, 122, 27, 72, 243,
                        230, 60, 179, 17, 255, 166, 147, 231, 13, 182, 206, 7, 9, 225, 196, 152,
                        28, 127, 205, 111, 1, 33, 3, 90, 249, 72, 176, 24, 177, 15, 244, 242, 166,
                        91, 179, 107, 118, 10, 227, 196, 58, 243, 29, 62, 197, 90, 196, 208, 42,
                        212, 228, 208, 29, 40, 68,
                    ],
                    sequence: 4294967295,
                },
                TxIn {
                    previous_output: [
                        199, 106, 135, 0, 185, 117, 124, 99, 211, 106, 15, 189, 198, 113, 214, 189,
                        25, 221, 198, 45, 62, 102, 201, 221, 198, 180, 230, 119, 168, 63, 170, 134,
                        1, 0, 0, 0,
                    ],
                    script_length: 107,
                    signature_script: vec![
                        72, 48, 69, 2, 33, 0, 148, 183, 111, 75, 123, 151, 140, 112, 229, 245, 34,
                        191, 169, 213, 114, 188, 201, 178, 174, 94, 42, 210, 246, 124, 146, 195,
                        195, 193, 14, 222, 13, 185, 2, 32, 104, 44, 162, 137, 124, 138, 201, 138,
                        17, 189, 255, 197, 139, 68, 191, 177, 133, 93, 174, 140, 68, 249, 106, 194,
                        21, 34, 44, 192, 250, 197, 96, 22, 1, 33, 3, 90, 249, 72, 176, 24, 177, 15,
                        244, 242, 166, 91, 179, 107, 118, 10, 227, 196, 58, 243, 29, 62, 197, 90,
                        196, 208, 42, 212, 228, 208, 29, 40, 68,
                    ],
                    sequence: 4294967295,
                },
                TxIn {
                    previous_output: [
                        113, 35, 225, 56, 130, 84, 0, 26, 180, 60, 21, 164, 153, 182, 156, 157, 52,
                        43, 137, 67, 175, 115, 113, 220, 238, 17, 250, 26, 185, 120, 104, 194, 1,
                        0, 0, 0,
                    ],
                    script_length: 107,
                    signature_script: vec![
                        72, 48, 69, 2, 33, 0, 249, 75, 138, 74, 35, 71, 68, 234, 176, 124, 125,
                        236, 105, 223, 106, 96, 243, 178, 247, 73, 116, 137, 249, 160, 249, 141,
                        194, 244, 245, 150, 142, 148, 2, 32, 75, 3, 136, 146, 62, 123, 235, 44, 96,
                        246, 251, 57, 182, 175, 38, 231, 171, 3, 92, 22, 239, 131, 242, 250, 189,
                        44, 162, 42, 103, 251, 124, 173, 1, 33, 3, 90, 249, 72, 176, 24, 177, 15,
                        244, 242, 166, 91, 179, 107, 118, 10, 227, 196, 58, 243, 29, 62, 197, 90,
                        196, 208, 42, 212, 228, 208, 29, 40, 68,
                    ],
                    sequence: 4294967295,
                },
                TxIn {
                    previous_output: [
                        211, 188, 83, 197, 125, 117, 74, 74, 184, 74, 214, 26, 114, 107, 75, 181,
                        136, 146, 27, 10, 10, 3, 171, 202, 169, 123, 208, 250, 240, 241, 114, 231,
                        1, 0, 0, 0,
                    ],
                    script_length: 108,
                    signature_script: vec![
                        73, 48, 70, 2, 33, 0, 224, 53, 209, 40, 121, 66, 156, 139, 156, 123, 122,
                        129, 244, 76, 38, 203, 29, 91, 123, 62, 128, 125, 105, 44, 218, 226, 166,
                        66, 199, 138, 236, 154, 2, 33, 0, 130, 49, 45, 12, 10, 54, 196, 88, 128,
                        232, 147, 104, 113, 85, 134, 124, 46, 236, 177, 197, 78, 248, 91, 139, 78,
                        139, 91, 97, 221, 88, 22, 89, 1, 33, 3, 90, 249, 72, 176, 24, 177, 15, 244,
                        242, 166, 91, 179, 107, 118, 10, 227, 196, 58, 243, 29, 62, 197, 90, 196,
                        208, 42, 212, 228, 208, 29, 40, 68,
                    ],
                    sequence: 4294967295,
                },
                TxIn {
                    previous_output: [
                        230, 17, 204, 216, 152, 113, 52, 184, 70, 87, 1, 249, 234, 17, 39, 102, 77,
                        17, 41, 48, 122, 17, 106, 157, 133, 63, 1, 153, 206, 101, 110, 234, 1, 0,
                        0, 0,
                    ],
                    script_length: 107,
                    signature_script: vec![
                        72, 48, 69, 2, 32, 63, 84, 31, 24, 79, 144, 242, 87, 201, 64, 157, 230,
                        108, 126, 186, 229, 5, 47, 242, 225, 171, 184, 51, 149, 222, 246, 79, 93,
                        65, 17, 39, 172, 2, 33, 0, 218, 47, 194, 209, 134, 43, 227, 58, 108, 15,
                        234, 194, 96, 163, 122, 140, 96, 42, 133, 56, 173, 205, 183, 242, 198, 29,
                        254, 85, 229, 71, 188, 221, 1, 33, 3, 90, 249, 72, 176, 24, 177, 15, 244,
                        242, 166, 91, 179, 107, 118, 10, 227, 196, 58, 243, 29, 62, 197, 90, 196,
                        208, 42, 212, 228, 208, 29, 40, 68,
                    ],
                    sequence: 4294967295,
                },
            ],
            tx_out_count: 9,
            tx_out: vec![
                TxOut {
                    value: 35000,
                    pk_script_length: 25,
                    pk_script: vec![
                        118, 169, 20, 229, 71, 99, 169, 199, 169, 16, 118, 146, 239, 40, 0, 135,
                        51, 87, 76, 201, 29, 91, 18, 136, 172,
                    ],
                },
                TxOut {
                    value: 6945000,
                    pk_script_length: 25,
                    pk_script: vec![
                        118, 169, 20, 83, 55, 48, 148, 170, 167, 46, 81, 250, 112, 50, 153, 245,
                        36, 27, 189, 6, 255, 98, 230, 136, 172,
                    ],
                },
                TxOut {
                    value: 615519,
                    pk_script_length: 25,
                    pk_script: vec![
                        118, 169, 20, 118, 81, 78, 44, 13, 38, 12, 152, 103, 31, 202, 163, 105, 61,
                        151, 14, 188, 44, 242, 57, 136, 172,
                    ],
                },
                TxOut {
                    value: 20000,
                    pk_script_length: 25,
                    pk_script: vec![
                        118, 169, 20, 254, 14, 239, 105, 52, 104, 7, 185, 183, 145, 48, 227, 146,
                        106, 193, 158, 34, 133, 84, 149, 136, 172,
                    ],
                },
                TxOut {
                    value: 426540,
                    pk_script_length: 25,
                    pk_script: vec![
                        118, 169, 20, 154, 196, 13, 68, 9, 142, 117, 87, 77, 157, 245, 147, 40,
                        251, 240, 78, 65, 221, 125, 46, 136, 172,
                    ],
                },
                TxOut {
                    value: 680033,
                    pk_script_length: 25,
                    pk_script: vec![
                        118, 169, 20, 55, 156, 16, 203, 12, 73, 124, 201, 36, 154, 42, 134, 84,
                        163, 241, 155, 233, 217, 93, 134, 136, 172,
                    ],
                },
                TxOut {
                    value: 20000,
                    pk_script_length: 25,
                    pk_script: vec![
                        118, 169, 20, 205, 186, 89, 206, 86, 230, 187, 91, 139, 71, 209, 78, 66,
                        173, 7, 161, 199, 118, 29, 63, 136, 172,
                    ],
                },
                TxOut {
                    value: 645634,
                    pk_script_length: 25,
                    pk_script: vec![
                        118, 169, 20, 10, 74, 129, 168, 231, 144, 184, 206, 179, 2, 189, 63, 34,
                        252, 125, 202, 254, 161, 148, 12, 136, 172,
                    ],
                },
                TxOut {
                    value: 669645,
                    pk_script_length: 25,
                    pk_script: vec![
                        118, 169, 20, 122, 228, 120, 18, 59, 150, 13, 46, 233, 18, 104, 91, 129,
                        152, 169, 8, 100, 187, 100, 137, 136, 172,
                    ],
                },
            ],
            tx_witness: vec![],
            lock_time: 0,
        };

        block.txns = vec![tx1.clone(), tx2];

        assert_eq!(block.proof_of_inclusion(tx1), true);
    }

    #[test]
    fn test_generates_origin_block_merkle() {
        let mut block = Block {
            version: 1,
            hash: [
                0, 0, 0, 0, 9, 51, 234, 1, 173, 14, 33, 132, 32, 151, 121, 186, 174, 195, 206, 217,
                15, 163, 244, 8, 113, 149, 38, 248, 215, 127, 73, 67,
            ],
            previous_block: [
                0, 0, 0, 0, 9, 51, 234, 1, 173, 14, 233, 132, 32, 151, 121, 186, 174, 195, 206,
                217, 15, 163, 244, 8, 113, 149, 38, 248, 215, 127, 73, 67,
            ],
            merkle_root_hash: [
                240, 49, 95, 252, 56, 112, 157, 112, 173, 86, 71, 226, 32, 72, 53, 141, 211, 116,
                95, 60, 227, 135, 66, 35, 200, 10, 124, 146, 250, 176, 200, 186,
            ],
            timestamp: 1296688928,
            n_bits: 486604799,
            nonce: 1924588547,
            txn_count: 1,
            txns: vec![],
        };

        let tx = Tx {
            id: [
                240, 49, 95, 252, 56, 112, 157, 112, 173, 86, 71, 226, 32, 72, 53, 141, 211, 116,
                95, 60, 227, 135, 66, 35, 200, 10, 124, 146, 250, 176, 200, 186,
            ],
            version: 1,
            flag: 0,
            tx_in_count: 1, // varint
            tx_in: vec![TxIn {
                previous_output: [
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 255, 255, 255, 255,
                ],
                script_length: 14, // varint
                signature_script: vec![4, 32, 231, 73, 77, 1, 127, 6, 47, 80, 50, 83, 72, 47],
                sequence: 4294967295,
            }],
            tx_out_count: 1, // varint
            tx_out: vec![TxOut {
                value: 5000000000,
                pk_script_length: 35, // varint
                pk_script: vec![
                    33, 2, 26, 234, 242, 248, 99, 138, 18, 154, 49, 86, 251, 231, 229, 239, 99, 82,
                    38, 176, 186, 253, 73, 95, 240, 58, 254, 44, 132, 61, 126, 58, 75, 81, 172,
                ],
            }],
            tx_witness: vec![],
            lock_time: 0,
        };

        block.txns = vec![tx];

        let expected_merkle_root = [
            240, 49, 95, 252, 56, 112, 157, 112, 173, 86, 71, 226, 32, 72, 53, 141, 211, 116, 95,
            60, 227, 135, 66, 35, 200, 10, 124, 146, 250, 176, 200, 186,
        ];

        assert_eq!(block.get_merkle_tree_root().unwrap(), expected_merkle_root);
    }

    #[test]
    fn test_generates_merkle_root_on_block_with_many_transaction() {
        let mut block = Block {
            version: 2,
            hash: [
                0, 0, 0, 0, 0, 2, 60, 60, 152, 89, 35, 223, 255, 89, 74, 130, 64, 234, 30, 151, 40,
                37, 10, 91, 84, 236, 23, 192, 158, 144, 91, 89,
            ],
            previous_block: [
                0, 0, 0, 0, 0, 2, 60, 60, 152, 89, 35, 223, 255, 89, 74, 130, 64, 234, 30, 151, 40,
                37, 10, 91, 84, 236, 23, 192, 158, 144, 91, 89,
            ],
            merkle_root_hash: [
                136, 122, 27, 116, 246, 94, 78, 137, 248, 236, 162, 104, 55, 210, 207, 205, 139,
                16, 92, 241, 228, 96, 167, 60, 7, 168, 155, 54, 29, 202, 64, 99,
            ],
            timestamp: 1384047529,
            n_bits: 486604799,
            nonce: 2442677017,
            txn_count: 2,
            txns: vec![],
        };

        let tx1 = Tx {
            id: [
                163, 249, 79, 52, 224, 98, 202, 218, 50, 159, 58, 108, 242, 175, 222, 216, 208, 9,
                229, 154, 123, 49, 21, 38, 108, 225, 75, 56, 80, 72, 169, 157,
            ],
            version: 2,
            flag: 0,
            tx_in_count: 1,
            tx_in: vec![TxIn {
                previous_output: [
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 255, 255, 255, 255,
                ],
                script_length: 18,
                signature_script: vec![
                    3, 206, 247, 1, 5, 82, 126, 227, 169, 4, 0, 0, 0, 0, 14, 0, 0, 0,
                ],
                sequence: 4294967295,
            }],
            tx_out_count: 1,
            tx_out: vec![TxOut {
                value: 5000020000,
                pk_script_length: 25,
                pk_script: vec![
                    118, 169, 20, 195, 208, 147, 199, 86, 220, 79, 141, 216, 23, 181, 3, 198, 78,
                    203, 128, 39, 118, 33, 52, 136, 172,
                ],
            }],
            tx_witness: vec![],
            lock_time: 0,
        };

        let tx2 = Tx {
            id: [
                72, 132, 120, 96, 171, 214, 128, 219, 33, 157, 16, 192, 174, 101, 128, 69, 181,
                126, 185, 38, 161, 37, 17, 65, 92, 229, 106, 55, 131, 235, 133, 202,
            ],
            version: 2,
            flag: 0,
            tx_in_count: 7,
            tx_in: vec![
                TxIn {
                    previous_output: [
                        226, 186, 153, 202, 133, 201, 191, 217, 242, 20, 228, 81, 115, 195, 78,
                        140, 34, 173, 40, 212, 252, 161, 254, 59, 118, 110, 113, 203, 95, 194, 15,
                        31, 1, 0, 0, 0,
                    ],
                    script_length: 108,
                    signature_script: vec![
                        73, 48, 70, 2, 33, 0, 186, 116, 152, 184, 8, 221, 93, 28, 177, 136, 228,
                        20, 140, 153, 52, 84, 129, 0, 53, 247, 167, 210, 132, 236, 111, 18, 230,
                        22, 184, 157, 248, 68, 2, 33, 0, 228, 96, 137, 98, 40, 71, 186, 241, 162,
                        226, 222, 5, 21, 235, 53, 85, 46, 23, 162, 171, 237, 37, 108, 133, 186,
                        197, 192, 99, 165, 197, 28, 248, 1, 33, 3, 90, 249, 72, 176, 24, 177, 15,
                        244, 242, 166, 91, 179, 107, 118, 10, 227, 196, 58, 243, 29, 62, 197, 90,
                        196, 208, 42, 212, 228, 208, 29, 40, 68,
                    ],
                    sequence: 4294967295,
                },
                TxIn {
                    previous_output: [
                        87, 11, 145, 133, 166, 10, 91, 198, 242, 120, 93, 28, 141, 156, 172, 229,
                        167, 78, 2, 4, 36, 136, 23, 48, 7, 126, 253, 166, 170, 52, 117, 44, 0, 0,
                        0, 0,
                    ],
                    script_length: 106,
                    signature_script: vec![
                        71, 48, 68, 2, 32, 11, 179, 179, 252, 228, 62, 6, 213, 107, 68, 198, 255,
                        74, 179, 57, 210, 58, 128, 130, 231, 153, 227, 15, 162, 228, 59, 217, 16,
                        136, 205, 178, 163, 2, 32, 55, 79, 199, 51, 230, 226, 197, 138, 149, 59,
                        180, 46, 57, 174, 142, 38, 0, 166, 144, 155, 122, 34, 211, 127, 94, 94,
                        159, 188, 187, 36, 135, 41, 1, 33, 3, 90, 249, 72, 176, 24, 177, 15, 244,
                        242, 166, 91, 179, 107, 118, 10, 227, 196, 58, 243, 29, 62, 197, 90, 196,
                        208, 42, 212, 228, 208, 29, 40, 68,
                    ],
                    sequence: 4294967295,
                },
                TxIn {
                    previous_output: [
                        32, 147, 198, 194, 94, 20, 50, 221, 56, 255, 251, 30, 188, 120, 121, 159,
                        94, 103, 113, 8, 92, 223, 73, 28, 93, 246, 131, 233, 78, 185, 135, 74, 1,
                        0, 0, 0,
                    ],
                    script_length: 108,
                    signature_script: vec![
                        73, 48, 70, 2, 33, 0, 240, 181, 236, 200, 22, 39, 131, 90, 11, 7, 31, 63,
                        23, 150, 223, 11, 124, 117, 103, 71, 72, 58, 43, 126, 35, 203, 163, 3, 190,
                        61, 167, 15, 2, 33, 0, 166, 238, 85, 92, 155, 22, 40, 70, 122, 27, 72, 243,
                        230, 60, 179, 17, 255, 166, 147, 231, 13, 182, 206, 7, 9, 225, 196, 152,
                        28, 127, 205, 111, 1, 33, 3, 90, 249, 72, 176, 24, 177, 15, 244, 242, 166,
                        91, 179, 107, 118, 10, 227, 196, 58, 243, 29, 62, 197, 90, 196, 208, 42,
                        212, 228, 208, 29, 40, 68,
                    ],
                    sequence: 4294967295,
                },
                TxIn {
                    previous_output: [
                        199, 106, 135, 0, 185, 117, 124, 99, 211, 106, 15, 189, 198, 113, 214, 189,
                        25, 221, 198, 45, 62, 102, 201, 221, 198, 180, 230, 119, 168, 63, 170, 134,
                        1, 0, 0, 0,
                    ],
                    script_length: 107,
                    signature_script: vec![
                        72, 48, 69, 2, 33, 0, 148, 183, 111, 75, 123, 151, 140, 112, 229, 245, 34,
                        191, 169, 213, 114, 188, 201, 178, 174, 94, 42, 210, 246, 124, 146, 195,
                        195, 193, 14, 222, 13, 185, 2, 32, 104, 44, 162, 137, 124, 138, 201, 138,
                        17, 189, 255, 197, 139, 68, 191, 177, 133, 93, 174, 140, 68, 249, 106, 194,
                        21, 34, 44, 192, 250, 197, 96, 22, 1, 33, 3, 90, 249, 72, 176, 24, 177, 15,
                        244, 242, 166, 91, 179, 107, 118, 10, 227, 196, 58, 243, 29, 62, 197, 90,
                        196, 208, 42, 212, 228, 208, 29, 40, 68,
                    ],
                    sequence: 4294967295,
                },
                TxIn {
                    previous_output: [
                        113, 35, 225, 56, 130, 84, 0, 26, 180, 60, 21, 164, 153, 182, 156, 157, 52,
                        43, 137, 67, 175, 115, 113, 220, 238, 17, 250, 26, 185, 120, 104, 194, 1,
                        0, 0, 0,
                    ],
                    script_length: 107,
                    signature_script: vec![
                        72, 48, 69, 2, 33, 0, 249, 75, 138, 74, 35, 71, 68, 234, 176, 124, 125,
                        236, 105, 223, 106, 96, 243, 178, 247, 73, 116, 137, 249, 160, 249, 141,
                        194, 244, 245, 150, 142, 148, 2, 32, 75, 3, 136, 146, 62, 123, 235, 44, 96,
                        246, 251, 57, 182, 175, 38, 231, 171, 3, 92, 22, 239, 131, 242, 250, 189,
                        44, 162, 42, 103, 251, 124, 173, 1, 33, 3, 90, 249, 72, 176, 24, 177, 15,
                        244, 242, 166, 91, 179, 107, 118, 10, 227, 196, 58, 243, 29, 62, 197, 90,
                        196, 208, 42, 212, 228, 208, 29, 40, 68,
                    ],
                    sequence: 4294967295,
                },
                TxIn {
                    previous_output: [
                        211, 188, 83, 197, 125, 117, 74, 74, 184, 74, 214, 26, 114, 107, 75, 181,
                        136, 146, 27, 10, 10, 3, 171, 202, 169, 123, 208, 250, 240, 241, 114, 231,
                        1, 0, 0, 0,
                    ],
                    script_length: 108,
                    signature_script: vec![
                        73, 48, 70, 2, 33, 0, 224, 53, 209, 40, 121, 66, 156, 139, 156, 123, 122,
                        129, 244, 76, 38, 203, 29, 91, 123, 62, 128, 125, 105, 44, 218, 226, 166,
                        66, 199, 138, 236, 154, 2, 33, 0, 130, 49, 45, 12, 10, 54, 196, 88, 128,
                        232, 147, 104, 113, 85, 134, 124, 46, 236, 177, 197, 78, 248, 91, 139, 78,
                        139, 91, 97, 221, 88, 22, 89, 1, 33, 3, 90, 249, 72, 176, 24, 177, 15, 244,
                        242, 166, 91, 179, 107, 118, 10, 227, 196, 58, 243, 29, 62, 197, 90, 196,
                        208, 42, 212, 228, 208, 29, 40, 68,
                    ],
                    sequence: 4294967295,
                },
                TxIn {
                    previous_output: [
                        230, 17, 204, 216, 152, 113, 52, 184, 70, 87, 1, 249, 234, 17, 39, 102, 77,
                        17, 41, 48, 122, 17, 106, 157, 133, 63, 1, 153, 206, 101, 110, 234, 1, 0,
                        0, 0,
                    ],
                    script_length: 107,
                    signature_script: vec![
                        72, 48, 69, 2, 32, 63, 84, 31, 24, 79, 144, 242, 87, 201, 64, 157, 230,
                        108, 126, 186, 229, 5, 47, 242, 225, 171, 184, 51, 149, 222, 246, 79, 93,
                        65, 17, 39, 172, 2, 33, 0, 218, 47, 194, 209, 134, 43, 227, 58, 108, 15,
                        234, 194, 96, 163, 122, 140, 96, 42, 133, 56, 173, 205, 183, 242, 198, 29,
                        254, 85, 229, 71, 188, 221, 1, 33, 3, 90, 249, 72, 176, 24, 177, 15, 244,
                        242, 166, 91, 179, 107, 118, 10, 227, 196, 58, 243, 29, 62, 197, 90, 196,
                        208, 42, 212, 228, 208, 29, 40, 68,
                    ],
                    sequence: 4294967295,
                },
            ],
            tx_out_count: 9,
            tx_out: vec![
                TxOut {
                    value: 35000,
                    pk_script_length: 25,
                    pk_script: vec![
                        118, 169, 20, 229, 71, 99, 169, 199, 169, 16, 118, 146, 239, 40, 0, 135,
                        51, 87, 76, 201, 29, 91, 18, 136, 172,
                    ],
                },
                TxOut {
                    value: 6945000,
                    pk_script_length: 25,
                    pk_script: vec![
                        118, 169, 20, 83, 55, 48, 148, 170, 167, 46, 81, 250, 112, 50, 153, 245,
                        36, 27, 189, 6, 255, 98, 230, 136, 172,
                    ],
                },
                TxOut {
                    value: 615519,
                    pk_script_length: 25,
                    pk_script: vec![
                        118, 169, 20, 118, 81, 78, 44, 13, 38, 12, 152, 103, 31, 202, 163, 105, 61,
                        151, 14, 188, 44, 242, 57, 136, 172,
                    ],
                },
                TxOut {
                    value: 20000,
                    pk_script_length: 25,
                    pk_script: vec![
                        118, 169, 20, 254, 14, 239, 105, 52, 104, 7, 185, 183, 145, 48, 227, 146,
                        106, 193, 158, 34, 133, 84, 149, 136, 172,
                    ],
                },
                TxOut {
                    value: 426540,
                    pk_script_length: 25,
                    pk_script: vec![
                        118, 169, 20, 154, 196, 13, 68, 9, 142, 117, 87, 77, 157, 245, 147, 40,
                        251, 240, 78, 65, 221, 125, 46, 136, 172,
                    ],
                },
                TxOut {
                    value: 680033,
                    pk_script_length: 25,
                    pk_script: vec![
                        118, 169, 20, 55, 156, 16, 203, 12, 73, 124, 201, 36, 154, 42, 134, 84,
                        163, 241, 155, 233, 217, 93, 134, 136, 172,
                    ],
                },
                TxOut {
                    value: 20000,
                    pk_script_length: 25,
                    pk_script: vec![
                        118, 169, 20, 205, 186, 89, 206, 86, 230, 187, 91, 139, 71, 209, 78, 66,
                        173, 7, 161, 199, 118, 29, 63, 136, 172,
                    ],
                },
                TxOut {
                    value: 645634,
                    pk_script_length: 25,
                    pk_script: vec![
                        118, 169, 20, 10, 74, 129, 168, 231, 144, 184, 206, 179, 2, 189, 63, 34,
                        252, 125, 202, 254, 161, 148, 12, 136, 172,
                    ],
                },
                TxOut {
                    value: 669645,
                    pk_script_length: 25,
                    pk_script: vec![
                        118, 169, 20, 122, 228, 120, 18, 59, 150, 13, 46, 233, 18, 104, 91, 129,
                        152, 169, 8, 100, 187, 100, 137, 136, 172,
                    ],
                },
            ],
            tx_witness: vec![],
            lock_time: 0,
        };

        block.txns = vec![tx1, tx2];

        let expected_merkle_root = [
            136, 122, 27, 116, 246, 94, 78, 137, 248, 236, 162, 104, 55, 210, 207, 205, 139, 16,
            92, 241, 228, 96, 167, 60, 7, 168, 155, 54, 29, 202, 64, 99,
        ];
        assert_eq!(block.get_merkle_tree_root().unwrap(), expected_merkle_root);
    }

    // #[test]

    // fn test_validate_proof_of_work(){
    //     let block = Block::new(
    //         1,
    //         [
    //             0, 0, 0, 0, 9, 51, 234, 1, 173, 14, 233, 132, 32, 151, 121, 186, 174, 195, 206,
    //             217, 15, 163, 244, 8, 113, 149, 38, 248, 215, 127, 73, 67,
    //         ],
    //         [
    //             0, 0, 0, 0, 9, 51, 234, 1, 173, 14, 233, 132, 32, 151, 121, 186, 174, 195, 206,
    //             217, 15, 163, 244, 8, 113, 149, 38, 248, 215, 127, 73, 67,
    //         ],
    //         [
    //             240, 49, 95, 252, 56, 112, 157, 112, 173, 86, 71, 226, 32, 72, 53, 141, 211, 116,
    //             95, 60, 227, 135, 66, 35, 200, 10, 124, 146, 250, 176, 200, 186,
    //         ],
    //         1296688928,
    //         486604799,
    //         1924588547,
    //         1,
    //     );

    //     assert_eq!(block.validate_pow(), true);
    // }
}
