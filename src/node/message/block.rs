use crate::error::Error;
use bitcoin_hashes::{sha256, Hash, HashEngine};
use super::tx::{Tx, TxIn, TxOut};
use super::MessagePayload;
use crate::node::message::{tx::decode_tx, merkle_tree};
use crate::utils::*;
use std::os::linux::raw;
use std::vec;
use super::merkle_tree::MerkleTree;

use std::{
    fs::{File, OpenOptions},
    io::Read,
    io::Write,
};

use super::get_headers::decode_header;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Block {
    version: u32,
    previous_block: [u8; 32],
    merkle_root_hash: [u8; 32],
    timestamp: u32,
    n_bits: u32,
    nonce: u32,
    pub txn_count: u8, // TODO Variable size
    txns: Vec<Tx>,     // TODO Variable size
}

impl Block {
    pub fn new(
        version: u32,
        previous_block: [u8; 32],
        merkle_root_hash: [u8; 32],
        timestamp: u32,
        n_bits: u32,
        nonce: u32,
        txn_count: u8,
    ) -> Self {
        let txns: Vec<Tx> = Vec::new();

        Self {
            version,
            previous_block,
            merkle_root_hash,
            timestamp,
            n_bits,
            nonce,
            txn_count,
            txns,
        }
    }

    fn add_txns(&mut self, txns:Vec<Tx> ) {
        //TODO if (txns.len()!=self.txn_count as usize){
        //    Error
        //}
        self.txns = txns;
    }

    fn init_merkle_tree(&self) -> MerkleTree{
        let raw_txs = self.txns.iter().map(|tx| tx.encode()).collect::<Vec<Vec<u8>>>();
        let raw_txs_slice = raw_txs.iter().map(|tx| tx.as_slice()).collect::<Vec<&[u8]>>();

        let mut merkle_tree = MerkleTree::new();
        
        merkle_tree.generate_merkle_tree(raw_txs_slice);

        merkle_tree
    }

    pub fn get_merkle_tree_root(&self)-> Result<sha256::Hash, Error>{

         let merkle_tree = self.init_merkle_tree();

        merkle_tree.get_root()
    }

    //let mut merkle_tree = MerkleTree::new();
    //merkle_tree.generate_merkle_tree(raw_trxs);

    pub fn proof_of_inclusion(&self, tx_req: Tx) -> bool {

        let merkle_tree = self.init_merkle_tree();

        merkle_tree.proof_of_inclusion(tx_req.encode().as_slice())
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
        buffer[offset..offset + 1].copy_from_slice(&self.txn_count.to_le_bytes());
        offset += 1; // Es variable

        // Encode txns, for complete initial download is zero.
        // buffer[offset..offset + 1].copy_from_slice(&[0]);
    }

    pub fn get_prev(&self) -> [u8; 32] {
        self.previous_block
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
    let mut block_header = decode_internal_block(&buffer).unwrap();
    let mut transactions = Vec::new();


    let tnx_count = read_varint(&mut &buffer[80..]).unwrap() as u8;
    let mut offset = 80 + get_offset(&buffer[80..]);


    for _ in 0..tnx_count {
        if let Some(tx) = decode_tx(&buffer, &mut offset) {
            transactions.push(tx);
        } else {
            return Err("Failed to decode transaction".to_string());
        }
    }

    block_header.txn_count = tnx_count;
    block_header.txns = transactions;

    Ok(MessagePayload::Block(block_header))
}

pub fn decode_internal_block(buffer: &[u8]) -> Option<Block> {
    let version = read_u32_le(&buffer, 0);

    let mut previous_block_header_hash: [u8; 32] = [0u8; 32];
    copy_bytes_to_array(&buffer[4..36], &mut previous_block_header_hash);
    previous_block_header_hash.reverse();

    let mut merkle_root_hash: [u8; 32] = [0u8; 32];
    copy_bytes_to_array(&buffer[36..68], &mut merkle_root_hash);
    merkle_root_hash.reverse();

    let timestamp = read_le(&buffer[68..72]) as u32;
    let n_bits = read_le(&buffer[72..76]) as u32;
    let nonce = read_le(&buffer[76..80]) as u32;

    Some(Block::new(
        version,
        previous_block_header_hash,
        merkle_root_hash,
        timestamp,
        n_bits,
        nonce,
        0,
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
            1,
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
                1,
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
                1,
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

    #[test]
    fn test_proof_of_inclution(){

        let mut block = Block::new(
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
            3,
        );

        let tx_1 = Tx {
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
            tx_out: vec![
                TxOut {
                    value: 100_000_000,
                    pk_script_length: 0, // varint
                    pk_script: vec![],
                },
            ],
            tx_witness: vec![],
            lock_time: 0,
        };

        let tx_2 = Tx {
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
            tx_out: vec![
                TxOut {
                    value: 100_000_000,
                    pk_script_length: 0, // varint
                    pk_script: vec![],
                },
            ],
            tx_witness: vec![],
            lock_time: 0,
        };

        let tx_3 = Tx {
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
            tx_out: vec![
                TxOut {
                    value: 100_000_000,
                    pk_script_length: 0, // varint
                    pk_script: vec![],
                },
            ],
            tx_witness: vec![],
            lock_time: 0,
        };

        let expected_tex = tx_1.clone();
        let txns = vec![tx_1,tx_2,tx_3];

        block.add_txns(txns);
    
        assert_eq!(block.proof_of_inclusion(expected_tex), true);

    }
    
    #[test]
    fn test_proof_of_inclution_doesnt_have_invalid_tx(){

        let mut block = Block::new(
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
            3,
        );

        let tx_1 = Tx {
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
            tx_out: vec![
                TxOut {
                    value: 100_000_000,
                    pk_script_length: 0, // varint
                    pk_script: vec![],
                },
            ],
            tx_witness: vec![],
            lock_time: 0,
        };

        let tx_2 = Tx {
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
            tx_out: vec![
                TxOut {
                    value: 100_000_000,
                    pk_script_length: 0, // varint
                    pk_script: vec![],
                },
            ],
            tx_witness: vec![],
            lock_time: 0,
        };

        let tx_3 = Tx {
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
            tx_out: vec![
                TxOut {
                    value: 100_000_000,
                    pk_script_length: 0, // varint
                    pk_script: vec![],
                },
            ],
            tx_witness: vec![],
            lock_time: 0,
        };

        let not_expected_tnx=Tx {
            version: 1,
            flag: 0,
            tx_in_count: 1, // varint
            tx_in: vec![
                TxIn {
                    previous_output: [0; 36],
                    script_length: 0, // varint
                    signature_script: vec![],
                    sequence: 0,
                },
            ],
            tx_out_count: 1, // varint
            tx_out: vec![
                TxOut {
                    value: 100_000_000,
                    pk_script_length: 0, // varint
                    pk_script: vec![],
                },
            ],
            tx_witness: vec![],
            lock_time: 0,
        };

        let txns = vec![tx_1,tx_2,tx_3];

        block.add_txns(txns);
    
        assert_eq!( block.proof_of_inclusion(not_expected_tnx), false);

    }

    #[test]
    fn test_prof_validation_with_origin_block(){

        let mut block = Block::new(
            
            1, 
            [0, 0, 0, 0, 9, 51, 234, 1, 173, 14, 233, 132, 32, 151, 121, 186, 
            174, 195, 206, 217, 15, 163, 244, 8, 113, 149, 38, 248, 215, 127, 73, 67], 
            [240, 49, 95, 252, 56, 112, 157, 112, 173, 86, 71, 226, 32, 72, 53,
             141, 211, 116, 95, 60, 227, 135, 66, 35, 200, 10, 124, 146, 250, 176, 200, 186], 
             1296688928,
             486604799,
             1924588547,
             1,
        );

        let tx = Tx {
            version: 1,
            flag: 0,
            tx_in_count: 1, // varint
            tx_in: vec![
                TxIn {
                    previous_output: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255],
                    script_length: 14, // varint
                    signature_script: vec![4, 32, 231, 73, 77, 1, 127, 6, 47, 80, 50, 83, 72, 47],
                    sequence: 4294967295,
                },
            ],
            tx_out_count: 1, // varint
            tx_out: vec![
                TxOut {
                    value: 5000000000,
                    pk_script_length: 35, // varint
                    pk_script: vec![33, 2, 26, 234, 242, 248, 99, 138, 18, 154, 49, 86, 251, 231, 229, 239, 99, 82, 38, 176, 186, 253, 73, 95, 240, 58, 254, 44, 132, 61, 126, 58, 75, 81, 172],
                },
            ],
            tx_witness: vec![],
            lock_time: 0,
        }; 

        let expected_tex = tx.clone();
        let txns = vec![tx];

        block.add_txns(txns);
    
        assert_eq!(block.proof_of_inclusion(expected_tex), true);
    }

    #[test]
    fn test_generates_origin_block_merkle(){

        let mut block = Block::new(
            
            1, 
            [0, 0, 0, 0, 9, 51, 234, 1, 173, 14, 233, 132, 32, 151, 121, 186, 
            174, 195, 206, 217, 15, 163, 244, 8, 113, 149, 38, 248, 215, 127, 73, 67], 
            [240, 49, 95, 252, 56, 112, 157, 112, 173, 86, 71, 226, 32, 72, 53,
             141, 211, 116, 95, 60, 227, 135, 66, 35, 200, 10, 124, 146, 250, 176, 200, 186], 
             1296688928,
             486604799,
             1924588547,
             1,
        );

        let tx = Tx {
            version: 1,
            flag: 0,
            tx_in_count: 1, // varint
            tx_in: vec![
                TxIn {
                    previous_output: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255],
                    script_length: 14, // varint
                    signature_script: vec![4, 32, 231, 73, 77, 1, 127, 6, 47, 80, 50, 83, 72, 47],
                    sequence: 4294967295,
                },
            ],
            tx_out_count: 1, // varint
            tx_out: vec![
                TxOut {
                    value: 5000000000,
                    pk_script_length: 35, // varint
                    pk_script: vec![33, 2, 26, 234, 242, 248, 99, 138, 18, 154, 49, 86, 251, 231, 229, 239, 99, 82, 38, 176, 186, 253, 73, 95, 240, 58, 254, 44, 132, 61, 126, 58, 75, 81, 172],
                },
            ],
            tx_witness: vec![],
            lock_time: 0,
        }; 

        block.add_txns(vec![tx]);

        let expected_merkle_root = [240, 49, 95, 252, 56, 112, 157, 112, 173, 86, 71, 226, 32, 72, 53,
        141, 211, 116, 95, 60, 227, 135, 66, 35, 200, 10, 124, 146, 250, 176, 200, 186];
        
        println!("{:?}",block.get_merkle_tree_root().unwrap().to_string());

    }

    
}
