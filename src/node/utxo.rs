use bitcoin_hashes::{hash160, Hash};

use crate::net::message::tx::Tx;
use crate::utils::read_be;
use std::collections::HashMap;
use std::mem;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Utxo {
    pub transaction_id: [u8; 32],
    pub output_index: u32,
    pub value: u64,
}

impl Utxo {
    pub fn size(&self) -> usize {
        let mut size = 0;

        size += 32;
        size += mem::size_of::<u32>();
        size += mem::size_of::<u64>();

        size
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::new();

        encoded.extend(&self.transaction_id);
        encoded.extend(&self.output_index.to_be_bytes());
        encoded.extend(&self.value.to_be_bytes());

        encoded
    }
}

pub fn decode(buffer: &[u8]) -> Option<Utxo> {
    if buffer.len() != 44 {
        return None;
    }

    let mut transaction_id = [0u8; 32];
    transaction_id.copy_from_slice(&buffer[0..32]);

    let output_index = read_be(&buffer[32..36]) as u32;

    let value = read_be(&buffer[36..44]) as u64;

    Some(Utxo {
        transaction_id,
        output_index,
        value,
    })
}

// Get UTXOs of a specific address
pub fn get_utxos_by_address(
    utxo_set: &HashMap<[u8; 20], Vec<Utxo>>,
    pk_hash: [u8; 20],
) -> Vec<Utxo> {
    match utxo_set.get(&pk_hash) {
        Some(utxos) => utxos.clone(),
        None => Vec::new(),
    }
}

// Deletes the outpoints from the UTXO set that each Tx_in points to
pub fn update_utxo_set(utxo_set: &mut HashMap<[u8; 20], Vec<Utxo>>, tx: &Tx) {
    for tx_in in &tx.tx_in {
        let mut sig_script_inv = tx_in.signature_script.clone();
        sig_script_inv.reverse();

        // This is a coinbase or an invalid sigScript.
        if tx_in.script_length < 33 {
            return;
        }

        // Public Key
        let mut sec_pk = sig_script_inv[0..33].to_vec();
        sec_pk.reverse();

        let pk_hash = hash160::Hash::hash(&sec_pk).to_byte_array();

        let mut hash_tx = tx_in.previous_output.hash;
        hash_tx.reverse(); //this is because we didnt reverse the hash in decode_internal_tx
        
        let index = tx_in.previous_output.index;

        if let Some(utxos) = utxo_set.get(&pk_hash) {
            let mut utxos = utxos.clone();

            for i in 0..utxos.len() {
                if utxos[i].transaction_id == hash_tx && utxos[i].output_index == index {
                    utxos.remove(i);
                    break;
                }
            }

            // Updates the new list of UTXOs for the address
            utxo_set.insert(pk_hash, utxos);
        }
    }
}

// Add UTXO to each UTXO
pub fn generate_utxos(utxo_set: &mut HashMap<[u8; 20], Vec<Utxo>>, tx: &Tx) {
    
    for (index, tx_out) in tx.tx_out.iter().enumerate() {
        //  Creo un outpoint a partir de la TxOut
        let utxo_new: Utxo = Utxo {
            transaction_id: tx.id,
            output_index: index as u32,
            value: tx_out.value,
        };

        let pk_script = &tx_out.pk_script;

        // From pk_script obtain the address and encode it into base58Check
        if pk_script.len() < 23 {
            continue;
        }

        let mut pk_hash = [0u8; 20];
        pk_hash.copy_from_slice(&pk_script[3..23]);
        let mut is_duplicated = false;

        // append to address this UTXO
        let utxos_updated: Vec<Utxo> = match utxo_set.get(&pk_hash) {
            Some(utxos) => {
                let mut utxos_return: Vec<Utxo> = utxos.clone();
                for utxo_curr in utxos {
                    if utxo_curr == &utxo_new {
                        is_duplicated = true;
                        break;
                    }
                }
                if !is_duplicated {
                    utxos_return.push(utxo_new);
                }
                utxos_return
            }
            None => {
                vec![utxo_new]
            }
        };

        utxo_set.insert(pk_hash, utxos_updated);
    }
}

#[cfg(test)]
mod tests {
    use crate::net::message::tx::{OutPoint, TxIn, TxOut};

    use super::*;

    #[test]
    fn test_generate_utxos_and_update_utxo_set() {
        let pk = [
            100, 227, 171, 27, 188, 160, 210, 116, 110, 81, 97, 65, 97, 169, 21, 128, 49, 207, 184,
            237,
        ];

        // Create an empty utxo_set
        let mut utxo_set = HashMap::new();
        assert!(utxo_set.len() == 0);

        let mut id = [
            188, 230, 109, 89, 92, 255, 134, 80, 172, 55, 252, 24, 23, 39, 241, 197, 198, 168,
            115, 20, 9, 105, 75, 41, 112, 143, 54, 138, 18, 137, 204, 123,
        ];

        id.reverse();

        // Create a real transaction
        let tx_1 = Tx {
            id: id,
            version: 2,
            lock_time: 2438543,
            flag: 0,
            tx_witness: vec![],
            tx_in_count: 1,
            tx_in: vec![TxIn {
                previous_output: OutPoint {
                    hash: [
                        59, 232, 99, 171, 169, 82, 175, 162, 183, 23, 60, 141, 197, 86, 144, 123,
                        180, 223, 116, 168, 232, 149, 239, 195, 167, 23, 23, 52, 241, 117, 172,
                        194,
                    ],
                    index: 1,
                },
                script_length: 18,
                signature_script: vec![
                    3, 206, 247, 1, 5, 82, 126, 227, 169, 4, 0, 0, 0, 0, 14, 0, 0, 0,
                ],
                sequence: 4294967295,
            }],
            tx_out_count: 1,
            tx_out: vec![TxOut {
                value: 1302208,
                pk_script_length: 25,
                pk_script: vec![
                    118, 169, 20, 100, 227, 171, 27, 188, 160, 210, 116, 110, 81, 97, 65, 97, 169,
                    21, 128, 49, 207, 184, 237, 136, 172,
                ],
            }],
        };

        // Generate UTXO set from TxOuts of tx_1
        generate_utxos(&mut utxo_set, &tx_1);
        assert!(utxo_set.len() == 1);

        // Update UTXOs set from TxIn of tx_1
        update_utxo_set(&mut utxo_set, &tx_1);
        let mut utxos_pk = utxo_set.get(&pk).unwrap().clone();

        assert!(utxo_set.len() == 1);
        assert!(utxos_pk.len() == 1);

        let tx_2 = Tx {
            id: [
                246, 58, 249, 53, 156, 62, 74, 87, 182, 55, 162, 148, 78, 155, 162, 247, 171, 49,
                217, 173, 92, 130, 53, 22, 26, 131, 145, 221, 124, 249, 125, 69,
            ],
            version: 1,
            lock_time: 0,
            flag: 0,
            tx_witness: vec![],
            tx_in_count: 1,
            tx_in: vec![TxIn {
                previous_output: OutPoint {
                    hash: [
                        188, 230, 109, 89, 92, 255, 134, 80, 172, 55, 252, 24, 23, 39, 241, 197,
                        198, 168, 115, 20, 9, 105, 75, 41, 112, 143, 54, 138, 18, 137, 204, 123,
                    ],
                    index: 0,
                },
                script_length: 106,
                signature_script: [
                    71, 48, 68, 2, 32, 90, 170, 121, 238, 37, 6, 132, 231, 219, 177, 232, 205, 193,
                    91, 19, 0, 78, 80, 3, 220, 74, 72, 193, 233, 60, 142, 7, 146, 55, 176, 114,
                    103, 2, 32, 77, 132, 142, 31, 180, 80, 208, 220, 209, 113, 149, 161, 101, 31,
                    48, 203, 6, 231, 128, 247, 187, 43, 252, 11, 99, 202, 70, 115, 113, 45, 3, 186,
                    1, 33, 2, 20, 28, 142, 103, 244, 6, 181, 130, 126, 50, 140, 1, 132, 188, 50,
                    59, 67, 144, 104, 43, 227, 97, 153, 206, 105, 1, 12, 47, 189, 173, 128, 172,
                ]
                .to_vec(),
                sequence: 4294967295,
            }],
            tx_out_count: 1,
            tx_out: vec![TxOut {
                value: 100000,
                pk_script_length: 25,
                pk_script: vec![
                    118, 169, 20, 181, 51, 138, 19, 120, 118, 0, 187, 24, 163, 236, 151, 149, 117,
                    93, 82, 212, 10, 107, 236, 136, 172,
                ],
            }],
        };

        generate_utxos(&mut utxo_set, &tx_2);
        utxos_pk = utxo_set.get(&pk).unwrap().clone();

        assert!(utxo_set.len() == 2);
        assert!(utxos_pk.len() == 1);

        update_utxo_set(&mut utxo_set, &tx_2);
        utxos_pk = utxo_set.get(&pk).unwrap().clone();

        assert!(utxo_set.len() == 2);
        assert!(utxos_pk.len() == 0);
    }

    }
