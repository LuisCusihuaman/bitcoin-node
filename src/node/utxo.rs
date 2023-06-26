use bitcoin_hashes::{hash160, Hash};

use crate::net::message::tx::Tx;
use crate::utils::{get_address_base58, read_be};
use std::collections::{BTreeMap, HashMap};
use std::mem;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Utxo {
    pub transaction_id: [u8; 32],
    pub output_index: u32, // this is a transaction tx/_in outpoint index?
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

        // Esto es una coinbase o si es una sigScript invalida
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
        let mut is_duplicated= false;
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
                // new address from one month
                let mut utxos_return = Vec::new();
                utxos_return.push(utxo_new);
                utxos_return
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

        // Create a real transaction
        let tx_1 = Tx {
            id: [
                188, 230, 109, 89, 92, 255, 134, 80, 172, 55, 252, 24, 23, 39, 241, 197, 198, 168,
                115, 20, 9, 105, 75, 41, 112, 143, 54, 138, 18, 137, 204, 123,
            ],
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
            tx_out_count: 2,
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

    //     #[test]
    //     fn correctly_creates_unspent_utxo() {
    //         let mut utxo_set = HashMap::new();
    //         let new_transaction = Tx {
    //             id: [
    //                 72, 132, 120, 96, 171, 214, 128, 219, 33, 157, 16, 192, 174, 101, 128, 69, 181,
    //                 126, 185, 38, 161, 37, 17, 65, 92, 229, 106, 55, 131, 235, 133, 202,
    //             ],
    //             version: 2,
    //             flag: 0,
    //             tx_in_count: 7,
    //             tx_in: vec![
    //                 TxIn {
    //                     previous_output: OutPoint {
    //                         hash: [
    //                             226, 186, 153, 202, 133, 201, 191, 217, 242, 20, 228, 81, 115, 195, 78,
    //                             140, 34, 173, 40, 212, 252, 161, 254, 59, 118, 110, 113, 203, 95, 194,
    //                             15, 31,
    //                         ],
    //                         index: 1,
    //                     },
    //                     script_length: 108,
    //                     signature_script: vec![
    //                         73, 48, 70, 2, 33, 0, 186, 116, 152, 184, 8, 221, 93, 28, 177, 136, 228,
    //                         20, 140, 153, 52, 84, 129, 0, 53, 247, 167, 210, 132, 236, 111, 18, 230,
    //                         22, 184, 157, 248, 68, 2, 33, 0, 228, 96, 137, 98, 40, 71, 186, 241, 162,
    //                         226, 222, 5, 21, 235, 53, 85, 46, 23, 162, 171, 237, 37, 108, 133, 186,
    //                         197, 192, 99, 165, 197, 28, 248, 1, 33, 3, 90, 249, 72, 176, 24, 177, 15,
    //                         244, 242, 166, 91, 179, 107, 118, 10, 227, 196, 58, 243, 29, 62, 197, 90,
    //                         196, 208, 42, 212, 228, 208, 29, 40, 68,
    //                     ],
    //                     sequence: 4294967295,
    //                 },
    //                 TxIn {
    //                     previous_output: OutPoint {
    //                         hash: [
    //                             87, 11, 145, 133, 166, 10, 91, 198, 242, 120, 93, 28, 141, 156, 172,
    //                             229, 167, 78, 2, 4, 36, 136, 23, 48, 7, 126, 253, 166, 170, 52, 117,
    //                             44,
    //                         ],
    //                         index: 0,
    //                     },
    //                     script_length: 106,
    //                     signature_script: vec![
    //                         71, 48, 68, 2, 32, 11, 179, 179, 252, 228, 62, 6, 213, 107, 68, 198, 255,
    //                         74, 179, 57, 210, 58, 128, 130, 231, 153, 227, 15, 162, 228, 59, 217, 16,
    //                         136, 205, 178, 163, 2, 32, 55, 79, 199, 51, 230, 226, 197, 138, 149, 59,
    //                         180, 46, 57, 174, 142, 38, 0, 166, 144, 155, 122, 34, 211, 127, 94, 94,
    //                         159, 188, 187, 36, 135, 41, 1, 33, 3, 90, 249, 72, 176, 24, 177, 15, 244,
    //                         242, 166, 91, 179, 107, 118, 10, 227, 196, 58, 243, 29, 62, 197, 90, 196,
    //                         208, 42, 212, 228, 208, 29, 40, 68,
    //                     ],
    //                     sequence: 4294967295,
    //                 },
    //                 TxIn {
    //                     previous_output: OutPoint {
    //                         hash: [
    //                             32, 147, 198, 194, 94, 20, 50, 221, 56, 255, 251, 30, 188, 120, 121,
    //                             159, 94, 103, 113, 8, 92, 223, 73, 28, 93, 246, 131, 233, 78, 185, 135,
    //                             74,
    //                         ],
    //                         index: 1,
    //                     },
    //                     script_length: 108,
    //                     signature_script: vec![
    //                         73, 48, 70, 2, 33, 0, 240, 181, 236, 200, 22, 39, 131, 90, 11, 7, 31, 63,
    //                         23, 150, 223, 11, 124, 117, 103, 71, 72, 58, 43, 126, 35, 203, 163, 3, 190,
    //                         61, 167, 15, 2, 33, 0, 166, 238, 85, 92, 155, 22, 40, 70, 122, 27, 72, 243,
    //                         230, 60, 179, 17, 255, 166, 147, 231, 13, 182, 206, 7, 9, 225, 196, 152,
    //                         28, 127, 205, 111, 1, 33, 3, 90, 249, 72, 176, 24, 177, 15, 244, 242, 166,
    //                         91, 179, 107, 118, 10, 227, 196, 58, 243, 29, 62, 197, 90, 196, 208, 42,
    //                         212, 228, 208, 29, 40, 68,
    //                     ],
    //                     sequence: 4294967295,
    //                 },
    //                 TxIn {
    //                     previous_output: OutPoint {
    //                         hash: [
    //                             199, 106, 135, 0, 185, 117, 124, 99, 211, 106, 15, 189, 198, 113, 214,
    //                             189, 25, 221, 198, 45, 62, 102, 201, 221, 198, 180, 230, 119, 168, 63,
    //                             170, 134,
    //                         ],
    //                         index: 1,
    //                     },
    //                     script_length: 107,
    //                     signature_script: vec![
    //                         72, 48, 69, 2, 33, 0, 148, 183, 111, 75, 123, 151, 140, 112, 229, 245, 34,
    //                         191, 169, 213, 114, 188, 201, 178, 174, 94, 42, 210, 246, 124, 146, 195,
    //                         195, 193, 14, 222, 13, 185, 2, 32, 104, 44, 162, 137, 124, 138, 201, 138,
    //                         17, 189, 255, 197, 139, 68, 191, 177, 133, 93, 174, 140, 68, 249, 106, 194,
    //                         21, 34, 44, 192, 250, 197, 96, 22, 1, 33, 3, 90, 249, 72, 176, 24, 177, 15,
    //                         244, 242, 166, 91, 179, 107, 118, 10, 227, 196, 58, 243, 29, 62, 197, 90,
    //                         196, 208, 42, 212, 228, 208, 29, 40, 68,
    //                     ],
    //                     sequence: 4294967295,
    //                 },
    //                 TxIn {
    //                     previous_output: OutPoint {
    //                         hash: [
    //                             113, 35, 225, 56, 130, 84, 0, 26, 180, 60, 21, 164, 153, 182, 156, 157,
    //                             52, 43, 137, 67, 175, 115, 113, 220, 238, 17, 250, 26, 185, 120, 104,
    //                             194,
    //                         ],
    //                         index: 1,
    //                     },
    //                     script_length: 107,
    //                     signature_script: vec![
    //                         72, 48, 69, 2, 33, 0, 249, 75, 138, 74, 35, 71, 68, 234, 176, 124, 125,
    //                         236, 105, 223, 106, 96, 243, 178, 247, 73, 116, 137, 249, 160, 249, 141,
    //                         194, 244, 245, 150, 142, 148, 2, 32, 75, 3, 136, 146, 62, 123, 235, 44, 96,
    //                         246, 251, 57, 182, 175, 38, 231, 171, 3, 92, 22, 239, 131, 242, 250, 189,
    //                         44, 162, 42, 103, 251, 124, 173, 1, 33, 3, 90, 249, 72, 176, 24, 177, 15,
    //                         244, 242, 166, 91, 179, 107, 118, 10, 227, 196, 58, 243, 29, 62, 197, 90,
    //                         196, 208, 42, 212, 228, 208, 29, 40, 68,
    //                     ],
    //                     sequence: 4294967295,
    //                 },
    //                 TxIn {
    //                     previous_output: OutPoint {
    //                         hash: [
    //                             211, 188, 83, 197, 125, 117, 74, 74, 184, 74, 214, 26, 114, 107, 75,
    //                             181, 136, 146, 27, 10, 10, 3, 171, 202, 169, 123, 208, 250, 240, 241,
    //                             114, 231,
    //                         ],
    //                         index: 1,
    //                     },
    //                     script_length: 108,
    //                     signature_script: vec![
    //                         73, 48, 70, 2, 33, 0, 224, 53, 209, 40, 121, 66, 156, 139, 156, 123, 122,
    //                         129, 244, 76, 38, 203, 29, 91, 123, 62, 128, 125, 105, 44, 218, 226, 166,
    //                         66, 199, 138, 236, 154, 2, 33, 0, 130, 49, 45, 12, 10, 54, 196, 88, 128,
    //                         232, 147, 104, 113, 85, 134, 124, 46, 236, 177, 197, 78, 248, 91, 139, 78,
    //                         139, 91, 97, 221, 88, 22, 89, 1, 33, 3, 90, 249, 72, 176, 24, 177, 15, 244,
    //                         242, 166, 91, 179, 107, 118, 10, 227, 196, 58, 243, 29, 62, 197, 90, 196,
    //                         208, 42, 212, 228, 208, 29, 40, 68,
    //                     ],
    //                     sequence: 4294967295,
    //                 },
    //                 TxIn {
    //                     previous_output: OutPoint {
    //                         hash: [
    //                             230, 17, 204, 216, 152, 113, 52, 184, 70, 87, 1, 249, 234, 17, 39, 102,
    //                             77, 17, 41, 48, 122, 17, 106, 157, 133, 63, 1, 153, 206, 101, 110, 234,
    //                         ],
    //                         index: 1,
    //                     },
    //                     script_length: 107,
    //                     signature_script: vec![
    //                         72, 48, 69, 2, 32, 63, 84, 31, 24, 79, 144, 242, 87, 201, 64, 157, 230,
    //                         108, 126, 186, 229, 5, 47, 242, 225, 171, 184, 51, 149, 222, 246, 79, 93,
    //                         65, 17, 39, 172, 2, 33, 0, 218, 47, 194, 209, 134, 43, 227, 58, 108, 15,
    //                         234, 194, 96, 163, 122, 140, 96, 42, 133, 56, 173, 205, 183, 242, 198, 29,
    //                         254, 85, 229, 71, 188, 221, 1, 33, 3, 90, 249, 72, 176, 24, 177, 15, 244,
    //                         242, 166, 91, 179, 107, 118, 10, 227, 196, 58, 243, 29, 62, 197, 90, 196,
    //                         208, 42, 212, 228, 208, 29, 40, 68,
    //                     ],
    //                     sequence: 4294967295,
    //                 },
    //             ],
    //             tx_out_count: 9,
    //             tx_out: vec![
    //                 TxOut {
    //                     value: 35000,
    //                     pk_script_length: 25,
    //                     pk_script: vec![
    //                         118, 169, 20, 229, 71, 99, 169, 199, 169, 16, 118, 146, 239, 40, 0, 135,
    //                         51, 87, 76, 201, 29, 91, 18, 136, 172,
    //                     ],
    //                 },
    //                 TxOut {
    //                     value: 6945000,
    //                     pk_script_length: 25,
    //                     pk_script: vec![
    //                         118, 169, 20, 83, 55, 48, 148, 170, 167, 46, 81, 250, 112, 50, 153, 245,
    //                         36, 27, 189, 6, 255, 98, 230, 136, 172,
    //                     ],
    //                 },
    //                 TxOut {
    //                     value: 615519,
    //                     pk_script_length: 25,
    //                     pk_script: vec![
    //                         118, 169, 20, 118, 81, 78, 44, 13, 38, 12, 152, 103, 31, 202, 163, 105, 61,
    //                         151, 14, 188, 44, 242, 57, 136, 172,
    //                     ],
    //                 },
    //                 TxOut {
    //                     value: 20000,
    //                     pk_script_length: 25,
    //                     pk_script: vec![
    //                         118, 169, 20, 254, 14, 239, 105, 52, 104, 7, 185, 183, 145, 48, 227, 146,
    //                         106, 193, 158, 34, 133, 84, 149, 136, 172,
    //                     ],
    //                 },
    //                 TxOut {
    //                     value: 426540,
    //                     pk_script_length: 25,
    //                     pk_script: vec![
    //                         118, 169, 20, 154, 196, 13, 68, 9, 142, 117, 87, 77, 157, 245, 147, 40,
    //                         251, 240, 78, 65, 221, 125, 46, 136, 172,
    //                     ],
    //                 },
    //                 TxOut {
    //                     value: 680033,
    //                     pk_script_length: 25,
    //                     pk_script: vec![
    //                         118, 169, 20, 55, 156, 16, 203, 12, 73, 124, 201, 36, 154, 42, 134, 84,
    //                         163, 241, 155, 233, 217, 93, 134, 136, 172,
    //                     ],
    //                 },
    //                 TxOut {
    //                     value: 20000,
    //                     pk_script_length: 25,
    //                     pk_script: vec![
    //                         118, 169, 20, 205, 186, 89, 206, 86, 230, 187, 91, 139, 71, 209, 78, 66,
    //                         173, 7, 161, 199, 118, 29, 63, 136, 172,
    //                     ],
    //                 },
    //                 TxOut {
    //                     value: 645634,
    //                     pk_script_length: 25,
    //                     pk_script: vec![
    //                         118, 169, 20, 10, 74, 129, 168, 231, 144, 184, 206, 179, 2, 189, 63, 34,
    //                         252, 125, 202, 254, 161, 148, 12, 136, 172,
    //                     ],
    //                 },
    //                 TxOut {
    //                     value: 669645,
    //                     pk_script_length: 25,
    //                     pk_script: vec![
    //                         118, 169, 20, 122, 228, 120, 18, 59, 150, 13, 46, 233, 18, 104, 91, 129,
    //                         152, 169, 8, 100, 187, 100, 137, 136, 172,
    //                     ],
    //                 },
    //             ],
    //             tx_witness: vec![],
    //             lock_time: 0,
    //         };

    //         generate_utxos(&mut utxo_set, &new_transaction);
    //         let utxo = utxo_set.get(&new_transaction.id).unwrap().first().unwrap();

    //         // Ensure that the UTXO set is updated correctly

    //         assert_eq!(utxo.spent, false);
    //     }

    //     #[test]
    //     fn correctly_updates_spent_utxo() {
    //         let mut utxo_set = HashMap::new();
    //         let new_transaction = Tx {
    //             id: [
    //                 72, 132, 120, 96, 171, 214, 128, 219, 33, 157, 16, 192, 174, 101, 128, 69, 181,
    //                 126, 185, 38, 161, 37, 17, 65, 92, 229, 106, 55, 131, 235, 133, 202,
    //             ],
    //             version: 2,
    //             flag: 0,
    //             tx_in_count: 7,
    //             tx_in: vec![TxIn {
    //                 previous_output: OutPoint {
    //                     hash: [
    //                         230, 17, 204, 216, 152, 113, 52, 184, 70, 87, 1, 249, 234, 17, 39, 102, 77,
    //                         17, 41, 48, 122, 17, 106, 157, 133, 63, 1, 153, 206, 101, 110, 234,
    //                     ],
    //                     index: 1,
    //                 },
    //                 script_length: 107,
    //                 signature_script: vec![
    //                     72, 48, 69, 2, 32, 63, 84, 31, 24, 79, 144, 242, 87, 201, 64, 157, 230, 108,
    //                     126, 186, 229, 5, 47, 242, 225, 171, 184, 51, 149, 222, 246, 79, 93, 65, 17,
    //                     39, 172, 2, 33, 0, 218, 47, 194, 209, 134, 43, 227, 58, 108, 15, 234, 194, 96,
    //                     163, 122, 140, 96, 42, 133, 56, 173, 205, 183, 242, 198, 29, 254, 85, 229, 71,
    //                     188, 221, 1, 33, 3, 90, 249, 72, 176, 24, 177, 15, 244, 242, 166, 91, 179, 107,
    //                     118, 10, 227, 196, 58, 243, 29, 62, 197, 90, 196, 208, 42, 212, 228, 208, 29,
    //                     40, 68,
    //                 ],
    //                 sequence: 4294967295,
    //             }],
    //             tx_out_count: 9,
    //             tx_out: vec![TxOut {
    //                 value: 669645,
    //                 pk_script_length: 25,
    //                 pk_script: vec![
    //                     118, 169, 20, 122, 228, 120, 18, 59, 150, 13, 46, 233, 18, 104, 91, 129, 152,
    //                     169, 8, 100, 187, 100, 137, 136, 172,
    //                 ],
    //             }],
    //             tx_witness: vec![],
    //             lock_time: 0,
    //         };

    //         let new_transaction = Tx {
    //             id: [
    //                 72, 132, 120, 96, 171, 214, 128, 219, 33, 157, 16, 192, 174, 101, 128, 69, 181,
    //                 126, 185, 38, 161, 37, 17, 65, 92, 229, 106, 55, 131, 235, 133, 202,
    //             ],
    //             version: 2,
    //             flag: 0,
    //             tx_in_count: 7,
    //             tx_in: vec![TxIn {
    //                 previous_output: OutPoint {
    //                     hash: [
    //                         230, 17, 204, 216, 152, 113, 52, 184, 70, 87, 1, 249, 234, 17, 39, 102, 77,
    //                         17, 41, 48, 122, 17, 106, 157, 133, 63, 1, 153, 206, 101, 110, 234,
    //                     ],
    //                     index: 1,
    //                 },
    //                 script_length: 107,
    //                 signature_script: vec![
    //                     72, 48, 69, 2, 32, 63, 84, 31, 24, 79, 144, 242, 87, 201, 64, 157, 230, 108,
    //                     126, 186, 229, 5, 47, 242, 225, 171, 184, 51, 149, 222, 246, 79, 93, 65, 17,
    //                     39, 172, 2, 33, 0, 218, 47, 194, 209, 134, 43, 227, 58, 108, 15, 234, 194, 96,
    //                     163, 122, 140, 96, 42, 133, 56, 173, 205, 183, 242, 198, 29, 254, 85, 229, 71,
    //                     188, 221, 1, 33, 3, 90, 249, 72, 176, 24, 177, 15, 244, 242, 166, 91, 179, 107,
    //                     118, 10, 227, 196, 58, 243, 29, 62, 197, 90, 196, 208, 42, 212, 228, 208, 29,
    //                     40, 68,
    //                 ],
    //                 sequence: 4294967295,
    //             }],
    //             tx_out_count: 9,
    //             tx_out: vec![TxOut {
    //                 value: 645634,
    //                 pk_script_length: 25,
    //                 pk_script: vec![
    //                     118, 169, 20, 10, 74, 129, 168, 231, 144, 184, 206, 179, 2, 189, 63, 34, 252,
    //                     125, 202, 254, 161, 148, 12, 136, 172,
    //                 ],
    //             }],
    //             tx_witness: vec![],
    //             lock_time: 0,
    //         };

    //         generate_utxos(&mut utxo_set, &new_transaction);
    //         update_utxo_set(&mut utxo_set, &new_transaction);

    //         let tx_in = TxIn {
    //             previous_output: OutPoint {
    //                 hash: [
    //                     230, 17, 204, 216, 152, 113, 52, 184, 70, 87, 1, 249, 234, 17, 39, 102, 77, 17,
    //                     41, 48, 122, 17, 106, 157, 133, 63, 1, 153, 206, 101, 110, 234,
    //                 ],
    //                 index: 1,
    //             },
    //             script_length: 107,
    //             signature_script: vec![
    //                 72, 48, 69, 2, 32, 63, 84, 31, 24, 79, 144, 242, 87, 201, 64, 157, 230, 108, 126,
    //                 186, 229, 5, 47, 242, 225, 171, 184, 51, 149, 222, 246, 79, 93, 65, 17, 39, 172, 2,
    //                 33, 0, 218, 47, 194, 209, 134, 43, 227, 58, 108, 15, 234, 194, 96, 163, 122, 140,
    //                 96, 42, 133, 56, 173, 205, 183, 242, 198, 29, 254, 85, 229, 71, 188, 221, 1, 33, 3,
    //                 90, 249, 72, 176, 24, 177, 15, 244, 242, 166, 91, 179, 107, 118, 10, 227, 196, 58,
    //                 243, 29, 62, 197, 90, 196, 208, 42, 212, 228, 208, 29, 40, 68,
    //             ],
    //             sequence: 4294967295,
    //         };

    //         // Ensure that the UTXO set is updated correctly
    //         assert!(is_tx_spent(&utxo_set, &tx_in) == false);
    //     }

    //     #[test]
    //     fn test_utxo_set_saves_all_tx_out_from_tx() {
    //         let mut utxo_set = HashMap::new();

    //         let new_transaction = Tx {
    //             id: [
    //                 72, 132, 120, 96, 171, 214, 128, 219, 33, 157, 16, 192, 174, 101, 128, 69, 181,
    //                 126, 185, 38, 161, 37, 17, 65, 92, 229, 106, 55, 131, 235, 133, 202,
    //             ],
    //             version: 2,
    //             flag: 0,
    //             tx_in_count: 1,
    //             tx_in: vec![TxIn {
    //                 previous_output: OutPoint {
    //                     hash: [
    //                         230, 17, 204, 216, 152, 113, 52, 184, 70, 87, 1, 249, 234, 17, 39, 102, 77,
    //                         17, 41, 48, 122, 17, 106, 157, 133, 63, 1, 153, 206, 101, 110, 234,
    //                     ],
    //                     index: 1,
    //                 },
    //                 script_length: 107,
    //                 signature_script: vec![
    //                     72, 48, 69, 2, 32, 63, 84, 31, 24, 79, 144, 242, 87, 201, 64, 157, 230, 108,
    //                     126, 186, 229, 5, 47, 242, 225, 171, 184, 51, 149, 222, 246, 79, 93, 65, 17,
    //                     39, 172, 2, 33, 0, 218, 47, 194, 209, 134, 43, 227, 58, 108, 15, 234, 194, 96,
    //                     163, 122, 140, 96, 42, 133, 56, 173, 205, 183, 242, 198, 29, 254, 85, 229, 71,
    //                     188, 221, 1, 33, 3, 90, 249, 72, 176, 24, 177, 15, 244, 242, 166, 91, 179, 107,
    //                     118, 10, 227, 196, 58, 243, 29, 62, 197, 90, 196, 208, 42, 212, 228, 208, 29,
    //                     40, 68,
    //                 ],
    //                 sequence: 4294967295,
    //             }],
    //             tx_out_count: 1,
    //             tx_out: vec![
    //                 TxOut {
    //                     value: 669645,
    //                     pk_script_length: 25,
    //                     pk_script: vec![
    //                         118, 169, 20, 122, 228, 120, 18, 59, 150, 13, 46, 233, 18, 104, 91, 129,
    //                         152, 169, 8, 100, 187, 100, 137, 136, 172,
    //                     ],
    //                 },
    //                 TxOut {
    //                     value: 645634,
    //                     pk_script_length: 25,
    //                     pk_script: vec![
    //                         118, 169, 20, 10, 74, 129, 168, 231, 144, 184, 206, 179, 2, 189, 63, 34,
    //                         252, 125, 202, 254, 161, 148, 12, 136, 172,
    //                     ],
    //                 },
    //                 TxOut {
    //                     value: 669645,
    //                     pk_script_length: 25,
    //                     pk_script: vec![
    //                         118, 169, 20, 122, 228, 120, 18, 59, 150, 13, 46, 233, 18, 104, 91, 129,
    //                         152, 169, 8, 100, 187, 100, 137, 136, 172,
    //                     ],
    //                 },
    //             ],
    //             tx_witness: vec![],
    //             lock_time: 0,
    //         };

    //         generate_utxos(&mut utxo_set, &new_transaction);

    //         let utxo = utxo_set.get(&new_transaction.id).unwrap();

    //         assert_eq!(utxo.len(), 3);
    //     }
}
