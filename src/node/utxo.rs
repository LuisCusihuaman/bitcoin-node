use crate::node::message::tx::Tx;

#[derive(Clone, Debug, Eq, PartialEq)]

pub struct Utxo {
    pub transaction_id: [u8; 32],
    pub output_index: u32,
    pub value: u64,
    pub recipient_address: Vec<u8>,
    pub spent: bool,
}

pub fn update_utxo_set(utxo_set: &mut [Utxo], tx: &Tx) {
    for tx_in in &tx.tx_in {
        for utxo in utxo_set.iter_mut() {
            if utxo.transaction_id == tx.id {
                // Mark the UTXO as spent
                // For example, you can set a flag or remove the UTXO from the set
                // For simplicity, let's assume setting a `spent` flag to true
                utxo.spent = true;
                break;

                // Borrar de la tabla en un futuro
            }
        }
    }
}

pub fn generate_utxos(utxo_set: &mut Vec<Utxo>, tx: &Tx) {
    for (index, tx_out) in tx.tx_out.iter().enumerate() {
        let utxo = Utxo {
            transaction_id: tx.id,
            output_index: index as u32,
            value: tx_out.value,
            recipient_address: tx_out.pk_script.clone(),
            spent: false,
        };
        utxo_set.push(utxo);
    }
}

pub fn find_utxo(utxo_set: &[Utxo], transaction_id: &[u8; 32], output_index: u32) -> Option<Utxo> {
    for utxo in utxo_set {
        if utxo.transaction_id == *transaction_id && utxo.output_index == output_index {
            return Some(utxo.clone());
        }
    }
    None
}

pub fn find_utxo_by_address(utxo_set: &[Utxo], address: &[u8]) -> Vec<Utxo> {
    let mut utxos: Vec<Utxo> = Vec::new();
    for utxo in utxo_set {
        if utxo.recipient_address == *address {
            utxos.push(utxo.clone());
        }
    }
    utxos
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::message::tx::{Tx, TxIn, TxOut};

    #[test]
    fn test_generate_utxos_and_update_utxo_set() {
        // Create a sample transaction
        let transaction = Tx {
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

        // Generate UTXOs from the transaction
        let utxos = generate_utxos(&transaction);

        // Ensure that the UTXOs are generated correctly
        assert_eq!(utxos.len(), 1);
        assert_eq!(utxos[0].transaction_id, transaction.id);
        assert_eq!(utxos[0].output_index, 0);
        assert_eq!(utxos[0].value, 5000020000);
        assert_eq!(
            utxos[0].recipient_address,
            vec![
                118, 169, 20, 195, 208, 147, 199, 86, 220, 79, 141, 216, 23, 181, 3, 198, 78, 203,
                128, 39, 118, 33, 52, 136, 172,
            ]
        );

        // Create a UTXO set
        let mut utxo_set = utxos.clone();

        // Update the UTXO set with a new transaction spending the previous UTXO
        let new_transaction = Tx {
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

        update_utxo_set(&mut utxo_set, &new_transaction);

        // Ensure that the UTXO set is updated correctly
        assert_eq!(utxo_set.len(), 1);
        assert_eq!(utxo_set[0].spent, false);
    }

    // Test helpers
    fn generate_utxos(tx: &Tx) -> Vec<Utxo> {
        let mut utxos = Vec::new();
        let transaction_id = tx.id;

        for (output_index, tx_out) in tx.tx_out.iter().enumerate() {
            let utxo = Utxo {
                transaction_id,
                output_index: output_index as u32,
                value: tx_out.value,
                recipient_address: tx_out.pk_script.clone(),
                spent: false,
            };
            utxos.push(utxo);
        }
        utxos
    }
}
