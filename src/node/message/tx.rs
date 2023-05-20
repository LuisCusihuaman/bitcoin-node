use bitcoin_hashes::Hash;

use crate::utils::write_varint;

use crate::utils::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Tx {
    pub id: [u8; 32],
    pub version: u32,
    pub flag: u16,
    pub tx_in_count: u64, // varint
    pub tx_in: Vec<TxIn>,
    pub tx_out_count: u64, // varint
    pub tx_out: Vec<TxOut>,
    pub tx_witness: Vec<u8>,
    pub lock_time: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TxIn {
    pub previous_output: [u8; 36],
    pub script_length: u64, // varint
    pub signature_script: Vec<u8>,
    pub sequence: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TxOut {
    pub value: u64,
    pub pk_script_length: u64, // varint
    pub pk_script: Vec<u8>,
}

impl Tx {
    pub fn encode(&self) -> Vec<u8> {
        let mut encoded: Vec<u8> = Vec::new();

        encoded.extend(self.version.to_le_bytes());

        if self.flag != 0 {
            encoded.extend(self.flag.to_le_bytes());
        }

        write_varint(&mut encoded, self.tx_in_count as usize).unwrap();

        for tx_in in &self.tx_in {
            encoded.extend(tx_in.previous_output);
            write_varint(&mut encoded, tx_in.script_length as usize).unwrap();
            encoded.extend(tx_in.signature_script.clone());
            encoded.extend(tx_in.sequence.to_le_bytes());
        }

        write_varint(&mut encoded, self.tx_out_count as usize).unwrap();

        for tx_out in &self.tx_out {
            encoded.extend(tx_out.value.to_le_bytes());
            write_varint(&mut encoded, tx_out.pk_script_length as usize).unwrap();
            encoded.extend(tx_out.pk_script.clone());
        }

        if self.flag != 0 {
            encoded.extend(&self.tx_witness);
        }

        encoded.extend(self.lock_time.to_le_bytes());

        encoded
    }
}

// pub struct OutPoint {
//     hash: [u8; 32],
//     index: u32,
// }

// pub struct TxInWitness {
//     witness: Vec<u8>,
// }

pub fn decode_tx(buffer: &[u8], offset: &mut usize) -> Option<Tx> {
    let old_offset = *offset;
    let version = read_u32_le(&buffer, 0);
    *offset += 4;

    // If present, always 0x0001 , and indicates the presence of witness data
    let (flag, flag_bytes) = check_flag(&buffer[*offset..]);
    *offset += flag_bytes;

    if flag == 1 {
        // AAAAAA
        println!("flag: 1 LOL")
    }

    let tx_in_count = read_varint(&mut &buffer[*offset..]).unwrap() as u64; // Never zero, TODO calcular bien offset arriba
    *offset += get_offset(&buffer[*offset..]);

    let mut tx_in = Vec::new();

    for _ in 0..tx_in_count {
        let mut previous_output = [0u8; 36];
        previous_output.copy_from_slice(&buffer[*offset..*offset + 36]);
        *offset += 36;

        let script_length = read_varint(&mut &buffer[*offset..]).unwrap() as u64;
        *offset += get_offset(&buffer[*offset..]);

        let mut signature_script = Vec::new();
        signature_script.extend(&buffer[*offset..*offset + script_length as usize]);
        *offset += script_length as usize;

        let sequence = read_u32_le(&buffer, *offset);
        *offset += 4;

        let tx_input = TxIn {
            previous_output,
            script_length,
            signature_script,
            sequence,
        };

        tx_in.push(tx_input);
    }

    let tx_out_count = read_varint(&mut &buffer[*offset..]).unwrap() as u64;
    *offset += get_offset(&buffer[*offset..]);

    let mut tx_out = Vec::new();

    for _ in 0..tx_out_count {
        let value = read_u64_le(buffer, *offset);
        *offset += 8;

        let pk_script_length = read_varint(&mut &buffer[*offset..]).unwrap() as u64;
        *offset += get_offset(&buffer[*offset..]);

        let mut pk_script = Vec::new();
        pk_script.extend(&buffer[*offset..*offset + pk_script_length as usize]);
        *offset += pk_script_length as usize;

        let tx_output = TxOut {
            value,
            pk_script_length,
            pk_script,
        };

        tx_out.push(tx_output);
    }

    let tx_witness = if flag != 0 {
        let witness_length = buffer[*offset];
        *offset += 1;

        let mut tx_witness = Vec::new();
        tx_witness.extend(&buffer[*offset..*offset + witness_length as usize]);
        *offset += witness_length as usize;

        tx_witness
    } else {
        Vec::new()
        // Offset no se actualiza
    };

    let lock_time = read_u32_le(&buffer, *offset);
    *offset += 4;

    let raw_hash = double_sha256(&buffer[old_offset..*offset]).to_byte_array();
    let mut id: [u8; 32] = [0u8; 32];
    copy_bytes_to_array(&raw_hash, &mut id);
    id.reverse();
    println!("id: {:?}", id);

    Some(Tx {
        id,
        version,
        flag,
        tx_in_count,
        tx_in,
        tx_out_count,
        tx_out,
        tx_witness,
        lock_time,
    })
}

fn check_flag(buffer: &[u8]) -> (u16, usize) {
    if buffer[0] != 0x00 {
        return (0, 0);
    }
    if buffer[1] != 0x01 {
        return (0, 0);
    }
    (0x0001, 2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_encode_tx() {
            let tx = Tx {
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

            let mut expected_encoded: Vec<u8> = Vec::new();

            expected_encoded.extend(&[0x01, 0x00, 0x00, 0x00]); // version
                                                                //expected_encoded.extend(&[0x00, 0x00]); // flag
            expected_encoded.extend(&[0x02]); // tx_in_count  // varint

            for _ in 0..2 {
                expected_encoded.extend(&[0x00; 36]); // tx_in.previous_output
                expected_encoded.extend(&[0x00]); // tx_in.script_length // varint// varint
                                                  // expected_encoded.extend( vacio ); // tx_in.signature_script
                expected_encoded.extend(&[0x00; 4]); // tx_in.sequence
            }

            expected_encoded.extend(&[0x01]); // tx_out_count // varint
            expected_encoded.extend(100_000_000u64.to_le_bytes()); // tx_out.value
            expected_encoded.extend(&[0x00]); // tx_out.pk_script_length // varint
                                              // expected_encoded.extend( vacio ); // tx_in.signature_script

            expected_encoded.extend(&[0x00, 0x00, 0x00, 0x00]); // lock_time

            assert_eq!(tx.encode(), expected_encoded);
        }
    }

    #[test]
    fn test_encode_tx_with_script_length() {
        let tx = Tx {
            id: [0u8; 32],
            version: 1,
            flag: 0,
            tx_in_count: 2, // varint
            tx_in: vec![
                TxIn {
                    previous_output: [0; 36],
                    script_length: 1, // varint
                    signature_script: vec![4],
                    sequence: 0,
                },
                TxIn {
                    previous_output: [0; 36],
                    script_length: 1, // varint
                    signature_script: vec![4],
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

        let mut expected_encoded: Vec<u8> = Vec::new();

        expected_encoded.extend(&[0x01, 0x00, 0x00, 0x00]); // version
                                                            //expected_encoded.extend(&[0x00, 0x00]); // flag
        expected_encoded.extend(&[0x02]); // tx_in_count  // varint

        for _ in 0..2 {
            expected_encoded.extend(&[0x00; 36]); // tx_in.previous_output
            expected_encoded.extend(&[0x01]); // tx_in.script_length // varint// varint
            expected_encoded.extend(&[0x04]); // tx_in.signature_script
            expected_encoded.extend(&[0x00; 4]); // tx_in.sequence
        }

        expected_encoded.extend(&[0x01]); // tx_out_count // varint
        expected_encoded.extend(100_000_000u64.to_le_bytes()); // tx_out.value
        expected_encoded.extend(&[0x00]); // tx_out.pk_script_length // varint
                                          // expected_encoded.extend( vacio ); // tx_in.signature_script

        expected_encoded.extend(&[0x00, 0x00, 0x00, 0x00]); // lock_time

        assert_eq!(tx.encode(), expected_encoded);
    }
}
