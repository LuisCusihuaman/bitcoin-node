use crate::utils::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Tx {
    version: u32,
    flag: u16,
    tx_in_count: u64,
    tx_in: Vec<TxIn>,
    tx_out_count: u64,
    tx_out: Vec<TxOut>,
    tx_witness: Vec<u8>,
    lock_time: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TxIn {
    previous_output: [u8; 36],
    script_length: u8,
    signature_script: Vec<u8>,
    sequence: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TxOut {
    value: u64,
    pk_script_length: u64,
    pk_script: Vec<u8>,
}

impl Tx {
    pub fn get_size(&self) -> u64 {
        let mut size = 0;

        // Calculate the size of fixed-size fields
        size += std::mem::size_of::<u32>() as u64; // version
        size += std::mem::size_of::<u32>() as u64; // flag
        size += std::mem::size_of::<u8>() as u64; // tx_in_count
        size += std::mem::size_of::<u8>() as u64; // tx_out_count
        size += std::mem::size_of::<u32>() as u64; // lock_time

        // Calculate the size of variable-length fields
        size += self.tx_in.iter().fold(0, |acc, tx_in| {
            acc + std::mem::size_of::<[u8; 32]>() as u64
                + std::mem::size_of::<u8>() as u64
                + tx_in.signature_script.len() as u64
                + std::mem::size_of::<u32>() as u64
        });

        size += self.tx_out.iter().fold(0, |acc, tx_out| {
            acc + std::mem::size_of::<u64>() as u64
                + std::mem::size_of::<u8>() as u64
                + tx_out.pk_script.len() as u64
        });

        size += self.tx_witness.len() as u64;

        size
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
    let version = read_u32_le(&buffer, 0);
    *offset += 4;

    // If present, always 0x0001 , and indicates the presence of witness data
    let (flag, flag_bytes) = check_flag(&buffer[*offset..]);
    *offset += flag_bytes;

    if flag == 1{
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

        let script_length = read_varint(&mut &buffer[*offset..]).unwrap() as u8;
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

    Some(Tx {
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
        return (0, 0)
    }
    if buffer[1] != 0x01 {
        return (0, 0)
    }
    (0x0001, 2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_size() {
        // Create a sample transaction
        let tx_in_1 = TxIn {
            previous_output: [0u8; 36],
            script_length: 10,
            signature_script: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
            sequence: 0,
        };

        let tx_in_2 = TxIn {
            previous_output: [0u8; 36],
            script_length: 5,
            signature_script: vec![11, 12, 13, 14, 15],
            sequence: 0,
        };

        let tx_out_1 = TxOut {
            value: 100_000_000,
            pk_script_length: 8,
            pk_script: vec![16, 17, 18, 19, 20, 21, 22, 23],
        };

        let tx_out_2 = TxOut {
            value: 200_000_000,
            pk_script_length: 6,
            pk_script: vec![24, 25, 26, 27, 28, 29],
        };

        let tx = Tx {
            version: 1,
            flag: 0,
            tx_in_count: 2,
            tx_in: vec![tx_in_1.clone(), tx_in_2.clone()],
            tx_out_count: 2,
            tx_out: vec![tx_out_1.clone(), tx_out_2.clone()],
            tx_witness: vec![30, 31, 32],
            lock_time: 123456789,
        };

        // Calculate the expected size
        let expected_size = std::mem::size_of::<u32>() as u64 +  // version
            std::mem::size_of::<u32>() as u64 +  // flag
            std::mem::size_of::<u8>() as u64 +   // tx_in_count
            std::mem::size_of_val(&tx_in_1.previous_output) as u64 +  // previous_output
            std::mem::size_of::<u8>() as u64 +   // script_length
            tx_in_1.signature_script.len() as u64 +  // signature_script
            std::mem::size_of::<u32>() as u64 +  // sequence
            std::mem::size_of_val(&tx_in_2.previous_output) as u64 +  // previous_output
            std::mem::size_of::<u8>() as u64 +   // script_length
            tx_in_2.signature_script.len() as u64 +  // signature_script
            std::mem::size_of::<u32>() as u64 +  // sequence
            std::mem::size_of::<u8>() as u64 +   // tx_out_count
            std::mem::size_of::<u64>() as u64 +  // value
            std::mem::size_of::<u8>() as u64 +   // pk_script_length
            tx_out_1.pk_script.len() as u64 +    // pk_script
            std::mem::size_of::<u64>() as u64 +  // value
            std::mem::size_of::<u8>() as u64 +   // pk_script_length
            tx_out_2.pk_script.len() as u64 +    // pk_script
            tx.tx_witness.len() as u64 +         // tx_witness
            std::mem::size_of::<u32>() as u64; // lock_time

        // Check if the calculated size matches the expected size
        assert_eq!(tx.get_size(), expected_size);
    }
}
