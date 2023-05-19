#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Tx {
    version: u32,
    flag: u32,
    tx_in_count: u8,
    tx_in: Vec<TxIn>,
    tx_out_count: u8,
    tx_out: Vec<TxOut>,
    tx_witness: Vec<u8>,
    lock_time: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TxIn {
    previous_output: [u8; 32],
    script_length: u8,
    signature_script: Vec<u8>,
    sequence: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TxOut {
    value: u64,
    pk_script_length: u8,
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

pub fn decode_tx(buffer: &[u8]) -> Option<Tx> {
    if buffer.len() < 85 {
        return None; // Buffer is not large enough for a complete transaction
    }

    let version = u32::from_le_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);

    let flag = u32::from_le_bytes([buffer[4], buffer[5], buffer[6], buffer[7]]);

    let tx_in_count = buffer[8];

    let mut tx_in = Vec::new();
    let mut offset = 9;
    for _ in 0..tx_in_count {
        if offset + 38 > buffer.len() {
            return None; // Buffer is not large enough for the next transaction input
        }

        let mut previous_output = [0u8; 32];
        previous_output.copy_from_slice(&buffer[offset..offset + 32]);
        offset += 32;

        let script_length = buffer[offset];
        offset += 1;

        if offset + script_length as usize > buffer.len() {
            return None; // Buffer is not large enough for the input signature script
        }

        let mut signature_script = Vec::new();
        signature_script.extend_from_slice(&buffer[offset..offset + script_length as usize]);
        offset += script_length as usize;

        let sequence = u32::from_le_bytes([
            buffer[offset],
            buffer[offset + 1],
            buffer[offset + 2],
            buffer[offset + 3],
        ]);
        offset += 4;

        let tx_input = TxIn {
            previous_output,
            script_length,
            signature_script,
            sequence,
        };
        tx_in.push(tx_input);
    }

    let tx_out_count = buffer[offset];

    let mut tx_out = Vec::new();
    offset += 1;
    for _ in 0..tx_out_count {
        if offset + 9 > buffer.len() {
            return None; // Buffer is not large enough for the next transaction output
        }

        let value = u64::from_le_bytes([
            buffer[offset],
            buffer[offset + 1],
            buffer[offset + 2],
            buffer[offset + 3],
            buffer[offset + 4],
            buffer[offset + 5],
            buffer[offset + 6],
            buffer[offset + 7],
        ]);
        offset += 8;

        let pk_script_length = buffer[offset];
        offset += 1;

        if offset + pk_script_length as usize > buffer.len() {
            return None; // Buffer is not large enough for the output pubkey script
        }

        let mut pk_script = Vec::new();
        pk_script.extend_from_slice(&buffer[offset..offset + pk_script_length as usize]);
        offset += pk_script_length as usize;

        let tx_output = TxOut {
            value,
            pk_script_length,
            pk_script,
        };
        tx_out.push(tx_output);
    }

    let tx_witness = if flag != 0 {
        let witness_length = buffer[offset];
        offset += 1;

        if offset + witness_length as usize > buffer.len() {
            return None; // Buffer is not large enough for the transaction witness
        }

        let mut tx_witness = Vec::new();
        tx_witness.extend(&buffer[offset..offset + witness_length as usize]);
        offset += witness_length as usize;

        tx_witness
    } else {
        Vec::new()
    };

    if offset + 4 > buffer.len() {
        return None; // Buffer is not large enough for the transaction lock time
    }

    let lock_time = u32::from_le_bytes([
        buffer[offset],
        buffer[offset + 1],
        buffer[offset + 2],
        buffer[offset + 3],
    ]);

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

#[cfg(test)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_size() {
        // Create a sample transaction
        let tx_in_1 = TxIn {
            previous_output: [0u8; 32],
            script_length: 10,
            signature_script: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
            sequence: 0,
        };

        let tx_in_2 = TxIn {
            previous_output: [0u8; 32],
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
