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

pub struct OutPoint {
    hash: [u8; 32],
    index: u32,
}

pub struct TxInWitness {
    witness: Vec<u8>,
}
