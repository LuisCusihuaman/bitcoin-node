use crate::node::utxo::decode;
use crate::node::utxo::Utxo;

use super::MessagePayload;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PayloadUtxosMsg {
    pub utxos: Vec<Utxo>,
}

impl PayloadUtxosMsg {
    pub fn encode(&self, buffer: &mut [u8]) {
        let mut encoded = Vec::new();

        for utxo in &self.utxos {
            encoded.extend(utxo.encode());
        }
        buffer.copy_from_slice(&encoded)
    }

    pub fn size(&self) -> usize {
        let mut size: usize = 0;

        for utxo in &self.utxos {
            size += utxo.size();
        }
        size
    }
}

pub fn decode_utxos(buffer: &[u8]) -> Result<MessagePayload, String> {
    let utxos: Vec<Utxo> = buffer
        .chunks(44)
        .map(|chunk| decode(chunk).unwrap())
        .collect();

    Ok(MessagePayload::UTXOs(PayloadUtxosMsg { utxos }))
}
