use crate::node::utxo::Utxo;

use super::MessagePayload;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PayloadUtxosMsg {
    pub utxos: Vec<Utxo>,
}

impl PayloadUtxosMsg {
    pub fn encode(&self, buffer: &mut [u8]) {
        // TODO
        // encode UTXO
    }

    pub fn size(&self) -> usize {
        let size: usize = 0;

        // TODO
        // for utxo in self.utxos {
        //     // size of each UTXO
        // }

        size
    }
}

pub fn decode_utxos(buffer: &[u8]) -> Result<MessagePayload, String> {
    // TODO
    // decode UTXO
    let payload = PayloadUtxosMsg { utxos: vec![] };
    Ok(MessagePayload::UTXOs(payload))
}
