use crate::net::message::tx::Tx;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PayloadSendTx {
    tx: Tx,
}

impl PayloadSendTx {

    pub fn encode(&self, buffer: &mut [u8]){
        // encode UTXO
    }
}
    


pub fn decode_send_tx(buffer: &mut [u8]){
    // decode UTXO
}