use crate::node::utxo::Utxo;


#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PayloadSendUtxo {
    utxos: Vec<Utxo>,
}

impl PayloadSendUtxo {

    pub fn encode(&self, buffer: &mut [u8]){
        // encode UTXO
    }
}
    


pub fn decode_send_utxos(buffer: &mut [u8]){
    // decode UTXO
}