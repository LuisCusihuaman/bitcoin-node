use crate::net::message::MessagePayload;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PayloadGetUtxo {
    pub address: String, 
}

impl PayloadGetUtxo {

    pub fn encode(&self, buffer: &mut [u8]) {
        // encode address
        let offset = 0;
        let address = self.address.as_bytes();
        buffer[offset..offset+20].copy_from_slice(address);
    }
}
    

pub fn decode_get_utxos(buffer: &[u8])-> Result<MessagePayload, String>{
    let address = bs58::encode(&buffer[0..20]).into_string(); // ver como lo recibimos, esto puede cambiar
 
    let payload = PayloadGetUtxo{address};

    Ok(MessagePayload::GetUTXOs(payload))
}