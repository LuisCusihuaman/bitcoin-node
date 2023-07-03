use crate::net::message::MessagePayload;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PayloadGetTxHistory {
    pub address: [u8; 20],
}

impl PayloadGetTxHistory {
    pub fn encode(&self, buffer: &mut [u8]) {
        buffer.copy_from_slice(&self.address);
    }

    pub fn size(&self) -> usize {
        self.address.len()
    }
}

pub fn decode_get_tx_history(buffer: &[u8]) -> Result<MessagePayload, String> {
    let mut address = [0u8; 20];
    address.copy_from_slice(buffer);

    let payload = PayloadGetTxHistory { address };

    Ok(MessagePayload::GetTxHistory(payload))
}
