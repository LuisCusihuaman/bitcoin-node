use super::{MessagePayload, TxStatus};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PayloadTxStatus {
    pub tx_id: [u8; 32],
    pub status: TxStatus,
}

impl PayloadTxStatus {
    pub fn size(&self) -> usize {
        let mut size: usize = 0;

        size += self.tx_id.len();
        size += 1; // status is encoded as a single byte

        size
    }

    pub fn encode(&self, buffer: &mut [u8]) {
        let mut encoded = Vec::new();

        encoded.extend(self.tx_id);

        let status = encode_status(self.status.clone());
        encoded.extend(status.to_be_bytes());

        buffer.copy_from_slice(&encoded)
    }
}

pub fn decode_send_tx_status(buffer: &[u8]) -> Result<MessagePayload, String> {
    let mut tx_id = [0u8; 32];
    tx_id.copy_from_slice(&buffer[0..32]);

    let status = decode_status(&buffer[32]);

    Ok(MessagePayload::TxStatus(PayloadTxStatus { tx_id, status }))
}

fn decode_status(byte: &u8) -> TxStatus {
    match byte {
        0 => TxStatus::Confirmed,
        1 => TxStatus::Unconfirmed,
        _ => TxStatus::Unknown,
    }
}

fn encode_status(status: TxStatus) -> u8 {
    match status {
        TxStatus::Confirmed => 0,
        TxStatus::Unconfirmed => 1,
        _ => 2,
    }
}
