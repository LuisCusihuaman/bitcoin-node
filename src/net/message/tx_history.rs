use crate::utils::get_le_varint;
use crate::utils::get_offset;
use crate::utils::read_varint;

use super::tx::decode_internal_tx;
use super::tx::Tx;
use super::MessagePayload;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PayloadTxHistory {
    pub pk_hash: Vec<u8>,
    pub txns_count: usize,
    pub txns: Vec<Tx>,
}

impl PayloadTxHistory {
    pub fn encode(&self, buffer: &mut [u8]) {
        let mut encoded: Vec<u8> = Vec::new();


        let count_bytes = get_le_varint(self.txns_count);
        encoded.extend(&count_bytes);

        for tx in &self.txns {
            let mut empty = vec![];
            let tx = tx.encode(&mut empty);
            encoded.extend(&tx);
        }

        encoded.extend(&self.pk_hash);

        buffer.copy_from_slice(&encoded);
    }

    pub fn size(&self) -> usize {
        let mut size: usize = 0;

        size += self.pk_hash.len(); // pk_hash

        size += get_le_varint(self.txns_count).len(); // variable size

        for tx in &self.txns {
            size += tx.size();
        }
        size
    }
}

pub fn decode_tx_history(buffer: &[u8]) -> Result<MessagePayload, String> {
    let mut offset = 0;

    let txns_count = read_varint(&buffer[offset..]);
    offset += get_offset(&buffer[offset..]);

    let mut txns = Vec::new();
    for _ in 0..txns_count {
        let tx = decode_internal_tx(buffer, &mut offset).unwrap();
        txns.push(tx);
    }

    let pk_hash = buffer[offset..offset+20].to_vec();
    offset += 20;

    let payload = PayloadTxHistory { pk_hash, txns_count, txns };

    Ok(MessagePayload::TxHistory(payload))
}
