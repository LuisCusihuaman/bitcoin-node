use super::MessagePayload;
use crate::utils::*;
use std::vec;

pub fn decode_inv(buffer: &[u8]) -> Result<MessagePayload, String> {
    let _count = read_varint(&mut &buffer[0..])?;
    let offset = get_offset(&buffer[..]);

    let chunked = buffer[offset..].chunks(36);
    let mut inv = vec![];

    for bufercito in chunked.clone() {
        match decode_inventory(bufercito) {
            Some(block) => {
                inv.extend(block);
            }
            None => continue,
        }
    }

    Ok(MessagePayload::Inv(inv))
}

fn decode_inventory(buffer: &[u8]) -> Option<Vec<u8>> {
    if buffer.len() != 36 {
        return None;
    }
    Some(buffer.to_vec())
}
