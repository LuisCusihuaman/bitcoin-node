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
                inv.push(block);
            }
            None => continue,
        }
    }

    Ok(MessagePayload::Inv(inv))
}

fn decode_inventory(buffer: &[u8]) -> Option<[u8; 36]> {
    if buffer.len() != 36 {
        return None;
    }

    // let type_inv = read_u32_le(&buffer, 0);
    let mut inv: [u8; 36] = [0u8; 36];
    copy_bytes_to_array(&buffer[..], &mut inv);

    Some(inv)
}
