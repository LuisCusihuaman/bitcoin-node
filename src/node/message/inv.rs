
use super::MessagePayload;
use crate::utils::*;
use std::vec;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Inv {
    pub type_inv: u32,
    hash: [u8; 32],
}

impl Inv {
    pub fn new(type_inv: u32, hash: [u8; 32]) -> Self {
        Self { type_inv, hash }
    }
}


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

fn decode_inventory(buffer: &[u8]) -> Option<Inv> {
    if buffer.len() != 36 {
        return None;
    }

    let type_inv = read_u32_le(&buffer, 0);
    let mut hash: [u8; 32] = [0u8; 32];
    copy_bytes_to_array(&buffer[4..36], &mut hash);
    hash.reverse();

    Some(Inv::new(
        type_inv,
        hash,
    ))
}
