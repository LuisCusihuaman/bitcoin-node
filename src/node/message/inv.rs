use super::MessagePayload;
use crate::utils::*;
use std::vec;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PayloadInv {
    pub count: usize,
    pub inv_type: u32,
    pub invs: Vec<u8>,
}

pub fn decode_inv(buffer: &[u8]) -> Result<MessagePayload, String> {
    let count = read_varint(&mut &buffer[0..]);
    let offset = get_offset(buffer);
    let inv_type = read_u32_le(&buffer[offset..], 0); //TODO: are the same for blocks only, but refactor for tx
    let chunked = buffer[offset..].chunks(36);
    let mut invs = vec![];

    for bufercito in chunked.clone() {
        match decode_inventory(bufercito) {
            Some(block) => {
                invs.extend(block);
            }
            None => continue,
        }
    }

    let inv = PayloadInv {
        count,
        inv_type,
        invs,
    };

    Ok(MessagePayload::Inv(inv))
}

fn decode_inventory(buffer: &[u8]) -> Option<Vec<u8>> {
    if buffer.len() != 36 {
        return None;
    }
    Some(buffer.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_inventory() {
        let expected_inv = PayloadInv {
            count: 500,
            inv_type: 2,
            invs: vec![
                2, 0, 0, 0, 6, 18, 142, 135, 190, 139, 27, 77, 234, 71, 167, 36, 125, 85, 40, 210,
                112, 44, 150, 130, 108, 122, 100, 132, 151, 231, 115, 184, 0, 0, 0, 0,
            ],
        };

        let buf = [
            253, 244, 1, 2, 0, 0, 0, 6, 18, 142, 135, 190, 139, 27, 77, 234, 71, 167, 36, 125, 85,
            40, 210, 112, 44, 150, 130, 108, 122, 100, 132, 151, 231, 115, 184, 0, 0, 0, 0,
        ];

        let result = match decode_inv(&buf) {
            Ok(MessagePayload::Inv(inv)) => inv,
            _ => PayloadInv {
                count: 0,
                inv_type: 2,
                invs: vec![],
            },
        };

        assert_eq!(result, expected_inv);
    }
}
