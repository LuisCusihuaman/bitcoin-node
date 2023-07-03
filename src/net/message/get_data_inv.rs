use crate::net::message::MessagePayload;
use crate::utils::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PayloadGetDataInv {
    pub count: usize, // variable size
    pub inv_type: u32,
    pub inventories: Vec<Inventory>, // variable size
}

impl PayloadGetDataInv {
    pub fn size(&self) -> usize {
        let mut size = 0;
        let count = get_le_varint(self.count);

        size += count.len(); // variable size
        size += self.count * 36; // variable size

        size
    }

    pub fn encode(&self, buffer: &mut [u8]) {
        let count = get_le_varint(self.count);
        let count_size = count.len();

        buffer[0..count_size].copy_from_slice(&count);
        let mut offset = count_size;

        for inventory in self.inventories.iter() {
            buffer[offset..offset + 36].copy_from_slice(&inventory.encode());
            offset += 36;
        }
    }
}

pub fn decode_internal_data_inv(buffer: &[u8]) -> PayloadGetDataInv {
    let count = read_varint(&buffer[0..]);
    let offset = get_offset(buffer);

    let mut inventories = Vec::new();

    for i in 0..count {
        let inv = decode_inventory(&buffer[offset + i * 36..offset + (i + 1) * 36]);

        // if inv.is_none() {
        //     return Err("Error decoding inventory".to_string());
        // }

        inventories.push(inv.unwrap());
    }

    PayloadGetDataInv {
        count,
        inv_type: inventories[0].inv_type,
        inventories,
    }
}

pub fn decode_get_data(buffer: &[u8]) -> Result<MessagePayload, String> {
    let get_data_inv = decode_internal_data_inv(buffer);
    Ok(MessagePayload::GetData(get_data_inv))
}

pub fn decode_inv(buffer: &[u8]) -> Result<MessagePayload, String> {
    let get_data_inv = decode_internal_data_inv(buffer);
    Ok(MessagePayload::Inv(get_data_inv))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Inventory {
    pub inv_type: u32,
    pub hash: Vec<u8>,
}

impl Inventory {
    pub fn encode(&self) -> Vec<u8> {
        let mut buffer = vec![0; 36];

        let mut hash = self.hash.clone();
        hash.reverse();

        buffer[0..4].copy_from_slice(&self.inv_type.to_le_bytes());
        buffer[4..].copy_from_slice(&hash);

        buffer
    }
}

fn decode_inventory(buffer: &[u8]) -> Option<Inventory> {
    if buffer.len() != 36 {
        return None;
    }

    let inv_type = read_le(&buffer[0..4]) as u32;

    let mut hash = buffer[4..].to_vec();
    hash.reverse();

    Some(Inventory { inv_type, hash })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_get_data() {
        let inventory = Inventory {
            inv_type: 2,
            hash: vec![
                6, 18, 142, 135, 190, 139, 27, 77, 234, 71, 167, 36, 125, 85, 40, 210, 112, 44,
                150, 130, 108, 122, 100, 132, 151, 231, 115, 184, 0, 0, 0, 0,
            ]
            .to_vec(),
        };

        let payload = PayloadGetDataInv {
            count: 1,
            inv_type: 2,
            inventories: vec![inventory],
        };

        let mut buffer = [0u8; 37];

        payload.encode(&mut buffer);

        let payload_expected = [
            1, 2, 0, 0, 0, 0, 0, 0, 0, 184, 115, 231, 151, 132, 100, 122, 108, 130, 150, 44, 112,
            210, 40, 85, 125, 36, 167, 71, 234, 77, 27, 139, 190, 135, 142, 18, 6,
        ];

        assert_eq!(buffer, payload_expected);
    }

    #[test]
    fn test_decode_inventory() {
        let buf = [
            2, 0, 0, 0, 0, 0, 0, 0, 184, 115, 231, 151, 132, 100, 122, 108, 130, 150, 44, 112, 210,
            40, 85, 125, 36, 167, 71, 234, 77, 27, 139, 190, 135, 142, 18, 6,
        ];

        let result = decode_inventory(&buf).unwrap();

        let expected_inv = Inventory {
            inv_type: 2,
            hash: vec![
                6, 18, 142, 135, 190, 139, 27, 77, 234, 71, 167, 36, 125, 85, 40, 210, 112, 44,
                150, 130, 108, 122, 100, 132, 151, 231, 115, 184, 0, 0, 0, 0,
            ]
            .to_vec(),
        };

        assert_eq!(result, expected_inv);
    }
}
