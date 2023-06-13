use crate::net::message::MessagePayload;
use crate::utils::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PayloadGetDataInv {
    pub count: usize, // variable size
    pub inv_type: u32,
    pub inventories: Vec<Inventory>, // variable size
}

impl PayloadGetDataInv {
    pub fn new_with_invs_bytes(buffer: Vec<u8>) -> Self {
        let mut inv_type = 0;

        let inventories: Vec<Inventory> = buffer[4..]
            .chunks(36)
            .map(|chunk| {
                inv_type = read_le(&chunk[0..4]) as u32;

                Inventory {
                    inv_type,
                    hash: chunk[4..36].to_vec(),
                }
            })
            .collect();

        Self {
            count: inventories.len(),
            inv_type,
            inventories,
        }
    }

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

pub fn decode_data_inv(buffer: &[u8]) -> Result<MessagePayload, String> {
    let count = read_varint(&buffer[0..]);
    let offset = get_offset(buffer);

    let mut inventories = Vec::new();

    for i in 0..count {
        let inv = decode_inventory(&buffer[offset + i * 36..offset + (i + 1) * 36]);

        if inv.is_none() {
            return Err("Error decoding inventory".to_string());
        }

        inventories.push(inv.unwrap());
    }

    let inv = PayloadGetDataInv {
        count,
        inv_type: inventories[0].inv_type,
        inventories,
    };

    Ok(MessagePayload::Inv(inv))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Inventory {
    pub inv_type: u32,
    pub hash: Vec<u8>,
}

impl Inventory {
    pub fn encode(&self) -> Vec<u8> {
        let mut buffer = vec![0; 36];

        buffer[0..4].copy_from_slice(&self.inv_type.to_le_bytes());
        buffer[4..].copy_from_slice(&self.hash);

        buffer
    }
}

fn decode_inventory(buffer: &[u8]) -> Option<Inventory> {
    if buffer.len() != 36 {
        return None;
    }

    let inv_type = read_le(&buffer[0..4]) as u32;
    let hash = buffer[4..].to_vec();

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
            count: 500,
            inv_type: 2,
            inventories: vec![inventory],
        };

        let mut buffer = [0u8; 39];

        payload.encode(&mut buffer);

        let payload_expected = [
            253, 244, 1, 2, 0, 0, 0, 6, 18, 142, 135, 190, 139, 27, 77, 234, 71, 167, 36, 125, 85,
            40, 210, 112, 44, 150, 130, 108, 122, 100, 132, 151, 231, 115, 184, 0, 0, 0, 0,
        ];

        assert_eq!(buffer, payload_expected);
    }

    #[test]
    fn test_decode_inventory() {
        let expected_inv = Inventory {
            inv_type: 2,
            hash: vec![
                6, 18, 142, 135, 190, 139, 27, 77, 234, 71, 167, 36, 125, 85, 40, 210, 112, 44,
                150, 130, 108, 122, 100, 132, 151, 231, 115, 184, 0, 0, 0, 0,
            ]
            .to_vec(),
        };

        let buf = [
            2, 0, 0, 0, 6, 18, 142, 135, 190, 139, 27, 77, 234, 71, 167, 36, 125, 85, 40, 210, 112,
            44, 150, 130, 108, 122, 100, 132, 151, 231, 115, 184, 0, 0, 0, 0,
        ];

        let result = decode_inventory(&buf).unwrap();

        assert_eq!(result, expected_inv);
    }
}
