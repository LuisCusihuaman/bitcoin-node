use crate::utils::write_varint_2;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PayloadGetData {
    count: usize,
    inventory: Vec<u8>,
}

impl PayloadGetData {
    pub fn new(count: usize, inventory: Vec<u8>) -> Self {
        Self { count, inventory }
    }

    pub fn size(&self) -> u64 {
        let mut size = 0;
        let count = write_varint_2(self.count);


        size += count.len(); // TODO Variable size
        size += self.inventory.len(); // TODO Variable size

        size as u64
    }

    pub fn encode(&self, buffer: &mut [u8]) {
        let count = write_varint_2(self.count);
        let count_size = count.len();

        buffer[0..count_size].copy_from_slice(&count);
        buffer[count_size..].copy_from_slice(&self.inventory);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_get_data() {
        let inventory = vec![0; 36];

        let payload = PayloadGetData::new(500, inventory);

        let mut buffer = [0u8; 36];
        payload.encode(&mut buffer);

        let payload_expected = [
            0x01, // count,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, // inventory
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];

        // assert_eq!(payload_expected, buffer);
    }
}
