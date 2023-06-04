use crate::utils::get_le_varint;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PayloadGetData {
    count: usize,
    inventory: Vec<u8>,
}

impl PayloadGetData {
    pub fn new(count: usize, inventory: Vec<u8>) -> Self {
        Self { count, inventory }
    }

    pub fn size(&self) -> usize {
        let mut size = 0;
        let count = get_le_varint(self.count);

        size += count.len(); // variable size
        size += self.inventory.len(); // variable size

        size
    }

    pub fn encode(&self, buffer: &mut [u8]) {
        let count = get_le_varint(self.count);
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
        let inventory = [
            2, 0, 0, 0, 6, 18, 142, 135, 190, 139, 27, 77, 234, 71, 167, 36, 125, 85, 40, 210, 112,
            44, 150, 130, 108, 122, 100, 132, 151, 231, 115, 184, 0, 0, 0, 0,
        ]
        .to_vec();

        let payload = PayloadGetData::new(500, inventory);

        let mut buffer = [0u8; 39];

        payload.encode(&mut buffer);

        let payload_expected = [
            253, 244, 1, 2, 0, 0, 0, 6, 18, 142, 135, 190, 139, 27, 77, 234, 71, 167, 36, 125, 85,
            40, 210, 112, 44, 150, 130, 108, 122, 100, 132, 151, 231, 115, 184, 0, 0, 0, 0,
        ];

        assert_eq!(buffer, payload_expected);
    }
}
