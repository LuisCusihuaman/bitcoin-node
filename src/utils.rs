use crate::net::message::block::Block;
use bitcoin_hashes::{sha256, Hash};
use chrono::prelude::*;
use chrono::NaiveDate;
use std::io;
use std::io::{Read, Write};

// get pubkeyhash from an addr in base58Check
pub fn pk_hash_from_addr(addr: &str) -> [u8; 20] {
    let pub_addr_hashed = match bs58::decode(addr).with_check(None).into_vec() {
        Ok(v) => v,
        Err(_) => vec![0; 20],
    };

    let mut address_bytes = [0; 20];
    address_bytes.copy_from_slice(&pub_addr_hashed[1..]);

    address_bytes
}

// Returns the address in base58Check (34 letras)
pub fn get_address_base58(pub_hash_key: [u8; 20]) -> String {
    let version = [0x6f];
    let input = [&version[..], &pub_hash_key[..]].concat();

    bs58::encode(input).with_check().into_string()
}

pub fn get_time() -> String {
    let local: DateTime<Local> = Local::now();
    local.format("%H:%M:%S").to_string()
}

pub fn get_hash_block_genesis() -> [u8; 32] {
    let mut hash_block_genesis: [u8; 32] = [
        0x00, 0x00, 0x00, 0x00, 0x09, 0x33, 0xea, 0x01, 0xad, 0x0e, 0xe9, 0x84, 0x20, 0x97, 0x79,
        0xba, 0xae, 0xc3, 0xce, 0xd9, 0x0f, 0xa3, 0xf4, 0x08, 0x71, 0x95, 0x26, 0xf8, 0xd7, 0x7f,
        0x49, 0x43,
    ];
    hash_block_genesis.reverse();

    hash_block_genesis
}

pub fn check_blockchain_integrity(blocks: Vec<Block>) -> bool {
    if blocks.is_empty() {
        return true;
    }

    let mut index = 1;
    while index < blocks.len() {
        let prev_block = &blocks[index - 1];
        let actual_block = &blocks[index];

        if actual_block.get_prev() != prev_block.get_hash() {
            return false;
        }

        index += 1;
    }
    true
}

pub fn read_le(bytes: &[u8]) -> usize {
    let mut result: usize = 0;
    let len_bytes = bytes.len();

    for i in 0..len_bytes {
        result |= (bytes[i] as usize) << (i * 8);
    }
    result
}

pub fn read_be(buffer: &[u8]) -> usize {
    let mut result = 0;
    for i in 0..buffer.len() {
        result += (buffer[i] as usize) << (8 * (buffer.len() - i - 1));
    }
    result
}

pub fn double_sha256(data: &[u8]) -> sha256::Hash {
    if data.is_empty() {
        let empty_hash = sha256::Hash::hash("".as_bytes());
        return sha256::Hash::hash(empty_hash.as_byte_array());
    }
    let hash = sha256::Hash::hash(data);
    sha256::Hash::hash(hash.as_byte_array())
}

pub fn copy_bytes_to_array(source: &[u8], target: &mut [u8]) {
    target.copy_from_slice(source);
}

pub fn read_u32_le(buffer: &[u8], offset: usize) -> u32 {
    let bytes = &buffer[offset..offset + 4];
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

pub fn read_u64_le(buffer: &[u8], offset: usize) -> u64 {
    let bytes = &buffer[offset..offset + 8];
    u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ])
}

pub fn read_u16_be(buffer: &[u8], offset: usize) -> u16 {
    let bytes = &buffer[offset..offset + 2];
    u16::from_be_bytes([bytes[0], bytes[1]])
}

pub fn read_string(buffer: &[u8], offset: usize, length: usize) -> String {
    String::from_utf8(buffer[offset..offset + length].to_vec()).unwrap()
}

pub fn get_offset(buff: &[u8]) -> usize {
    let i: u8 = buff[0];

    if i == 0xfdu8 {
        3_usize
    } else if i == 0xfeu8 {
        5_usize
    } else if i == 0xffu8 {
        9_usize
    } else {
        1_usize
    }
}

pub fn get_le_varint(value: usize) -> Vec<u8> {
    let mut result = vec![];

    if value < 0xfd {
        result.push(value as u8);
    } else if value <= 0xffff {
        result.push(0xfd);
        result.extend_from_slice(&value.to_le_bytes()[0..2]);
    } else if value <= 0xffffffff {
        result.push(0xfe);
        result.extend_from_slice(&value.to_le_bytes()[0..4]);
    } else {
        result.push(0xff);
        result.extend_from_slice(&value.to_le_bytes()[0..8]);
    }
    result
}

pub fn read_varint(buff: &[u8]) -> usize {
    match buff[0] {
        0xfd => u16::from_le_bytes([buff[1], buff[2]]) as usize,
        0xfe => u32::from_le_bytes([buff[1], buff[2], buff[3], buff[4]]) as usize,
        0xff => u64::from_le_bytes([
            buff[1], buff[2], buff[3], buff[4], buff[5], buff[6], buff[7], buff[8],
        ]) as usize,
        _ => buff[0] as usize,
    }
}

pub fn date_to_timestamp(date_str: &str) -> Option<u32> {
    if let Ok(parsed_date) = NaiveDate::parse_from_str(date_str, "%Y-%m-%d") {
        if let Some(datetime) = parsed_date.and_hms_opt(0, 0, 0) {
            let timestamp = datetime.timestamp() as u32;
            return Some(timestamp);
        }
    }
    None
}

pub fn array_to_hex(buff: &[u8]) -> String {
    let mut result = String::new();
    for byte in buff {
        result.push_str(&format!("{:02x}", byte));
    }
    result
}

pub fn little_endian_to_int(bytes: &[u8; 32]) -> u128 {
    let mut result: u128 = 0;

    for i in 0..16 {
        result |= u128::from(bytes[i]) << (8 * i);
    }
    result
}

pub fn take_elements_every<T: Clone, G, F>(items: Vec<T>, step: usize, mut apply_fn: F) -> Vec<G>
where
    G: Clone,
    F: FnMut(&mut T) -> G,
{
    let mut result = Vec::new();
    for (index, item) in items.into_iter().enumerate() {
        if (index + 1) % step == 0 {
            let mut cloned_item = item.clone();
            let transformed_item = apply_fn(&mut cloned_item);
            result.push(transformed_item);
        }
    }
    result
}

/// MockTcpStream es una mock que implementa los traits Read y Write, los mismos que implementa el TcpStream
pub struct MockTcpStream {
    pub(crate) read_data: Vec<u8>,
    pub(crate) write_data: Vec<u8>,
}

impl Read for MockTcpStream {
    /// Lee bytes del stream hasta completar el buffer y devuelve cuantos bytes fueron leidos
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.read_data.as_slice().read(buf)
    }
}

impl Write for MockTcpStream {
    /// Escribe el valor del buffer en el stream y devuelve cuantos bytes fueron escritos
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_data.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.write_data.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_array_to_hex_format() {
        // Empty array
        let array_1 = vec![];
        let result_1 = array_to_hex(&array_1);

        let expected_1 = "".to_string();
        assert!(result_1 == expected_1);

        // Array id
        let array_2 = [
            137, 85, 169, 121, 99, 223, 138, 234, 189, 76, 239, 70, 217, 238, 236, 133, 13, 246,
            181, 56, 30, 176, 253, 102, 55, 78, 134, 49, 5, 56, 149, 31,
        ];
        let result_2 = array_to_hex(&array_2);

        let expeced_2 =
            "8955a97963df8aeabd4cef46d9eeec850df6b5381eb0fd66374e86310538951f".to_string();
        assert!(result_2 == expeced_2);

        // Array tx raw
        let array_3 = [
            1, 0, 0, 0, 1, 123, 204, 137, 18, 138, 54, 143, 112, 41, 75, 105, 9, 20, 115, 168, 198,
            197, 241, 39, 23, 24, 252, 55, 172, 80, 134, 255, 92, 89, 109, 230, 188, 0, 0, 0, 0,
            106, 71, 48, 68, 2, 32, 90, 170, 121, 238, 37, 6, 132, 231, 219, 177, 232, 205, 193,
            91, 19, 0, 78, 80, 3, 220, 74, 72, 193, 233, 60, 142, 7, 146, 55, 176, 114, 103, 2, 32,
            77, 132, 142, 31, 180, 80, 208, 220, 209, 113, 149, 161, 101, 31, 48, 203, 6, 231, 128,
            247, 187, 43, 252, 11, 99, 202, 70, 115, 113, 45, 3, 186, 1, 33, 2, 20, 28, 142, 103,
            244, 6, 181, 130, 126, 50, 140, 1, 132, 188, 50, 59, 67, 144, 104, 43, 227, 97, 153,
            206, 105, 1, 12, 47, 189, 173, 128, 172, 255, 255, 255, 255, 2, 160, 134, 1, 0, 0, 0,
            0, 0, 25, 118, 169, 20, 181, 51, 138, 19, 120, 118, 0, 187, 24, 163, 236, 151, 149,
            117, 93, 82, 212, 10, 107, 236, 136, 172, 128, 209, 16, 0, 0, 0, 0, 0, 25, 118, 169,
            20, 100, 227, 171, 27, 188, 160, 210, 116, 110, 81, 97, 65, 97, 169, 21, 128, 49, 207,
            184, 237, 136, 172, 0, 0, 0, 0,
        ];
        let result_3 = array_to_hex(&array_3);

        let expected_3 = "01000000017bcc89128a368f70294b69091473a8c6c5f1271718fc37ac5086ff5c596de6bc000000006a47304402205aaa79ee250684e7dbb1e8cdc15b13004e5003dc4a48c1e93c8e079237b0726702204d848e1fb450d0dcd17195a1651f30cb06e780f7bb2bfc0b63ca4673712d03ba012102141c8e67f406b5827e328c0184bc323b4390682be36199ce69010c2fbdad80acffffffff02a0860100000000001976a914b5338a13787600bb18a3ec9795755d52d40a6bec88ac80d11000000000001976a91464e3ab1bbca0d2746e51614161a9158031cfb8ed88ac00000000".to_string();
        assert!(result_3 == expected_3);
    }

    #[test]
    fn test_read_varint() {
        // Test case 1: Single-byte integer
        let input1 = [0x7f];
        assert_eq!(read_varint(&input1), 0x7f);

        // Test case 2: Two-byte integer
        let input2 = [0xfd, 0x23, 0x01];
        assert_eq!(read_varint(&input2), 0x0123);

        // Test case 3: Four-byte integer
        let input3 = [0xfe, 0xef, 0xef, 0xcd, 0xab];
        assert_eq!(read_varint(&input3), 0xabcdefef);

        // Test case 4: Eight-byte integer
        let input4 = [0xff, 0xef, 0xcd, 0xab, 0x90, 0x78, 0x56, 0x34, 0x12];
        assert_eq!(read_varint(&input4), 0x1234567890abcdef);
    }

    #[test]
    fn test_get_le_varint() {
        // Test case 1: integer is single-byte varint
        assert_eq!(get_le_varint(1), vec![1]);

        // Test case 2: integer is two-byte varint
        assert_eq!(get_le_varint(500), vec![253, 244, 1]);

        // Test case 3: integer is four-byte varint
        assert_eq!(get_le_varint(100000), vec![254, 160, 134, 1, 0]);

        // Test case 4: integer is eight-byte varint
        assert_eq!(
            get_le_varint(10000000000),
            vec![255, 0, 228, 11, 84, 2, 0, 0, 0]
        );
    }

    #[test]
    fn test_take_elements_every() {
        let items = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let step = 3;
        let result = take_elements_every(items, step, |item| *item * 2);
        assert_eq!(result, vec![6, 12, 18]);
    }
}
