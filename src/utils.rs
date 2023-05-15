use std::io;
use std::io::{Read, Write};
use bitcoin_hashes::{sha256, Hash};

pub fn get_offset(buff: &[u8]) -> usize {
    let i: u8 = buff[0];

    if i == 0xfdu8 as u8 {
        2 as usize
    } else if i == 0xfeu8 as u8 {
        4 as usize
    } else if i == 0xffu8 as u8 {
        8 as usize
    } else {
        1 as usize // EDU PROBA CON 1 XD O.o
    }
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


pub fn read_varint<R: Read>(reader: &mut R) -> Result<usize, String> {
    let mut buffer = [0u8; 8];
    reader.read_exact(&mut buffer[0..1])
        .map_err(|err| format!("Failed to read varint: {}", err))?;

    let value = match buffer[0] {
        0xfd => {
            reader.read(&mut buffer[0..2])
                .map_err(|err| format!("Failed to read varint: {}", err))?;
            u64::from_le_bytes([buffer[0], buffer[1], 0, 0, 0, 0, 0, 0])
        }
        0xfe => {
            reader.read(&mut buffer[0..4])
                .map_err(|err| format!("Failed to read varint: {}", err))?;
            u64::from_le_bytes([buffer[0], buffer[1], buffer[2], buffer[3], 0, 0, 0, 0])
        }
        0xff => {
            reader.read(&mut buffer[0..8])
                .map_err(|err| format!("Failed to read varint: {}", err))?;
            u64::from_le_bytes([
                buffer[0], buffer[1], buffer[2], buffer[3], buffer[4], buffer[5], buffer[6],
                buffer[7],
            ])
        }
        _ => u64::from(buffer[0]),
    };


    Ok(value as usize)
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
    use std::io::Cursor;

    #[test]
    fn test_read_varint() {
        // Test case 1: Single-byte integer (0x7f)
        let input1 = &[0x7f];
        let mut cursor1 = Cursor::new(input1);
        assert_eq!(read_varint(&mut cursor1).unwrap(), 0x7f);

        // Test case 2: Two-byte integer (0xfd0123)
        let input2 = &[0xfd, 0x23, 0x01];
        let mut cursor2 = Cursor::new(input2);
        assert_eq!(read_varint(&mut cursor2).unwrap(), 0x0123);

        // Test case 3: Four-byte integer (0xfeabcdef)
        let input3 = &[0xfe, 0xef, 0xcd, 0xab];
        let mut cursor3 = Cursor::new(input3);
        assert_eq!(read_varint(&mut cursor3).unwrap(), 0xabcdef);

        // Test case 4: Eight-byte integer (0xff1234567890abcdef)
        let input4 = &[0xff, 0xef, 0xcd, 0xab, 0x90, 0x78, 0x56, 0x34, 0x12];
        let mut cursor4 = Cursor::new(input4);
        assert_eq!(read_varint(&mut cursor4).unwrap(), 0x1234567890abcdef);
    }
}
