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
