use crate::node::message::{MessageHeader, MessagePayload};
use bs58::{decode, encode};
use std::io::Write;
use std::net::TcpStream;
use std::time::Duration;
use std::io::Read;
use std::vec;

use super::message::Encoding;

pub struct P2PConnection {
    peer_address: String,
    tcp_stream: TcpStream,
}

impl P2PConnection {
    pub fn connect(addr: &String) -> Result<Self, String> {
        // TODO: save the peers that not pass the timeout
        let tcp_stream = TcpStream::connect_timeout(&addr.parse().unwrap(), Duration::from_secs(5))
            .map_err(|e| e.to_string())?;
        tcp_stream
            .set_nonblocking(true)
            .map_err(|e| e.to_string())?;
        Ok(Self {
            peer_address: addr.clone(),
            tcp_stream,
        })
    }

    pub fn send(&mut self, payload: &MessagePayload) -> Result<(), String> {
        let command_name_bytes = payload.command_name()?.as_bytes();
        let mut command_name = [0; 12];
        command_name[..command_name_bytes.len()].copy_from_slice(command_name_bytes);
        let payload_size = payload.size_of()? as usize;
        let header = MessageHeader::new(0x0b110907 as u32, command_name, payload_size as u32);
        let header_size = header.size_of()? as usize;
        let total_size = header_size + payload_size as usize;

        let mut buffer = vec![0; total_size];
        header.encode(&mut buffer[..header_size])?;
        payload.encode(&mut buffer[header_size..])?;
        self.tcp_stream
            .write(&buffer[..])
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    fn receive_internal<T: Read + Write>(&mut self, stream: &mut T) -> Result<Vec<MessagePayload>, String> {
        let mut buf = [0u8; 24];
        stream.read_exact(&mut buf).map_err(|e| e.to_string())?;

        // Parse the header fields
        let magic_number = read_u32_le(&buf[0..4]);
        let command_name = String::from_utf8_lossy(&buf[4..16]).trim_end_matches('\0').to_owned();
        let payload_size = read_u32_le(&buf[16..20]);

        // Read the payload
        let mut payload_buf = vec![0u8; payload_size as usize];
        stream.read_exact(&mut payload_buf).map_err(|e| e.to_string())?;

        // Match the command name to a payload type
        let payload = match command_name.as_str() {
            "version" => MessagePayload::Version(read_u32_le(&payload_buf)),
            "verack" => MessagePayload::Verack,
            &_ => todo!()
        };

        Ok(vec![payload])
    }

    pub fn receive(&mut self) -> (String, Vec<MessagePayload>) {
        

        // |payloads| (self.peer_address.clone(), payloads)
    }
}

fn read_u32_le(bytes: &[u8]) -> u32 {
    let mut result: u32 = 0;
    for i in 0..4 {
        result |= (bytes[i] as u32) << (i * 8);
    }
    result
}

#[cfg(test)]
mod tests {

    use super::*;
    use std::io;

    /// MockTcpStream es una mock que implementa los traits Read y Write, los mismos que implementa el TcpStream
    struct MockTcpStream {
        read_data: Vec<u8>,
        write_data: Vec<u8>,
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

    #[test]
    fn test_parse_with_valid_params() {
        let mut mock = MockTcpStream {
            read_data: "/get?name=pepito\n".as_bytes().to_vec(),
            write_data: Vec::new(),
        };

        let req = parse_internal(&mut mock);

        assert_eq!(req.path, "/get");
        assert_eq!(req.params.len(), 1);
    }
}
