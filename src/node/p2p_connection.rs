use std::io::{Read, Write};
use crate::node::message::{MessageHeader, MessagePayload, Encoding};
use std::net::TcpStream;
use std::time::Duration;
use std::vec;

use bitcoin_hashes::{sha256, Hash};


pub struct P2PConnection {
    peer_address: String,
    tcp_stream: TcpStream,
}

fn double_sha256(data: &[u8]) -> sha256::Hash {
    let hash = sha256::Hash::hash(data);
    sha256::Hash::hash(hash.as_byte_array())
}

impl P2PConnection {
    pub fn connect(addr: &String) -> Result<Self, String> {
        // TODO: save the peers that not pass the timeout
        let tcp_stream = TcpStream::connect_timeout(&addr.parse().unwrap(), Duration::from_secs(5))
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

        let mut buffer_total = vec![0; total_size];
        header.encode(&mut buffer_total[..header_size])?;
        let mut buffer_payload = vec![0; payload_size];
        payload.encode(&mut buffer_payload[..])?;

        let hash = double_sha256(&buffer_payload);
        let mut payload_checksum: [u8; 4] = [0u8; 4];
        payload_checksum.copy_from_slice(&hash[..4]);

        buffer_total[20..24].copy_from_slice(&payload_checksum[..]);
        buffer_total[24..].copy_from_slice(&buffer_payload[..]);

        self.tcp_stream
            .write(&buffer_total[..])
            .map_err(|e| e.to_string())?;
        Ok(())
    }
    pub fn receive(&mut self) -> Result<(String, MessagePayload), String> {
        let mut buffer = [0u8; 1000];
        self.tcp_stream.read(&mut buffer).map_err(|e| e.to_string())?;
        Ok((
            self.peer_address.clone(),
            receive_internal(&mut buffer).unwrap(),
        ))

        // |payloads| (self.peer_address.clone(), payloads)
    }
}

fn decode_message<T: Encoding<T>>(cmd: &String, data: &[u8]) -> Result<Option<T>, String> {
    T::decode(cmd, &data[..]).map(|t| Some(t))
}


fn receive_internal(buf: &mut [u8]) -> Result<MessagePayload, String> {
    // Parse the header fields
    let header: MessageHeader = decode_message(&String::default(), &buf[..24]).unwrap().unwrap();
    if header.magic_number != 118034699 {
        return Err(format!("Invalid magic number: 0x{:08x}", header.magic_number));
    }
    let command_name = String::from_utf8_lossy(&header.command_name).trim_end_matches('\0').to_owned();
    let payload = decode_message(&command_name, &buf[24..(24 + header.payload_size as usize)]).unwrap().unwrap();

    Ok(payload)
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::message::version::PayloadVersion;
    use crate::utils::MockTcpStream;

    #[test]
    fn test_read() {
        let mut mock_read_data = Vec::new();
        mock_read_data.extend(0x0b110907u32.to_le_bytes()); // magic number
        mock_read_data.extend("version\0\0\0\0\0".as_bytes()); // command name
        mock_read_data.extend(0x4u32.to_le_bytes()); // payload size
        mock_read_data.extend(0x5df6e0e2u32.to_le_bytes()); // checksum
        mock_read_data.extend(0xf0f0f000u32.to_le_bytes()); // payload

        let mut mock = MockTcpStream {
            read_data: mock_read_data,
            write_data: Vec::new(),
        };
        let mut buffer = [0u8; 100];
        // only write the bytes of mock_read_data
        mock.read(&mut buffer[..]).unwrap();
        let _ = receive_internal(&mut buffer).unwrap();
    }

    #[test]
    fn send_and_read() -> Result<(), String> {
        let mut conn = P2PConnection::connect(&"195.201.126.87:18333".to_string()).unwrap();
        let payload_version_message = MessagePayload::Version(PayloadVersion::default_version());
        conn.send(&payload_version_message).unwrap();
        let received_messages = conn.receive()?;
        if let MessagePayload::Version(payload_version) = received_messages.1 {
            assert_eq!(payload_version.addr_trans_port, 0 /* default_version */);
        }
        Ok(())
    }
}
