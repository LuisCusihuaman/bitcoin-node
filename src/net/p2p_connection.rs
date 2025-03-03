use crate::logger::log;
use crate::net::message::{Encoding, MessageHeader, MessagePayload};
use crate::utils::double_sha256;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::mpsc::Sender;
use std::thread;
use std::time::Duration;
use std::vec;

#[derive(Debug)]
pub struct P2PConnection {
    pub handshaked: bool,
    pub peer_address: String,
    pub tcp_stream: TcpStream,
    pub logger_tx: Sender<String>,
}

impl Clone for P2PConnection {
    fn clone(&self) -> Self {
        P2PConnection {
            handshaked: self.handshaked,
            peer_address: self.peer_address.clone(),
            tcp_stream: self.tcp_stream.try_clone().unwrap(),
            logger_tx: self.logger_tx.clone(),
        }
    }
}

impl P2PConnection {
    pub fn connect(addr: &str, logger_tx: Sender<String>) -> Result<Self, String> {
        // TODO: save the peers that not pass the timeout
        let tcp_stream = TcpStream::connect_timeout(&addr.parse().unwrap(), Duration::from_secs(5))
            .map_err(|e| e.to_string())?;

        tcp_stream.set_nonblocking(true).unwrap();

        Ok(Self {
            logger_tx,
            handshaked: true,
            peer_address: addr.to_owned(),
            tcp_stream,
        })
    }
    pub fn send(&mut self, payload: &MessagePayload) -> Result<(), String> {
        let command_name_bytes = payload.command_name().as_bytes();
        let mut command_name = [0; 12];
        command_name[..command_name_bytes.len()].copy_from_slice(command_name_bytes);
        let payload_size = payload.size_of();
        let header = MessageHeader::new(0x0b110907_u32, command_name, payload_size as u32);
        let header_size = header.size_of();
        let total_size = header_size + payload_size;

        let mut buffer_total = vec![0; total_size];
        header.encode(&mut buffer_total[..header_size])?;
        let mut buffer_payload = vec![0; payload_size];
        payload.encode(&mut buffer_payload[..])?;

        let hash = double_sha256(&buffer_payload);
        let mut payload_checksum: [u8; 4] = [0u8; 4];
        payload_checksum.copy_from_slice(&hash[..4]);

        buffer_total[20..24].copy_from_slice(&payload_checksum[..]);
        buffer_total[24..].copy_from_slice(&buffer_payload[..]);

        thread::sleep(Duration::from_millis(350)); // Strategy to not overload server limit rate
        log(
            self.logger_tx.clone(),
            format!(
                "Sending {} to {}",
                payload.command_name(),
                self.peer_address.as_str()
            ),
        );

        self.tcp_stream
            .write(&buffer_total[..])
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn receive(&mut self) -> (String, Vec<MessagePayload>) {
        let mut buffer = vec![0u8; 1_000_000];
        let mut received_bytes = Vec::new();
        let mut is_finished = false;

        while !is_finished {
            thread::sleep(Duration::from_millis(350));

            match self.tcp_stream.read(&mut buffer) {
                Ok(bytes_read) => {
                    if bytes_read == 0 {
                        // Sender has finished sending messages
                        is_finished = true;
                    } else {
                        buffer.resize(bytes_read, 0); // Resize the buffer to the actual number of bytes read
                        received_bytes.extend(&buffer[..bytes_read]);
                    }
                }
                Err(ref err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    // Resource temporarily unavailable, wait or perform other tasks
                    break;
                }
                Err(err) => {
                    log(
                        self.logger_tx.clone(),
                        format!("Error reading from TCP stream: {}", err),
                    );
                    break;
                }
            }
        }

        let messages: Vec<MessagePayload> =
            parse_messages_from(&mut received_bytes, self.logger_tx.clone());
        (self.peer_address.clone(), messages)
    }

    pub fn handshaked(&mut self) {
        self.handshaked = true;
    }
}

fn parse_messages_from(buf: &mut Vec<u8>, logger_tx: Sender<String>) -> Vec<MessagePayload> {
    let mut messages = Vec::new();
    let mut cursor = 0;
    while cursor < buf.len() {
        // Parse the header fields
        let header: MessageHeader =
            match decode_message(&String::default(), &buf[cursor..(cursor + 24)]) {
                Ok(header) => header,
                Err(_err) => continue,
            };

        let command_name = String::from_utf8_lossy(&header.command_name)
            .trim_end_matches('\0')
            .to_owned();

        if header.magic_number != 118034699 {
            log(
                logger_tx,
                format!("Invalid magic number: 0x{:08x}", header.magic_number),
            );
            break;
        }

        let mut payload_size = header.payload_size as usize;

        payload_size = if buf.len() < (payload_size + 24) {
            buf.len() - 24 - cursor
        } else {
            payload_size
        };

        let end_index = cursor + 24 + payload_size;
        if end_index > buf.len() {
            log(logger_tx, format!("Invalid end index: {}", end_index));
            break; // the last message has more bytes than received
        }

        match decode_message(&command_name, &buf[(cursor + 24)..end_index]) {
            Ok(payload) => {
                messages.push(payload);
            }
            Err(err) => {
                log(
                    logger_tx.clone(),
                    format!("Error decoding message: {}", err),
                );
            }
        }
        cursor += 24 + payload_size;
    }

    messages
}

fn decode_message<T: Encoding<T>>(cmd: &str, data: &[u8]) -> Result<T, String> {
    T::decode(cmd, data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logger::Logger;
    use crate::net::message::get_headers::PayloadGetHeaders;
    use crate::net::message::version::PayloadVersion;
    use crate::utils::MockTcpStream;
    use std::thread;

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
        //let _ = parse_messages_from(&mut buffer);
    }

    #[test]
    fn send_and_read() -> Result<(), String> {
        let logger = Logger::mock_logger();

        let mut conn = P2PConnection::connect(&"5.9.73.173:18333".to_string(), logger.tx).unwrap();
        let payload_version_message = MessagePayload::Version(PayloadVersion::default_version());
        conn.send(&payload_version_message).unwrap();
        conn.send(&MessagePayload::Verack).unwrap();

        thread::sleep(Duration::from_secs(1));

        let (_, messages) = conn.receive();

        for message in messages.iter() {
            println!("Received message: {:?}", message.command_name());
        }

        assert_ne!(messages.len(), 0);
        Ok(())
    }

    #[test]
    fn send_first_get_headers_and_response() -> Result<(), String> {
        // Handshake
        let logger = Logger::mock_logger();
        let mut conn = P2PConnection::connect(&"5.9.73.173:18333".to_string(), logger.tx).unwrap();
        let payload_version_message = MessagePayload::Version(PayloadVersion::default_version());
        conn.send(&payload_version_message).unwrap();
        conn.send(&MessagePayload::Verack).unwrap();

        thread::sleep(Duration::from_secs(1));

        let (_, first_messages) = conn.receive();
        for message in first_messages.iter() {
            println!("Received message: {:?}", message.command_name());
        }

        // Create getheaders message
        let hash_block_genesis: [u8; 32] = [
            0x00, 0x00, 0x00, 0x00, 0x09, 0x33, 0xea, 0x01, 0xad, 0x0e, 0xe9, 0x84, 0x20, 0x97,
            0x79, 0xba, 0xae, 0xc3, 0xce, 0xd9, 0x0f, 0xa3, 0xf4, 0x08, 0x71, 0x95, 0x26, 0xf8,
            0xd7, 0x7f, 0x49, 0x43,
        ];

        let stop_hash = [0u8; 32];

        let get_headers_message = MessagePayload::GetHeaders(PayloadGetHeaders::new(
            70015,
            1,
            hash_block_genesis.to_vec(),
            stop_hash.to_vec(),
        ));

        // Send getheaders message
        conn.send(&get_headers_message)?;

        // Receive headers message
        let (_ip_address, _response) = conn.receive();

        // TODO check response
        Ok(())
    }
}
