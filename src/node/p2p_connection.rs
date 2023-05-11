use crate::node::message::{MessageHeader, MessagePayload};
use std::io::{Cursor, Read, Write};
use std::net::TcpStream;
use std::time::Duration;
use std::vec;

use bitcoin_hashes::sha256;
use bitcoin_hashes::Hash;
use bs58::{decode, encode};

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
        let payload_checksum = payload.checksum()?;
        buffer[20..24].copy_from_slice(&payload_checksum[..]);
        //write payload message
        payload.encode(&mut buffer[header_size..])?;

        self.tcp_stream
            .write(&buffer[..])
            .map_err(|e| e.to_string())?;
        Ok(())
    }
    pub fn receive(&mut self) -> (String, Vec<MessagePayload>) {
        let mut buf = [0u8; 24];
        self.tcp_stream
            .read_exact(&mut buf)
            .map_err(|e| e.to_string())
            .unwrap();
        (
            self.peer_address.clone(),
            receive_internal(&mut buf).unwrap(),
        )

        // |payloads| (self.peer_address.clone(), payloads)
    }
}

fn receive_internal(buf: &mut [u8]) -> Result<Vec<MessagePayload>, String> {
    // Parse the header fields
    let magic_number = read_u32_le(&buf[0..4]);
    let command_name = String::from_utf8_lossy(&buf[4..16])
        .trim_end_matches('\0')
        .to_owned();
    let payload_size = read_u32_le(&buf[16..20]);
    let _checksum = sha256::Hash::hash(&buf[20..24]);

    // Check the magic number
    if magic_number != 0x0b110907 {
        return Err(format!("Invalid magic number: 0x{:08x}", magic_number));
    }
    //Read payload
    let mut payload: Vec<u8> = vec![0; payload_size as usize];

    let mut cursor = Cursor::new(&mut buf[24..]);
    cursor.read_exact(&mut payload).unwrap();

    // match with the command name and create instance of the payload
    let payload = match command_name.as_str() {
        "version" => MessagePayload::Verack, //MessagePayload::Version(0).decode(buffer) // we must a dummy valid in argument?
        "verack" => MessagePayload::Verack,
        // "ping" => MessagePayload::Ping(payload),
        // "pong" => MessagePayload::Pong(payload),
        // "addr" => MessagePayload::Addr(payload),
        // "inv" => MessagePayload::Inv(payload),
        // "getdata" => MessagePayload::GetData(payload),
        // "notfound" => MessagePayload::NotFound(payload),
        // "getblocks" => MessagePayload::GetBlocks(payload),
        // "getheaders" => MessagePayload::GetHeaders(payload),
        // "tx" => MessagePayload::Tx(payload),
        // "block" => MessagePayload::Block(payload),
        // "headers" => MessagePayload::Headers(payload),
        // "getaddr" => MessagePayload::GetAddr(payload),
        // "mempool" => MessagePayload::Mempool(payload),
        // "reject" => MessagePayload::Reject(payload),
        // "sendheaders" => MessagePayload::SendHeaders(payload),
        // "feefilter" => MessagePayload::FeeFilter(payload),
        // "filterload" => MessagePayload::FilterLoad(payload),
        // "filteradd" => MessagePayload::FilterAdd(payload),
        // "filterclear" => MessagePayload::FilterClear(payload),
        // "merkleblock" => MessagePayload::MerkleBlock(payload),
        // "cmpctblock" => MessagePayload::CmpctBlock(payload),
        // "getblocktxn" => MessagePayload::GetBlockTxn(payload),
        // "blocktxn" => MessagePayload::BlockTxn(payload),
        // "encinit" => MessagePayload::Encinit(payload),
        // "encack" => MessagePayload::Encack(payload),
        // "authchallenge" => MessagePayload::AuthChallenge(payload),
        // "authreply" => MessagePayload::AuthReply(payload),
        // "authpropose" => MessagePayload::AuthPropose(payload),
        // "unknown" => MessagePayload::Unknown(payload),
        _ => return Err(format!("Unknown command name: {}", command_name)),
    };
    Ok(vec![payload])
}

fn read_u32_le(bytes: &[u8]) -> u32 {
    assert_eq!(bytes.len(), 4);

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
        let a = receive_internal(&mut buffer).unwrap();
    }
}
