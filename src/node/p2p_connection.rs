use crate::node::message::{MessageHeader, MessagePayload};
use bs58::{decode, encode};
use std::io::Write;
use std::net::TcpStream;
use std::time::Duration;

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
}
