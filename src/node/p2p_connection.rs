use crate::node::message::{MessageHeader, MessagePayload};
use bs58::{decode, encode};
use std::io::Write;
use std::net::TcpStream;
use std::time::Duration;

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
        let payload_size = std::mem::size_of::<MessagePayload>(); // let payload_size = payload_str.len();

        let header = MessageHeader::new(payload_size as u32);
        let header_str = header.to_string();
        let header_size = std::mem::size_of::<MessageHeader>(); //let header_size = header_str.len();

        let total_size: usize = header_size + payload_size;
        let mut buffer = vec![0; total_size];

        //   buffer[..header_size].copy_from_slice(header_str.as_bytes());
        //  buffer[header_size..].copy_from_slice(payload_str.as_bytes());
        self.tcp_stream
            .write(&buffer[..])
            .map_err(|e| e.to_string())?;
        Ok(())
    }
}
