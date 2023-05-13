use bitcoin_hashes::sha256;
use bitcoin_hashes::Hash;
use std::io;
use std::io::{Write,Read};

type CompactSizeUint = String;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MessagePayload {
    Version(PayloadVersion),
    Verack,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct MessageHeader {
    magic_number: u32,
    //indicate the network type
    command_name: [u8; 12],
    payload_size: u32,
}

impl MessageHeader {
    pub fn new(magic_number: u32, command_name: [u8; 12], payload_size: u32) -> Self {
        MessageHeader {
            payload_size,
            magic_number,
            command_name,
        }
    }
}

pub trait Encoding<T> {
    fn size_of(&self) -> Result<u64, String>;
    fn encode(&self, buffer: &mut [u8]) -> Result<(), String>;
    fn command_name(&self) -> Result<&str, String>;
    fn decode(cmd: &String, buffer: &[u8]) -> Result<T, String>;
}

impl Encoding<MessageHeader> for MessageHeader {
    fn size_of(&self) -> Result<u64, String> {
        let size = std::mem::size_of::<MessageHeader>() as u64;
        Ok(size + 4)
    }

    fn encode(&self, buffer: &mut [u8]) -> Result<(), String> {
        buffer[0..4].copy_from_slice(&self.magic_number.to_be_bytes());

        // Write the command name as an ASCII string followed by null padding
        let command_name_bytes = self.command_name.as_ref();
        //let padding_size = 12 - command_name_bytes.len();
        buffer[4..16].copy_from_slice(command_name_bytes);
        buffer[4 + command_name_bytes.len()..16].fill(0x00);

        // Write the payload size in little-endian byte order
        buffer[16..20].copy_from_slice(&self.payload_size.to_le_bytes());

        Ok(())
    }
    fn command_name(&self) -> Result<&str, String> {
        Ok("")
    }

    fn decode(cmd: &String, buffer: &[u8]) -> Result<Self, String> {
        let mut buffer: [u8; 12] = [0u8; 12];
        buffer.copy_from_slice("".as_bytes());
        Ok(MessageHeader {
            magic_number: 118034699,
            command_name: buffer,
            payload_size: 0,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PayloadVersion {
    pub version: u32,
    services: u64,
    timestamp: u64,
    addr_recv_services: u64,
    addr_recv_ip_address: [u8; 16],
    addr_recv_port: u16,
    addr_trans_services: u64,
    pub addr_trans_ip_address: [u8; 16],
    pub addr_trans_port: u16,
    nonce: u64,
    user_agent_bytes: CompactSizeUint,
    user_agent: String,
    start_height: u32,
    relay: u8,
}

impl PayloadVersion {
    // new
    pub fn new(
        version: u32,
        services: u64,
        timestamp: u64,
        addr_recv_services: u64,
        addr_recv_ip_address: [u8; 16],
        addr_recv_port: u16,
        addr_trans_services: u64,
        addr_trans_ip_address: [u8; 16],
        addr_trans_port: u16,
        nonce: u64,
        user_agent_bytes: CompactSizeUint,
        user_agent: String,
        start_height: u32,
        relay: u8,
    ) -> Self {
        Self {
            version,
            services,
            timestamp,
            addr_recv_services,
            addr_recv_ip_address,
            addr_recv_port,
            addr_trans_services,
            addr_trans_ip_address,
            addr_trans_port,
            nonce,
            user_agent_bytes,
            user_agent,
            start_height,
            relay,
        }
    }

    pub fn default_version() -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let user_agent = String::default();
        let user_agent_bytes = user_agent.len().to_string();
        let addr_recv_ipv6_from_ipv4: [u8; 16] =
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 0];
        let addr_trans_ipv6_from_ipv4: [u8; 16] =
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 0];
        let addr_recv_port = 18333;
        let addr_trans_port = 18333;

        Self::new(
            70015, //Bitcoin Core 0.13.2 (Jan 2017)
            0,     //Unnamed receiving node
            timestamp,
            0, // Same format as the "services" field above.
            addr_recv_ipv6_from_ipv4,
            addr_recv_port,
            0, //Unnamed transmitting node
            addr_trans_ipv6_from_ipv4,
            addr_trans_port,
            0,                // If the nonce is 0, the nonce field is ignored.
            user_agent_bytes, // is a var int
            user_agent,
            0,
            0,
        )
    }
}

fn ipv4_to_ipv6_format(addr_recv: &String) -> ([u8; 16], u16) {
    match addr_recv.parse::<std::net::SocketAddr>() {
        Ok(addr) => {
            let ip: std::net::IpAddr = addr.ip();
            let port = addr.port();
            let mut ipv6 = [0u8; 16];
            match ip {
                std::net::IpAddr::V4(v4) => {
                    let octets = v4.octets();
                    ipv6[10] = 0xff;
                    ipv6[11] = 0xff;
                    ipv6[12] = octets[0];
                    ipv6[13] = octets[1];
                    ipv6[14] = octets[2];
                    ipv6[15] = octets[3];
                }
                std::net::IpAddr::V6(v6) => {
                    ipv6.copy_from_slice(&v6.octets());
                }
            }
            (ipv6, port)
        }
        Err(_) => ([0u8; 16], 0),
    }
}

impl Encoding<MessagePayload> for MessagePayload {
    fn size_of(&self) -> Result<u64, String> {
        match self {
            MessagePayload::Version(
                _, /*version and used for user_agent_bytes and user_agent*/
            ) => {
                let mut size = 0;
                size += 4; // version
                size += 8; // services
                size += 8; // timestamp
                size += 8; // addr_recv_services
                size += 16; // addr_recv_ip_address
                size += 2; // addr_recv_port
                size += 8; // addr_trans_services
                size += 16; // addr_trans_ip_address
                size += 2; // addr_trans_port
                size += 8; // nonce
                size += 1; // user_agent_bytes hardcoded
                size += 0; // "" hardcoded
                size += 4; // start_height
                size += 1; // relay

                Ok(size)
            }
            MessagePayload::Verack => Ok(0),
        }
    }

    fn encode(&self, buffer: &mut [u8]) -> Result<(), String> {
        match self {
            MessagePayload::Version(version) => {
                buffer[0..4].copy_from_slice(&version.version.to_le_bytes()); // 4 bytes
                buffer[4..12].copy_from_slice(&version.services.to_le_bytes()); // 8 bytes
                buffer[12..20].copy_from_slice(&version.timestamp.to_le_bytes()); // 8 bytes
                buffer[20..28].copy_from_slice(&version.addr_recv_services.to_le_bytes()); // 8 bytes
                buffer[28..44].copy_from_slice(&version.addr_recv_ip_address); // 16 bytes
                buffer[44..46].copy_from_slice(&version.addr_recv_port.to_be_bytes()); // 2 bytes
                buffer[46..54].copy_from_slice(&version.addr_trans_services.to_le_bytes()); // 8 bytes
                buffer[54..70].copy_from_slice(&version.addr_trans_ip_address); // 16 bytes
                buffer[70..72].copy_from_slice(&version.addr_trans_port.to_be_bytes()); // 2 bytes
                buffer[72..80].copy_from_slice(&version.nonce.to_le_bytes()); // 8 bytes
                                                                              //buffer[80..81].copy_from_slice(&version.user_agent_bytes.as_bytes()); // REVISAR VARIOS
                buffer[81..85].copy_from_slice(&version.start_height.to_le_bytes()); // 4 bytes
                buffer[85..86].copy_from_slice(&version.relay.to_le_bytes()); // 1 bytes
            }
            MessagePayload::Verack => {}
        }
        Ok(())
    }

    fn command_name(&self) -> Result<&str, String> {
        match self {
            MessagePayload::Version(_) => Ok("version"),
            MessagePayload::Verack => Ok("verack"),
        }
    }

    fn decode(cmd: &String, buffer: &[u8]) -> Result<Self, String> {
        match cmd.as_str() {
            "version" => decode_version(buffer),
            "verack" => Ok(MessagePayload::Verack),
            _ => Err("Unknown command".to_string()),
        }
    }
}



fn decode_version(buffer: &[u8]) -> Result<MessagePayload, String> {
    let mut addr_recv_ip_address: [u8; 16] = [0u8; 16];
    addr_recv_ip_address.copy_from_slice(&buffer[28..44]);
    let mut addr_trans_ip_address: [u8; 16] = [0u8; 16];
    addr_trans_ip_address.copy_from_slice(&buffer[54..70]);

    let ua_b_ffset = get_offset(&buffer[80..81]);
    let payload_size = buffer.len();
    let version =read_le(&buffer[0..4]) as u32; // 4 bytes
    let services = read_le(&buffer[4..12]) as u64; // 8 bytes
    let timestamp = read_le(&buffer[12..20]) as u64; // 8 bytes
    let addr_recv_services = read_le(&buffer[20..28]) as u64; // 8 bytes
    let addr_recv_port = read_be(&buffer[44..46]) as u16; // 2 bytes
    let addr_trans_services = read_le(&buffer[46..54]) as u64; // 8 bytes
    let addr_trans_port = read_be(&buffer[70..72]) as u16; // 2 bytes
    let nonce = read_le(&buffer[72..80]) as u64; //  8 bytes // HASTA ACA ES FIJO
    let user_agent_bytes = read_le(&buffer[80..(80 + ua_b_ffset)]);
    let user_agent = String::from_utf8(buffer[(80 + ua_b_ffset)..(80 + ua_b_ffset + user_agent_bytes)].to_vec()).unwrap();
    let start_height = read_le(&buffer[(payload_size - 5)..(payload_size - 1)]) as u32;
    let relay = read_le(&buffer[(payload_size - 1)..payload_size]) as u8;


    let message_payload = PayloadVersion::new(
        version,
        services,
        timestamp,
        addr_recv_services,
        addr_recv_ip_address,
        addr_recv_port,
        addr_trans_services,
        addr_recv_ip_address,
        addr_trans_port,
        nonce,
        user_agent_bytes.to_string(),
        user_agent,
        start_height,
        relay
    );
    Ok(MessagePayload::Version(message_payload))
}

fn get_offset(buff: &[u8]) -> usize {

    let i: u8 = buff[0];

    if i == 0xfdu8 as u8 {
        2 as usize
    } else if i == 0xfeu8 as u8{
        4 as usize
    } else if i == 0xffu8 as u8{
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

pub fn read_be(buffer: &[u8]) -> usize{
    let mut result = 0;
    for i in 0..buffer.len() {
        result += (buffer[i] as usize) << (8 * (buffer.len() - i - 1));
    }
    result
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_to_ipv6_format() {
        let (ipv6, port) = ipv4_to_ipv6_format(&"127.0.0.1:18333".to_string());
        assert_eq!(ipv6, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 127, 0, 0, 1]);
        assert_eq!(port, 18333);
    }
}
