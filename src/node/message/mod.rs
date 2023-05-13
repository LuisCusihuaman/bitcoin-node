use crate::node::message::version::PayloadVersion;
use crate::node::message::version::decode_version;

pub mod version;


#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MessagePayload {
    Version(PayloadVersion),
    Verack,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct MessageHeader {
    magic_number: u32,
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

    fn decode(_cmd: &String, _buffer: &[u8]) -> Result<Self, String> {
        let mut buffer: [u8; 12] = [0u8; 12];
        buffer.copy_from_slice("".as_bytes());
        Ok(MessageHeader {
            magic_number: 118034699,
            command_name: buffer,
            payload_size: 0,
        })
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
                version.encode(buffer)?;
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


fn get_offset(buff: &[u8]) -> usize {
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
