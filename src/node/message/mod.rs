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


