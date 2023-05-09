use std::io::Write;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MessagePayload {
    Version(u32),
    Verack,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct MessageHeader {
    magic_number: u32, //indicate the network type
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
}

impl Encoding<MessageHeader> for MessageHeader {
    fn encode(&self, buffer: &mut [u8]) -> Result<(), String> {
        buffer[0..4].copy_from_slice(&self.magic_number.to_le_bytes());

        // Write the command name as an ASCII string followed by null padding
        let command_name_bytes = self.command_name.as_ref();
        //let padding_size = 12 - command_name_bytes.len();
        buffer[4..16].copy_from_slice(command_name_bytes);
        buffer[4 + command_name_bytes.len()..16].fill(0x00);

        // Write the payload size in little-endian byte order
        buffer[16..20].copy_from_slice(&self.payload_size.to_le_bytes());

        Ok(())
    }

    fn size_of(&self) -> Result<u64, String> {
        Ok(std::mem::size_of::<MessageHeader>() as u64)
    }
    fn command_name(&self) -> Result<&str, String> {
        Ok("")
    }
}

impl Encoding<MessageHeader> for MessagePayload {
    fn encode(&self, buffer: &mut [u8]) -> Result<(), String> {
        match self {
            MessagePayload::Version(version) => {
                buffer[0..4].copy_from_slice(&version.to_le_bytes());
            }
            MessagePayload::Verack => {}
        }
        Ok(())
    }

    fn size_of(&self) -> Result<u64, String> {
        match self {
            MessagePayload::Version(_) => Ok(std::mem::size_of::<u32>() as u64),
            MessagePayload::Verack => Ok(0),
        }
    }
    fn command_name(&self) -> Result<&str, String> {
        match self {
            MessagePayload::Version(_) => Ok("version"),
            MessagePayload::Verack => Ok("verack"),
        }
    }
}
