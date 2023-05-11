use std::io::Write;
use bitcoin_hashes::sha256;
use bitcoin_hashes::Hash;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MessagePayload {
    Version(u32),
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
    fn checksum(&self) -> Result<[u8; 4], String>;
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
        let size = std::mem::size_of::<MessageHeader>() as u64;
        Ok(size + 4)
    }
    fn command_name(&self) -> Result<&str, String> {
        Ok("")
    }

    fn checksum(&self) -> Result<[u8; 4], String> {
        Ok([0xe2, 0xe0, 0xf6, 0x5d]) //0x5df6e0e2
    }
}

impl Encoding<MessageHeader> for MessagePayload {
    fn size_of(&self) -> Result<u64, String> {
        match self {
            MessagePayload::Version(_) => Ok(std::mem::size_of::<u32>() as u64),
            MessagePayload::Verack => Ok(0),
        }
    }

    fn encode(&self, buffer: &mut [u8]) -> Result<(), String> {
        match self {
            MessagePayload::Version(version) => {
                buffer[0..4].copy_from_slice(&version.to_le_bytes());
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

    fn checksum(&self) -> Result<[u8; 4], String> {
        match self {
            MessagePayload::Version(version) => {
                let bytes = version.to_le_bytes();
                let hash = sha256::Hash::hash(&bytes);
                let mut checksum = [0u8; 4];
                checksum.copy_from_slice(&hash[..4]);
                Ok(checksum)
            }
            MessagePayload::Verack => Ok([0x5d, 0xf6, 0xe0, 0xe2]),
        }
    }
}
