use crate::node::message::block::{decode_block, Block};
use crate::node::message::get_blocks::PayloadGetBlocks;
use crate::node::message::get_data::PayloadGetData;
use crate::node::message::get_headers::{decode_headers, PayloadGetHeaders};
use crate::node::message::inv::{decode_inv, PayloadInv};
use crate::node::message::version::{decode_version, PayloadVersion};

use crate::utils::read_le;

pub mod block;
pub mod get_blocks;
pub mod get_data;
pub mod get_headers;
pub mod inv;
pub mod merkle_tree;
pub mod tx;
pub mod version;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MessagePayload {
    Version(PayloadVersion),
    Verack,
    GetHeaders(PayloadGetHeaders),
    BlockHeader(Vec<Block>),
    GetBlocks(PayloadGetBlocks),
    Inv(PayloadInv),
    GetData(PayloadGetData),
    Block(Block),
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct MessageHeader {
    pub magic_number: u32,
    pub command_name: [u8; 12],
    pub payload_size: u32,
}

impl MessageHeader {
    pub fn new(magic_number: u32, command_name: [u8; 12], payload_size: u32) -> Self {
        MessageHeader {
            payload_size,
            magic_number,
            command_name,
        }
    }
    pub fn encode(&self, buffer: &mut [u8]) -> Result<(), String> {
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
}

pub trait Encoding<T> {
    fn size_of(&self) -> Result<u64, String>;
    fn encode(&self, buffer: &mut [u8]) -> Result<(), String>;
    fn command_name(&self) -> Result<&str, String>;
    fn decode(cmd: &str, buffer: &[u8]) -> Result<T, String>;
}

impl Encoding<MessageHeader> for MessageHeader {
    fn size_of(&self) -> Result<u64, String> {
        let size = std::mem::size_of::<MessageHeader>() as u64;
        Ok(size + 4)
    }

    fn encode(&self, buffer: &mut [u8]) -> Result<(), String> {
        self.encode(buffer)
    }

    fn command_name(&self) -> Result<&str, String> {
        Ok("")
    }

    fn decode(_cmd: &str, buffer: &[u8]) -> Result<Self, String> {
        let magic_number = read_le(&buffer[0..4]) as u32;
        let mut buff_tmp: [u8; 12] = [0u8; 12];
        buff_tmp.copy_from_slice(&buffer[4..16]);
        //let command_name = String::from_utf8_lossy(&buf[4..16]).trim_end_matches('\0').to_owned();
        let payload_size = read_le(&buffer[16..20]) as u32;
        Ok(MessageHeader {
            magic_number,
            command_name: buff_tmp,
            payload_size,
        })
    }
}

impl Encoding<MessagePayload> for MessagePayload {
    fn size_of(&self) -> Result<u64, String> {
        match self {
            MessagePayload::Version(version) => Ok(version.size()),
            MessagePayload::Verack => Ok(0),
            MessagePayload::GetHeaders(get_headers) => Ok(get_headers.size()),
            MessagePayload::BlockHeader(_) => Ok(0), // CHEQUEAR No se envía
            MessagePayload::GetBlocks(get_blocks) => Ok(get_blocks.size()),
            MessagePayload::Inv(_) => Ok(0), // No enviamos Inventario por ahora
            MessagePayload::GetData(get_data) => Ok(get_data.size()),
            MessagePayload::Block(_) => Ok(0),
        }
    }

    fn encode(&self, buffer: &mut [u8]) -> Result<(), String> {
        match self {
            MessagePayload::Version(version) => {
                version.encode(buffer)?;
            }
            MessagePayload::Verack => {}
            MessagePayload::GetHeaders(get_headers) => {
                get_headers.encode(buffer);
            }
            MessagePayload::BlockHeader(_) => {} // TODO No enviamos headers
            MessagePayload::GetBlocks(get_blocks) => {
                get_blocks.encode(buffer);
            }
            MessagePayload::Inv(_) => {} // TODO No enviamos inv
            MessagePayload::GetData(get_data) => {
                get_data.encode(buffer);
            }
            MessagePayload::Block(_) => {}
        }
        Ok(())
    }

    fn command_name(&self) -> Result<&str, String> {
        match self {
            MessagePayload::Version(_) => Ok("version"),
            MessagePayload::Verack => Ok("verack"),
            MessagePayload::GetHeaders(_) => Ok("getheaders"),
            MessagePayload::GetBlocks(_) => Ok("getblocks"),
            MessagePayload::BlockHeader(_) => Ok("headers"),
            MessagePayload::Inv(_) => Ok("inv"),
            MessagePayload::GetData(_) => Ok("getdata"),
            MessagePayload::Block(_) => Ok("block"),
        }
    }

    fn decode(cmd: &str, buffer: &[u8]) -> Result<Self, String> {
        match cmd {
            "version" => decode_version(buffer),
            "headers" => decode_headers(buffer),
            "inv" => decode_inv(buffer),
            "verack" => Ok(MessagePayload::Verack),
            "block" => decode_block(buffer),
            _ => Err("Unknown command: ".to_owned() + cmd),
        }
    }
}
