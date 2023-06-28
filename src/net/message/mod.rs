use self::get_data_inv::{decode_get_data, decode_inv, PayloadGetDataInv};
use self::get_headers::PayloadHeaders;
use self::tx_status::{decode_tx_status, PayloadTxStatus};
use crate::net::message::block::{decode_block, Block};
use crate::net::message::get_blocks::PayloadGetBlocks;
use crate::net::message::get_headers::{decode_headers, PayloadGetHeaders};
use crate::net::message::get_utxos::{decode_get_utxos, PayloadGetUtxos};
use crate::net::message::ping_pong::{decode_ping, decode_pong, PayloadPingPong};
use crate::net::message::tx::{decode_tx, Tx};
use crate::net::message::utxos_msg::{decode_utxos, PayloadUtxosMsg};
use crate::net::message::version::{decode_version, PayloadVersion};
use crate::utils::read_le;
use std::mem;

pub mod block;
pub mod get_blocks;
pub mod get_data_inv;
pub mod get_headers;
pub mod get_utxos;
pub mod ping_pong;
pub mod tx;
pub mod tx_status;
pub mod utxos_msg;
pub mod version;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TxStatus {
    Confirmed,
    Unconfirmed,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MessagePayload {
    Version(PayloadVersion),
    Verack,
    GetHeaders(PayloadGetHeaders),
    Headers(PayloadHeaders),
    GetBlocks(PayloadGetBlocks),
    Inv(PayloadGetDataInv),
    GetData(PayloadGetDataInv),
    Block(Block),
    Ping(PayloadPingPong),
    Pong(PayloadPingPong),
    GetUTXOs(PayloadGetUtxos),
    UTXOs(PayloadUtxosMsg),
    Tx(Tx),
    GetTxStatus(Tx),           // Wallet -> Node
    TxStatus(PayloadTxStatus), // Node -> Wallet
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
    fn size_of(&self) -> usize;
    fn encode(&self, buffer: &mut [u8]) -> Result<(), String>;
    fn command_name(&self) -> &str;
    fn decode(cmd: &str, buffer: &[u8]) -> Result<T, String>;
}

impl Encoding<MessageHeader> for MessageHeader {
    fn size_of(&self) -> usize {
        let mut size = 0;

        size += mem::size_of::<u32>(); // magic number
        size += self.command_name.len(); // command name
        size += mem::size_of::<u32>(); // payload size
        size += mem::size_of::<u32>(); // checksum

        size
    }

    fn encode(&self, buffer: &mut [u8]) -> Result<(), String> {
        self.encode(buffer)
    }

    fn command_name(&self) -> &str {
        ""
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
    fn size_of(&self) -> usize {
        let no_payload = 0;

        match self {
            MessagePayload::Version(version) => version.size(),
            MessagePayload::GetHeaders(get_headers) => get_headers.size(),
            MessagePayload::GetBlocks(get_blocks) => get_blocks.size(),
            MessagePayload::GetData(get_data) => get_data.size(),
            MessagePayload::Ping(ping) => ping.size(),
            MessagePayload::Pong(pong) => pong.size(),
            MessagePayload::GetUTXOs(get_utxos) => get_utxos.size(),
            MessagePayload::UTXOs(utxos) => utxos.size(),
            MessagePayload::Tx(tx) => tx.size(),
            MessagePayload::GetTxStatus(tx) => tx.size(),
            MessagePayload::TxStatus(tx_status) => tx_status.size(),
            _ => no_payload,
        }
    }

    fn encode(&self, buffer: &mut [u8]) -> Result<(), String> {
        match self {
            MessagePayload::Version(version) => {
                version.encode(buffer);
            }
            MessagePayload::GetHeaders(get_headers) => {
                get_headers.encode(buffer);
            }
            MessagePayload::GetBlocks(get_blocks) => {
                get_blocks.encode(buffer);
            }
            MessagePayload::GetData(get_data) => {
                get_data.encode(buffer);
            }
            MessagePayload::Ping(ping) => {
                ping.encode(buffer);
            }
            MessagePayload::Pong(pong) => {
                pong.encode(buffer);
            }
            MessagePayload::GetUTXOs(get_utxo) => {
                get_utxo.encode(buffer);
            }
            MessagePayload::UTXOs(utxos) => {
                utxos.encode(buffer);
            }
            MessagePayload::Tx(tx) => {
                tx.encode(buffer);
            }
            MessagePayload::TxStatus(tx_status) => {
                tx_status.encode(buffer);
            }
            MessagePayload::GetTxStatus(get_tx_status) => {
                get_tx_status.encode(buffer);
            }
            _ => {}
        }
        Ok(())
    }

    fn command_name(&self) -> &str {
        match self {
            MessagePayload::Version(_) => "version",
            MessagePayload::Verack => "verack",
            MessagePayload::GetHeaders(_) => "getheaders",
            MessagePayload::GetBlocks(_) => "getblocks",
            MessagePayload::Headers(_) => "headers",
            MessagePayload::Inv(_) => "inv",
            MessagePayload::GetData(_) => "getdata",
            MessagePayload::Block(_) => "block",
            MessagePayload::Ping(_) => "ping",
            MessagePayload::Pong(_) => "pong",
            MessagePayload::GetUTXOs(_) => "getutxos",
            MessagePayload::UTXOs(_) => "utxos",
            MessagePayload::Tx(_) => "tx",
            MessagePayload::GetTxStatus(_) => "gettxstatus",
            MessagePayload::TxStatus(_) => "txstatus",
        }
    }

    fn decode(cmd: &str, buffer: &[u8]) -> Result<Self, String> {
        match cmd {
            "version" => decode_version(buffer),
            "headers" => decode_headers(buffer),
            "inv" => decode_inv(buffer),
            "verack" => Ok(MessagePayload::Verack),
            "block" => decode_block(buffer),
            "ping" => decode_ping(buffer),
            "pong" => decode_pong(buffer),
            "getutxos" => decode_get_utxos(buffer),
            "utxos" => decode_utxos(buffer),
            "tx" => decode_tx(buffer),
            "getdata" => decode_get_data(buffer),
            "txconfirmed" => decode_tx(buffer),
            "gettxstatus" => decode_tx(buffer),
            "txstatus" => decode_tx_status(buffer),
            _ => Err("Unknown command: ".to_owned() + cmd),
        }
    }
}
