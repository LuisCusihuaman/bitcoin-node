use crate::node::message::MessagePayload;
use crate::utils::{read_be, read_le, get_offset};

type CompactSizeUint = String;

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
    pub fn encode(&self, buffer: &mut [u8]) -> Result<(), String> {
        buffer[0..4].copy_from_slice(&self.version.to_le_bytes()); // 4 bytes
        buffer[4..12].copy_from_slice(&self.services.to_le_bytes()); // 8 bytes
        buffer[12..20].copy_from_slice(&self.timestamp.to_le_bytes()); // 8 bytes
        buffer[20..28].copy_from_slice(&self.addr_recv_services.to_le_bytes()); // 8 bytes
        buffer[28..44].copy_from_slice(&self.addr_recv_ip_address); // 16 bytes
        buffer[44..46].copy_from_slice(&self.addr_recv_port.to_be_bytes()); // 2 bytes
        buffer[46..54].copy_from_slice(&self.addr_trans_services.to_le_bytes()); // 8 bytes
        buffer[54..70].copy_from_slice(&self.addr_trans_ip_address); // 16 bytes
        buffer[70..72].copy_from_slice(&self.addr_trans_port.to_be_bytes()); // 2 bytes
        buffer[72..80].copy_from_slice(&self.nonce.to_le_bytes()); // 8 bytes
        //buffer[80..81].copy_from_slice(&version.user_agent_bytes.as_bytes()); // REVISAR VARIOS
        buffer[81..85].copy_from_slice(&self.start_height.to_le_bytes()); // 4 bytes
        buffer[85..86].copy_from_slice(&self.relay.to_le_bytes()); // 1 bytes
        Ok(())
    }
}

impl PayloadVersion {
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

pub fn decode_version(buffer: &[u8]) -> Result<MessagePayload, String> {
    let mut addr_recv_ip_address: [u8; 16] = [0u8; 16];
    addr_recv_ip_address.copy_from_slice(&buffer[28..44]);
    let mut addr_trans_ip_address: [u8; 16] = [0u8; 16];
    addr_trans_ip_address.copy_from_slice(&buffer[54..70]);

    let ua_b_ffset = get_offset(&buffer[80..81]);
    let payload_size = buffer.len();
    let version = read_le(&buffer[0..4]) as u32; // 4 bytes
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
        relay,
    );
    Ok(MessagePayload::Version(message_payload))
}
