use crate::node::message::MessagePayload;
use crate::utils::{
    copy_bytes_to_array, read_string, read_u16_be, read_u32_le, read_u64_le, read_varint,
};

type CompactSizeUint = String;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PayloadVersion {
    pub version: u32,
    pub services: u64,
    pub timestamp: u64,
    pub addr_recv_services: u64,
    pub addr_recv_ip_address: [u8; 16],
    pub addr_recv_port: u16,
    pub addr_trans_services: u64,
    pub addr_trans_ip_address: [u8; 16],
    pub addr_trans_port: u16,
    pub nonce: u64,
    pub user_agent_bytes: CompactSizeUint,
    pub user_agent: String,
    pub start_height: u32,
    pub relay: u8,
}

impl PayloadVersion {
    pub fn size(&self) -> u64 {
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
        size
    }
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

        Self {
            version: 70015, //Bitcoin Core 0.13.2 (Jan 2017)
            services: 0,    //Unnamed receiving node
            timestamp,
            addr_recv_services: 0, // Same format as the "services" field above.
            addr_recv_ip_address: addr_recv_ipv6_from_ipv4,
            addr_recv_port,
            addr_trans_services: 0, //Unnamed transmitting node
            addr_trans_ip_address: addr_trans_ipv6_from_ipv4,
            addr_trans_port,
            nonce: 0,         // If the nonce is 0, the nonce field is ignored.
            user_agent_bytes, // is a var int
            user_agent,
            start_height: 0,
            relay: 0,
        }
    }
}

pub fn decode_version(buffer: &[u8]) -> Result<MessagePayload, String> {
    let mut addr_recv_ip_address: [u8; 16] = [0u8; 16];
    copy_bytes_to_array(&buffer[28..44], &mut addr_recv_ip_address);
    let mut addr_trans_ip_address: [u8; 16] = [0u8; 16];
    copy_bytes_to_array(&buffer[54..70], &mut addr_trans_ip_address);

    let payload_size = buffer.len();
    let version = read_u32_le(buffer, 0);
    let services = read_u64_le(buffer, 4);
    let timestamp = read_u64_le(buffer, 12);
    let addr_recv_services = read_u64_le(buffer, 20);
    let addr_recv_port = read_u16_be(buffer, 44);
    let addr_trans_services = read_u64_le(buffer, 46);
    let addr_trans_port = read_u16_be(buffer, 70);
    let nonce = read_u64_le(buffer, 72);
    let user_agent_bytes = read_varint(&mut &buffer[80..])?; // Read variable-length user_agent_bytes 😎
    let user_agent = read_string(buffer, 81, user_agent_bytes); // WHY I USE 81!!! AND NOT 80 :CC DOCS SAY START AFTER 80 🤔
    let start_height = read_u32_le(buffer, payload_size - 5);
    let relay = buffer[payload_size - 1];

    let message_payload = PayloadVersion {
        version,
        services,
        timestamp,
        addr_recv_services,
        addr_recv_ip_address,
        addr_recv_port,
        addr_trans_services,
        addr_trans_ip_address: addr_recv_ip_address,
        addr_trans_port,
        nonce,
        user_agent_bytes: user_agent.len().to_string(),
        user_agent,
        start_height,
        relay,
    };

    Ok(MessagePayload::Version(message_payload))
}
