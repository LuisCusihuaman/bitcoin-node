use super::MessagePayload;
use rand::Rng;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PayloadPingPong {
    pub nonce: Vec<u8>,
}

impl Default for PayloadPingPong {
    fn default() -> Self {
        Self::new()
    }
}

impl PayloadPingPong {
    pub fn new() -> Self {
        let mut rng = rand::thread_rng();
        let mut nonce = Vec::new();

        for _ in 0..8 {
            let random_number = rng.gen::<u8>();
            nonce.push(random_number);
        }

        PayloadPingPong { nonce }
    }

    pub fn size(&self) -> usize {
        8_usize
    }

    pub fn encode(&self, buffer: &mut [u8]) {
        buffer[0..8].copy_from_slice(&self.nonce);
    }
}

pub fn decode_ping(buffer: &[u8]) -> Result<MessagePayload, String> {
    if buffer.len() != 8 {
        return Err("Invalid payload size".to_string());
    }

    Ok(MessagePayload::Ping(PayloadPingPong {
        nonce: buffer.to_vec(),
    }))
}

pub fn decode_pong(buffer: &[u8]) -> Result<MessagePayload, String> {
    if buffer.len() != 8 {
        return Err("Invalid payload size".to_string());
    }

    Ok(MessagePayload::Pong(PayloadPingPong {
        nonce: buffer.to_vec(),
    }))
}
