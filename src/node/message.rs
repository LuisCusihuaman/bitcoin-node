#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MessagePayload {
    Version(u32),
    Verack,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct MessageHeader {
    payload_size: u32,
}

impl MessageHeader {
    pub fn new(payload_size: u32) -> Self {
        MessageHeader { payload_size }
    }
    pub fn to_string(&self) -> String {
        format!("MessageHeader {{ payload_size: {} }}", self.payload_size)
    }
}
