#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MessagePayload {
    Version  (u32),
    Verack,
}