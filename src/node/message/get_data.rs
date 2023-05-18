#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PayloadGetData {
    count: u32,
    inventory: u8,  
}


impl PayloadGetData{
    pub fn size(&self) -> u64 {
        let mut size = 0;
        size += 4; // version
        size += 1; // TODO Variable size
        size += 32; // TODO Variable size
        size += 32; // stop_hash

        size
    }

    pub fn encode(&self, buffer: &mut [u8]) {
        // TO DO
    }

    pub fn new(
        count: u32,
        inventory: u8,
    ) -> Self {
        Self {
            count,
            inventory,
        }
    }
}

