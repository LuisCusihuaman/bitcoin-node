#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PayloadGetData {
    count: u8,
    inventory: [u8;36],  
}


impl PayloadGetData{
    pub fn size(&self) -> u64 {
        let mut size = 0;
        size += 1; // TODO Variable size
        size += 36; // TODO Variable size
        
        size
    }

    pub fn encode(&self, buffer: &mut [u8]) {
        let count = 1u8.to_le_bytes();
        buffer[0..1].copy_from_slice(&count);
        buffer[1..].copy_from_slice(&self.inventory); 
        println!("{:?}", buffer);
    }

    pub fn new(
        count: u8,
        inventory: [u8;36],
    ) -> Self {       
        Self {
            count,
            inventory,
        }
    }
}

