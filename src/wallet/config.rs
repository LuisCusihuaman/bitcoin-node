use std::error::Error;
use std::fmt::format;
use std::fs::File;
use std::io;
use std::io::BufRead;
use std::io::BufReader;
use std::io::Read;

// use app::error::Error;
#[derive(Clone, Debug)]
pub struct Config {
    pub users: Vec<UserConfig>,
    pub tx_fee: f64,
    pub node_manager_address: String,
}

#[derive(Clone, Debug)]
pub struct UserConfig {
    pub private_key: String,
    pub name: String,
}

impl Config {
    pub fn new() -> Self {
        Self {
            users: Vec::new(),
            tx_fee: 0.0,
            node_manager_address: String::from(""),
        }
    }

    pub fn from_file(path: &str) -> Result<Self, Box<dyn Error>> {
        let file = File::open(path)?;
        Self::from_reader(file)
    }

    fn from_reader<T: Read>(content: T) -> Result<Config, Box<dyn Error>> {
        let reader = BufReader::new(content);

        let mut cfg = Self::new();

        for line in reader.lines() {
            let current_line = line?;
            let setting: Vec<&str> = current_line.split('=').collect();

            if setting.len() != 2 {
                return Err(Box::new(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("Invalid config input: {}", current_line),
                )));
            }
            Self::load_setting(&mut cfg, setting[0], setting[1])?;
        }
        Ok(cfg)
    }

    fn load_setting(&mut self, name: &str, value: &str) -> Result<(), Box<dyn Error>> {
        match name {
            "node_manager_address" => self.node_manager_address = String::from(value),
            "tx_fee" => self.tx_fee = value.parse::<f64>()?,
            name if name.starts_with("user_") => {
                let parts: Vec<&str> = name.split('_').collect();
                if parts.len() != 3 {
                    return Err(Box::new(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("Invalid config input: {}", name),
                    )));
                }
                let user_id = parts[1].parse::<usize>()?;
                if user_id > self.users.len() {
                    self.users.resize(user_id, UserConfig {
                        private_key: String::from(""),
                        name: String::from(""),
                    });
                }
                let user = &mut self.users[user_id - 1];
                match parts[2] {
                    "pk" => user.private_key = String::from(value),
                    "name" => user.name = String::from(value),
                    _ => {}
                }
            }
            _ => {}
        }
        Ok(())
    }
}
