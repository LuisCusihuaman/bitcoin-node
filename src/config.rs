use std::error::Error;
use std::fs::File;
use std::io;
use std::io::BufRead;
use std::io::BufReader;
use std::io::Read;

// use app::error::Error;

#[derive(Clone, Debug)]
pub struct Config {
    pub log_file: String,
    pub addrs: String,
    pub port: u16,
    pub dns: String,
    pub dns_port: u16,
    pub download_blocks_since_date: String,
}

impl Config {
    pub fn new() -> Self {
        Self {
            log_file: String::from(""),
            addrs: String::from(""),
            port: 0,
            dns: String::from(""),
            dns_port: 80,
            download_blocks_since_date: String::from(""),
        }
    }
    // Abro el archivo
    pub fn from_file(path: &str) -> Result<Self, Box<dyn Error>> {
        let file = File::open(path)?;
        Self::from_reader(file)
    }

    fn from_reader<T: Read>(content: T) -> Result<Config, Box<dyn Error>> {
        let reader = BufReader::new(content);

        let mut cfg = Self {
            log_file: String::from(""),
            addrs: String::from(""),
            port: 0,
            dns: String::from(""),
            dns_port: 80,
            download_blocks_since_date: String::from(""),
        };

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
            "LOG_FILE" => self.log_file = String::from(value),
            "IP_ADDRESS" => self.addrs = String::from(value),
            "PORT" => self.port = value.parse::<u16>()?,
            "DNS" => self.dns = String::from(value),
            "DOWNLOAD_BLOCKS_SINCE_DATE" => self.download_blocks_since_date = String::from(value),
            "DNS_PORT" => self.dns_port = value.parse::<u16>()?,
            _ => {}
        }
        Ok(())
    }
}
