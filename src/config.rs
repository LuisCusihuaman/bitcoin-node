use std::error::Error;
use std::fs::File;
use std::io;
use std::io::BufRead;
use std::io::BufReader;
use std::io::Read;

// use app::error::Error;

pub struct Config {
    pub logfile: String,
    pub direccion_ip: String,
    pub puerto: String,
    pub dns: String,
}

impl Config {
    // Abro el archivo
    pub fn from_file(path: &str) -> Result<Self, Box<dyn Error>> {
        let file = File::open(path)?;
        Self::from_reader(file)
    }

    fn from_reader<T: Read>(content: T) -> Result<Config, Box<dyn Error>> {
        let reader = BufReader::new(content);

        let mut cfg = Self {
            logfile: String::from(""),
            direccion_ip: String::from(""),
            puerto: String::from(""),
            dns: String::from(""),
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
            "logfile" => self.logfile = String::from(value),
            "direccionIP" => self.direccion_ip = String::from(value),
            "puerto" => self.puerto = String::from(value),
            "DNS" => self.dns = String::from(value),
            _ => {
                return Err(Box::new(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("Invalid config setting name: {}", name),
                )))
            }
        }
        Ok(())
    }
}
