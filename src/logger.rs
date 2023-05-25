use crate::config::Config;
use crate::utils::get_time;
use std::cell::RefCell;
use std::error::Error;
use std::fs::File;
use std::io::prelude::*;

pub struct Logger {
    file: RefCell<File>,
}

impl Logger {
    pub fn stdout() -> Self {
        Self {
            file: RefCell::new(File::create("/dev/null").unwrap()),
        }
    }
    pub fn new(config: &Config) -> Result<Self, Box<dyn Error>> {
        let file = File::create(&config.log_file)?;
        Ok(Self {
            file: RefCell::new(file),
        })
    }

    pub fn log(&self, msg: String) {
        let time_now = get_time();
        let message = format!("{} {}", time_now, msg);

        println!("{}", message);
        let mut file = self.file.borrow_mut();
        if let Err(err) = file.write_all(format!("{}\n", message).as_bytes()) {
            eprintln!("Failed to write to log file: {}", err);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn test_log() {
        let config = Config {
            log_file: "test.log".to_owned(),
            addrs: "".to_string(),
            port: 0,
            dns_port: 0,
            dns: "".to_string(),
            download_blocks_since_date: "".to_string(),
        };
        let logger = Logger::new(&config).unwrap();

        logger.log("test message".to_owned());
        let time_now = get_time();

        let mut file = File::open("test.log").unwrap();
        let mut contents = String::new();
        file.read_to_string(&mut contents).unwrap();

        assert_eq!(contents, format!("{} test message\n", time_now));

        // Remove the log file after the test
        let path = Path::new("test.log");
        if path.exists() {
            std::fs::remove_file(path).unwrap();
        }
    }
}
