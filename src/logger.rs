use std::cell::RefCell;
use std::error::Error;
use std::fs::File;
use std::io::prelude::*;

use crate::config::Config;

pub struct Logger {
    file: RefCell<File>,
    only_stdout: bool,
}

impl Logger {
    pub fn stdout() -> Self {
        Self {
            file: RefCell::new(File::create("/dev/null").unwrap()),
            only_stdout: true,
        }
    }
    pub fn new(config: &Config) -> Result<Self, Box<dyn Error>> {
        let file = File::create(&config.logfile)?;
        Ok(Self { file: RefCell::new(file), only_stdout: false })
    }

    pub fn log(&self, msg: String) {
        println!("{}", msg);
        let mut file = self.file.borrow_mut();
        if let Err(err) = file.write_all(format!("{}\n", msg).as_bytes()) {
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
        let config = Config { logfile: "test.log".to_owned(), direccion_ip: "".to_string(), puerto: "".to_string(), dns: "".to_string() };
        let logger = Logger::new(&config).unwrap();
        logger.log("test message".to_owned());

        let mut file = File::open("test.log").unwrap();
        let mut contents = String::new();
        file.read_to_string(&mut contents).unwrap();

        assert_eq!(contents, "test message\n");

        // Remove the log file after the test
        let path = Path::new("test.log");
        if path.exists() {
            std::fs::remove_file(path).unwrap();
        }
    }
}
