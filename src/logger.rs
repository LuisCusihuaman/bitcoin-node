use crate::utils::get_time;
use std::cell::RefCell;
use std::error::Error;
use std::fs::File;
use std::io::prelude::*;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread;
use crate::node::config::Config;

pub struct Logger {
    rx: Receiver<String>,
    pub tx: Sender<String>,
    file: RefCell<File>,
}

impl Logger {
    pub fn mock_logger() -> Self {
        let (sender, rx) = channel();
        let file = File::create("/dev/null").unwrap();

        Self {
            rx,
            tx: sender,
            file: RefCell::new(file),
        }
    }

    pub fn new(config: &Config) -> Result<Self, Box<dyn Error>> {
        let (sender, receiver) = channel();

        let file = File::create(&config.log_file)?;
        Ok(Self {
            rx: receiver,
            tx: sender,
            file: RefCell::new(file),
        })
    }

    pub fn run(&self) {
        loop {
            let msg = self.rx.recv().unwrap();
            self.log(msg);
        }
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

pub fn log(logger_tx: Sender<String>, msg: String) {
    match logger_tx.send(msg) {
        _ => {}
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
