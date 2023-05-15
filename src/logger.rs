use std::error::Error;
use std::fs::File;
use std::io::prelude::*;

use crate::config::Config;

pub struct Logger {
    file: File,
}

impl Logger {
    pub fn new(config: &Config) -> Result<Self, Box<dyn Error>> {
        let file = File::create(&config.logfile)?;
        Ok(Self { file })
    }

    pub fn log(&mut self, msg: &str) -> Result<(), Box<dyn Error>> {
        self.file.write_all(format!("{msg}").as_bytes())?;
        Ok(())
    }
}
