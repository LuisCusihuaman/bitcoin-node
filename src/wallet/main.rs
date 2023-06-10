use std::env;
use std::error::Error;
use std::io;

use app::config::Config;
use app::logger::Logger;
use app::wallet::wallet::Wallet;

fn main() -> Result<(), Box<dyn Error>> {
    let filepath = env::args().nth(1).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "Se debe pasar el nombre del archivo como parámetro",
        )
    })?;
    let config = Config::from_file(&filepath)?;
    let logger = Logger::new(&config)?;

    let mut _wallet = Wallet::new(config, &logger);

    // TODO inicializar interface

    Ok(())
}
