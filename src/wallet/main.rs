use app::config::Config;
use app::logger::Logger;
use app::wallet::wallet::Wallet;
use std::error::Error;
use std::io;
use std::{env, thread};

fn main() -> Result<(), Box<dyn Error>> {
    let filepath = env::args().nth(1).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "Se debe pasar el nombre del archivo como parámetro",
        )
    })?;
    let config = Config::from_file(&filepath)?;

    let logger = Logger::new(&config)?;
    let logger_tx = logger.tx.clone();

    let logger_thread = thread::spawn(move || {
        logger.run();
    });

    // let mut _wallet = Wallet::new(config, logger_tx);

    // TODO inicializar interface

    //////////// Para Edu
    // loop{
    //     preguntar si ya se acepto la Tx
    //      wallet.send(getTxStatus())
    // }

    logger_thread.join().unwrap();
    Ok(())
}
