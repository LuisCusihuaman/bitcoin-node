use std::env;
use std::error::Error;
use std::io;
use std::thread;

use app::logger::Logger;
use app::node::config::Config;
use app::node::manager::NodeManager;

mod config;

fn main() -> Result<(), Box<dyn Error>> {
    let filepath = env::args().nth(1).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "Se debe pasar el nombre del archivo como parametro",
        )
    })?;
    let extra_peer_address = env::args().nth(2);


    let config = Config::from_file(filepath.as_str())?;

    let logger = Logger::new(&config)?;
    let logger_tx = logger.tx.clone();

    let logger_thread = thread::spawn(move || {
        logger.run();
    });

    let mut node_manager = NodeManager::new(config, logger_tx);

    let mut node_network_address = node_manager.get_initial_nodes()?
        .iter().
        map(|ip| format!("{}:18333", ip)).collect::<Vec<String>>();

    if let Some(address) = extra_peer_address {
        node_network_address.push(address);
    }

    node_manager.connect(node_network_address)?;

    node_manager.handshake();
    node_manager.initial_block_download()?;
    node_manager.run();

    logger_thread.join().unwrap();

    Ok(())
}
