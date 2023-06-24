use app::config::Config;
use app::logger::Logger;
use app::node::manager::NodeManager;
use std::env;
use std::error::Error;
use std::io;
use std::thread;

fn main() -> Result<(), Box<dyn Error>> {
    // let filepath = env::args().nth(1).ok_or_else(|| {
    //     io::Error::new(
    //         io::ErrorKind::InvalidInput,
    //         "Se debe pasar el nombre del archivo como parametro",
    //     )
    // })?;

    let config = Config::from_file(&"nodo.config")?;

    let logger = Logger::new(&config)?;
    let logger_tx = logger.tx.clone();

    let logger_thread = thread::spawn(move || {
        logger.run();
    });

    let mut node_manager = NodeManager::new(config, logger_tx);

    let node_network_ips = node_manager.get_initial_nodes()?;

    node_manager.connect(
        node_network_ips
            .iter()
            .map(|ip| format!("{}:18333", ip))
            .collect(),
    )?;

    node_manager.handshake();
    node_manager.initial_block_download()?;
    node_manager.run();

    logger_thread.join().unwrap();

    Ok(())
}
