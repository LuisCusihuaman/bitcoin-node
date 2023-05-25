use std::env;
use std::error::Error;
use std::io;

use app::config::Config;
use app::logger::Logger;
use app::node::manager::NodeManager;

fn main() -> Result<(), Box<dyn Error>> {
    let filepath = env::args().nth(1).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "Se debe pasar el nombre del archivo como parametro",
        )
    })?;
    let config = Config::from_file(&filepath)?;
    let logger = Logger::new(&config)?;

    let mut node_manager = NodeManager::new(config, &logger);
    let node_network_ips = node_manager.get_initial_nodes()?;
    node_manager.connect(
        node_network_ips
            .iter()
            .map(|ip| format!("{}:18333", ip))
            .collect(),
    )?;
    node_manager.handshake();
    node_manager.initial_block_download()?;
    node_manager.block_broadcasting()?;
    // Spawn a new thread for the block_broadcasting function
    // thread::spawn(move || {
    //     let mut router = Router::new();
    //     router.branch("/test", handler_handshake);
    //     let mut server = Server::new(router, &logger, config);
    //     server.run(&"127.0.0.1:8090").unwrap();
    // });
    Ok(())
}
