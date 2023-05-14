use app::net::router::Router;
use app::net::server::Server;
use app::node::manager::{Config, NodeManager};



fn main() -> Result<(), String> {
    let mut node_manager = NodeManager::new(Config {
        addrs: "seed.testnet.bitcoin.sprovoost.nl".to_string(),
        port: 80,
    });
    let node_network_ips = node_manager.get_initial_nodes()?;
    node_manager.connect(node_network_ips)?;
    node_manager.run()
}
