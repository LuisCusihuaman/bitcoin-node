use app::node::manager::{Config, NodeManager};

fn main() {
    let mut node_manager = NodeManager::new(Config {
        addrs: "seed.testnet.bitcoin.sprovoost.nl".to_string(),
        port: 80,
    });
}
