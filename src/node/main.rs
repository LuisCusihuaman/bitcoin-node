use app::node::manager::{Config, NodeManager};

fn main() {
    let mut node_manager = NodeManager::new(Config {
        addrs: "seed.testnet.bitcoin.sprovoost.nl".to_string(),
        port: 80,
    });
    node_manager.load_initial_nodes().unwrap();
    for peer in node_manager.peers().iter() {
        println!("{}", peer);
    }
    //TODO: refactor network to node manager have a network
    // let mut network = manager.network::connect(NetworkParams::new(
    //     "127.0.0.1:8334".to_string(),
    //     vec![],
    //     10_000,
    // ))
    // .unwrap();
    // let mut connection_b =
    //     PeerConnection::connect("127.0.0.1:8334".to_string(), 10_000).unwrap();
    // let mut connection_c =
    //     PeerConnection::connect("127.0.0.1:8334".to_string(), 10_000).unwrap();
    // let _ = network.accept_new_peers().unwrap();
}
