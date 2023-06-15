#[cfg(test)]
mod tests {
    use std::thread;

    use app::config::Config;
    use app::logger::Logger;
    use app::net::message::get_blocks::PayloadGetBlocks;
    use app::net::message::get_data_inv::{Inventory, PayloadGetDataInv};
    use app::net::message::get_headers::PayloadGetHeaders;
    use app::net::message::ping_pong::PayloadPingPong;
    use app::net::message::MessagePayload;
    use app::node::manager::NodeManager;
    use app::utils::{check_blockchain_integrity, get_hash_block_genesis};
    use rand::Rng;

    #[test]
    fn test_get_all_ips_from_dns() {
        let logger = Logger::mock_logger();

        let config = Config::from_file("nodo.config")
            .map_err(|err| err.to_string())
            .unwrap();

        let mut node_manager = NodeManager::new(config, logger.tx);
        let node_network_ips = node_manager.get_initial_nodes().unwrap();
        assert_ne!(node_network_ips.len(), 0);
    }

    #[test]
    fn test_connect_node_with_external_nodes_not_refuse_connection() -> Result<(), String> {
        let logger = Logger::mock_logger();

        let config = Config::from_file("nodo.config").map_err(|err| err.to_string())?;

        let mut node_manager = NodeManager::new(config, logger.tx);
        let node_network_ips = node_manager.get_initial_nodes().unwrap();
        node_manager.connect(
            node_network_ips
                .iter()
                .map(|ip| format!("{}:18333", ip))
                .collect(),
        )?;
        Ok(())
    }

    #[test]
    fn test_node_handshake() -> Result<(), String> {
        let logger = Logger::mock_logger();
        let config = Config::new();

        let mut node_manager = NodeManager::new(config, logger.tx);

        node_manager.connect(vec!["5.9.73.173:18333".to_string()])?;
        node_manager.handshake();
        Ok(())
    }

    #[test]
    fn test_node_send_get_headers() {
        let mut node_manager = init_valid_node_manager();

        // Create getheaders message
        let hash_block_genesis: [u8; 32] = get_hash_block_genesis();

        let stop_hash = [0u8; 32];

        let get_headers_message = MessagePayload::GetHeaders(PayloadGetHeaders::new(
            70015,
            1,
            hash_block_genesis.to_vec(),
            stop_hash.to_vec(),
        ));

        // Send getheaders message
        node_manager.broadcast(&get_headers_message);

        // Wait for headers message
        let resp = node_manager.wait_for(vec!["headers"]);

        assert!(get_messages(resp).len() > 0);
    }

    #[test]
    fn test_node_send_get_blocks() {
        let mut node_manager = init_valid_node_manager();

        // Create getblocks message
        let get_blocks_message = MessagePayload::GetBlocks(PayloadGetBlocks {
            version: 70015,
            hash_count: 1,
            block_header_hashes: get_hash_block_genesis().to_vec(),
            stop_hash: [0u8; 32].to_vec(),
        });

        // Send getblocks message
        node_manager.broadcast(&get_blocks_message);

        // Wait for inv message
        let resp = node_manager.wait_for(vec!["inv"]);

        assert!(get_messages(resp).len() > 0);
    }

    #[test]
    fn test_node_send_get_data() {
        let mut node_manager = init_valid_node_manager();

        // Create inventories
        let inventory: Vec<Inventory> = vec![Inventory {
            inv_type: 2,
            hash: get_hash_block_genesis().to_vec(),
        }];

        // Create getdata message with prev inventories
        let get_data_message = MessagePayload::GetData(PayloadGetDataInv {
            count: 1,
            inv_type: 2,
            inventories: inventory,
        });

        // Send getdata message
        node_manager.broadcast(&get_data_message);

        // Wait for block message
        let resp = node_manager.wait_for(vec!["block"]);

        assert!(get_messages(resp).len() > 0);
    }

    #[test]
    #[ignore]
    fn test_complete_initial_block_download() -> Result<(), String> {
        let mut node_manager = init_valid_node_manager();

        node_manager.initial_block_download()?;

        //assert!(node_manager.get_blocks().len() >= 2000);
        Ok(())
    }

    #[test]
    #[ignore]
    fn test_check_blockchain_integrity() -> Result<(), String> {
        let mut node_manager = init_valid_node_manager();

        node_manager.initial_block_download()?;
        assert!(check_blockchain_integrity(node_manager.get_blocks()));

        Ok(())
    }

    #[test]
    fn test_node_send_messages_to_different_peers() -> Result<(), String> {
        let logger = Logger::mock_logger();
        let config = Config::new();

        let mut node_manager = NodeManager::new(config, logger.tx);
        node_manager.connect(vec![
            "5.9.149.16:18333".to_string(),
            "18.218.30.118:18333".to_string(),
        ])?;
        let verack1 = MessagePayload::Verack;
        let verack2 = MessagePayload::Verack;
        let verack3 = MessagePayload::Verack;

        node_manager.send(vec![verack1, verack2, verack3]);
        Ok(())
    }

    #[test]
    fn test_node_send_ping() {
        let mut node_manager = init_valid_node_manager();

        let ping_message: MessagePayload = MessagePayload::Ping(PayloadPingPong::new());

        // Send ping messages
        node_manager.broadcast(&ping_message);

        // Receive pong messages
        let resp = node_manager.wait_for(vec!["pong"]);

        assert!(get_messages(resp).len() > 0);
    }

    // HELPER FUNCTIONS
    fn init_valid_node_manager() -> NodeManager {
        let peers = [
            "93.157.187.23:18333",
            "5.9.149.16:18333",
            "18.218.30.118:18333",
        ];

        let mut rng = rand::thread_rng();
        let index = rng.gen_range(0..peers.len());

        let logger = Logger::mock_logger();
        let logget_tx = logger.tx.clone();

        thread::spawn(move || logger.run()); // TODO liberar recursos
        let config = Config::new();

        let mut node_manager = NodeManager::new(config, logget_tx);
        node_manager
            .connect(vec![peers[index].to_string()])
            .unwrap();
        node_manager.handshake();

        node_manager
    }

    fn get_messages(response: Vec<(String, Vec<MessagePayload>)>) -> Vec<MessagePayload> {
        response
            .iter()
            .map(|(_, message)| message.clone())
            .map(|mut message| message.pop().unwrap())
            .collect()
    }
}
