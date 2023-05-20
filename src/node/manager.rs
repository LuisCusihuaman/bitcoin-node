use crate::config::Config;
use crate::node::message::block::Block;
use crate::node::message::get_blocks::PayloadGetBlocks;
use crate::node::message::version::PayloadVersion;
use crate::node::message::MessagePayload;
use crate::node::p2p_connection::P2PConnection;
use crate::utils::date_to_timestamp;
use crate::{logger::Logger, node::message::get_headers::PayloadGetHeaders};
use std::thread;

use std::fs;
use std::net::{IpAddr, ToSocketAddrs};

pub struct NodeNetwork<'a> {
    pub peer_connections: Vec<P2PConnection>,
    logger: &'a Logger,
}

impl NodeNetwork<'_> {
    pub fn new(logger: &Logger) -> NodeNetwork {
        NodeNetwork {
            peer_connections: vec![],
            logger,
        }
    }
    pub fn handshake_complete(&mut self, peer_address: &String) {
        self.logger
            .log(format!("Handshake complete with peer: {}", peer_address));
        // added handshaked attribute of P2PConnection turned into true, filter first by peer_address
        if let Some(peer_connection) = self
            .peer_connections
            .iter_mut()
            .find(|connection| connection.peer_address == *peer_address)
        {
            peer_connection.handshaked();
        }
    }
    pub fn send_to_all_peers(&mut self, payload: &MessagePayload) -> Result<(), String> {
        for connection in &mut self.peer_connections {
            if let Err(e) = connection.send(payload) {
                eprintln!("Error sending message to peer: {:?}", e);
            }
        }
        Ok(())
    }

    pub fn receive_from_all_peers(&mut self) -> Vec<(String, Vec<MessagePayload>)> {
        self.peer_connections
            .iter_mut()
            .map(|connection| connection.receive())
            .collect()
    }
}

pub struct NodeManager<'a> {
    node_network: NodeNetwork<'a>,
    config: Config,
    logger: &'a Logger,
    blocks: Vec<Block>,
}

impl NodeManager<'_> {
    pub fn new(config: Config, logger: &Logger) -> NodeManager {
        NodeManager {
            config,
            node_network: NodeNetwork::new(logger),
            logger,
            blocks: vec![], // inicializar el block genesis (con el config)
        }
    }

    pub fn handshake(&mut self) {
        let payload_version_message = MessagePayload::Version(PayloadVersion::default_version());
        self.broadcast(&payload_version_message);
        self.wait_for(vec!["version", "verack"]);
    }

    pub fn wait_for(&mut self, commands: Vec<&str>) -> Vec<MessagePayload> {
        let mut matched_messages = Vec::new();
        let received_messages = self.node_network.receive_from_all_peers();

        let (peer_address, messages_from_first_peer) = match received_messages.first() {
            Some((peer_address, messages)) => (peer_address.clone(), messages.clone()),
            None => {
                println!("No se conectó");
                (String::from(""), matched_messages.clone())
            }
        };

        for message in messages_from_first_peer {
            match message {
                MessagePayload::Verack => {
                    self.logger
                        .log(format!("Received verack from {}", peer_address));
                    self.node_network.handshake_complete(&peer_address);
                    if commands.contains(&"verack") {
                        matched_messages.push(MessagePayload::Verack);
                    }
                }
                MessagePayload::Version(version) => {
                    self.broadcast(&MessagePayload::Verack);
                    self.logger
                        .log(format!("Received version from {}", peer_address));
                    if commands.contains(&"version") {
                        matched_messages.push(MessagePayload::Version(version.clone()));
                    }
                }
                MessagePayload::BlockHeader(blocks) => {
                    if commands.contains(&"headers") {
                        matched_messages.push(MessagePayload::BlockHeader(blocks.clone()));
                    }
                    self.blocks.extend(blocks.clone());
                    // total size_of of blocks
                    Block::encode_blocks_to_file(&blocks, "block_headers.bin");
                }
                MessagePayload::Block(block) => {
                    if commands.contains(&"block") {
                        matched_messages.push(MessagePayload::Block(block.clone()));
                    }

                    if let Some(index) = self.get_block_index_by_prev_hash(block.get_prev()) {
                        self.blocks[index] = block;
                    }
                }
                MessagePayload::Inv(inv) => {
                    self.logger
                        .log(format!("Received inv from {}", peer_address));

                    if commands.contains(&"inv") {
                        matched_messages.push(MessagePayload::Inv(inv.clone()));
                    }
                }

                _ => {}
            }
        }
        matched_messages
    }

    pub fn get_blocks(&self) -> Vec<Block> {
        self.blocks.clone()
    }

    fn resolve_hostname(&self, hostname: &str, port: u16) -> Result<Vec<IpAddr>, std::io::Error> {
        // resolve the hostname to a list of SocketAddr objects
        let addrs = (hostname, port).to_socket_addrs()?;

        // extract the IP addresses from the SocketAddr objects
        let ips: Vec<IpAddr> = addrs
            .filter_map(|addr| match addr.ip() {
                IpAddr::V4(ipv4) => Some(IpAddr::V4(ipv4)),
                IpAddr::V6(_) => None,
            })
            .collect();

        if ips.is_empty() {
            Err(std::io::Error::new(
                std::io::ErrorKind::AddrNotAvailable,
                "could not resolve hostname",
            ))
        } else {
            Ok(ips)
        }
    }

    pub fn get_initial_nodes(&mut self) -> Result<Vec<String>, String> {
        let ips = self
            .resolve_hostname(&self.config.addrs, self.config.port)
            .map_err(|e| format!("Error resolving hostname: {}", e))?;
        let ipv4_addresses: Vec<String> = ips
            .into_iter()
            .filter(|addr| addr.is_ipv4())
            .map(|ip| ip.to_string())
            .collect();
        Ok(ipv4_addresses)
    }

    pub fn connect(&mut self, node_network_addresses: Vec<String>) -> Result<(), String> {
        for addr in node_network_addresses.iter() {
            match P2PConnection::connect(addr) {
                Ok(peer_connection) => {
                    self.node_network.peer_connections.push(peer_connection);
                }
                Err(_) => {
                    //TODO: only continue on timeout error
                    //self.logger.log(format!("Error connecting to peer {}: {}", addr, e));
                    continue;
                }
            }
        }
        Ok(())
    }

    pub fn broadcast(&mut self, payload: &MessagePayload) {
        if let Err(e) = self.node_network.send_to_all_peers(&payload) {
            self.logger
                .log(format!("Error sending message to peer: {:?}", e));
        }
    }

    pub fn receive_all(&mut self) -> Vec<(String, Vec<MessagePayload>)> {
        self.node_network.receive_from_all_peers()
    }

    pub fn initial_block_download(&mut self) -> Result<(), String> {
        let file_path = "block_headers.bin";
        if fs::metadata(file_path).is_ok() {
            // Blocks file already exists, no need to perform initial block download
            self.blocks = Block::decode_blocks_from_file(file_path);
            if self.blocks.len() >= 2000 {
                return Err("Blocks failed to decode".to_string());
            }
            return Ok(());
        }
        // Create getheaders message
        let mut last_block_prev_hash: [u8; 32] = [
            0x00, 0x00, 0x00, 0x00, 0x09, 0x33, 0xea, 0x01, 0xad, 0x0e, 0xe9, 0x84, 0x20, 0x97,
            0x79, 0xba, 0xae, 0xc3, 0xce, 0xd9, 0x0f, 0xa3, 0xf4, 0x08, 0x71, 0x95, 0x26, 0xf8,
            0xd7, 0x7f, 0x49, 0x43,
        ];
        last_block_prev_hash.reverse();

        let stop_hash = [0u8; 32];

        let mut is_finished: bool = false;
        let mut messages: Vec<MessagePayload> = vec![];

        while !is_finished {
            let payload_get_headers =
                PayloadGetHeaders::new(70015, 1, last_block_prev_hash, stop_hash);
            let get_headers_message = MessagePayload::GetHeaders(payload_get_headers);

            self.broadcast(&get_headers_message);
            messages = self.wait_for(vec!["headers"]);

            last_block_prev_hash = match self.blocks.last() {
                Some(block) => block.get_prev().clone(),
                None => return Err("No blocks received".to_string()), // Err(Error::NoBlocksReceived)
            };
            last_block_prev_hash.reverse();
            println!("{:?}", self.blocks.len());
            is_finished = messages.is_empty();
        }

        if let Some(timestamp) = date_to_timestamp(&self.config.download_blocks_since_date) {
            if let Some(block_by_date) = self.get_block_by_timestamp(timestamp) {
                let mut block_hash = block_by_date.get_prev();
                block_hash.reverse();

                let stop_hash = [0u8; 32];

                let get_blocks_message = MessagePayload::GetBlocks(PayloadGetBlocks::new(
                    70015, 1, block_hash, stop_hash,
                ));

                // Send get block messages
                self.broadcast(&get_blocks_message);

                // Receive inv messages
                let messages = self.wait_for(vec!["inv"]);

                for inv in messages.iter() {
                    // TODO send get data message with inv
                }
            }
        }

        Ok(())
    }

    pub fn get_block_by_timestamp(&self, timestamp: u32) -> Option<Block> {
        for block in self.get_blocks() {
            if block.timestamp >= timestamp {
                return Some(block);
            }
        }
        None
    }

    pub fn get_block_index_by_prev_hash(&self, prev_hash: [u8; 32]) -> Option<usize> {
        for (index, block) in self.get_blocks().iter().enumerate() {
            if block.get_prev() == prev_hash {
                return Some(index);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::node;
    use crate::node::message::get_blocks::PayloadGetBlocks;
    use crate::node::message::get_data::PayloadGetData;
    use crate::node::message::get_headers::PayloadGetHeaders;
    use crate::node::message::version::PayloadVersion;

    #[test]
    fn test_get_all_ips_from_dns() {
        let logger = Logger::stdout();
        let config = Config::new();

        let mut node_manager = NodeManager::new(config, &logger);
        let node_network_ips = node_manager.get_initial_nodes().unwrap();
        assert_ne!(node_network_ips.len(), 0);
    }

    #[test]
    fn test_connect_node_with_external_nodes_not_refuse_connection() -> Result<(), String> {
        let logger = Logger::stdout();
        let config = Config::new();

        let mut node_manager = NodeManager::new(config, &logger);
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
        let logger = Logger::stdout();
        let config = Config::new();

        let mut node_manager = NodeManager::new(config, &logger);
        node_manager.connect(vec!["5.9.149.16:18333".to_string()])?;

        let payload_version_message = MessagePayload::Version(PayloadVersion::default_version());
        node_manager.broadcast(&payload_version_message);

        let received_messages = node_manager.receive_all();

        let (_, _received_payloads) = received_messages.first().unwrap(); // TODO add an assert

        Ok(())
    }

    #[test]
    fn test_node_send_get_headers_receives_headers() -> Result<(), String> {
        let logger: Logger = Logger::stdout();
        let config = Config::new();

        let mut node_manager = NodeManager::new(config, &logger);
        node_manager.connect(vec!["5.9.149.16:18333".to_string()])?;
        node_manager.handshake();

        // Create getheaders message
        let hash_block_genesis: [u8; 32] = get_first_hash_reversed();

        let stop_hash = [0u8; 32];

        let get_headers_message = MessagePayload::GetHeaders(PayloadGetHeaders::new(
            70015,
            1,
            hash_block_genesis,
            stop_hash,
        ));
        node_manager.broadcast(&get_headers_message);
        node_manager.wait_for(vec!["headers"]);
        let blocks = node_manager.get_blocks();

        assert!(blocks.len() > 0);
        std::fs::remove_file("block_headers.bin").unwrap();
        Ok(())
    }

    #[test]
    fn test_node_send_get_blocks_receives_inv() -> Result<(), String> {
        let logger: Logger = Logger::stdout();
        let config = Config::new();

        let mut node_manager = NodeManager::new(config, &logger);
        node_manager.connect(vec!["5.9.149.16:18333".to_string()])?;
        node_manager.handshake();

        let hash_beginning_project = get_first_hash_reversed();

        let stop_hash = [0u8; 32];

        let get_blocks_message = MessagePayload::GetBlocks(PayloadGetBlocks::new(
            70015,
            1,
            hash_beginning_project,
            stop_hash,
        ));

        node_manager.broadcast(&get_blocks_message);
        let messages_inv = node_manager.wait_for(vec!["inv"]);

        assert!(messages_inv.len() > 0);

        Ok(())
    }

    #[test]
    fn test_node_send_get_blocks_receives_inv_sends_get_data() -> Result<(), String> {
        let logger: Logger = Logger::stdout();
        let config = Config::new();

        let mut node_manager = NodeManager::new(config, &logger);
        node_manager.connect(vec!["5.9.149.16:18333".to_string()])?;
        node_manager.handshake();

        let hash_beginning_project = get_first_hash_reversed();

        let stop_hash = [0u8; 32];

        let get_blocks_message = MessagePayload::GetBlocks(PayloadGetBlocks::new(
            70015,
            1,
            hash_beginning_project,
            stop_hash,
        ));

        node_manager.broadcast(&get_blocks_message);

        // Recibo inventario
        let messages = node_manager.wait_for(vec!["inv"]);

        match messages.first() {
            Some(MessagePayload::Inv(inventories)) => {
                for inv in inventories.iter() {
                    let get_data_message = MessagePayload::GetData(PayloadGetData::new(1, *inv));

                    // Enviar el mensaje get data
                    node_manager.broadcast(&get_data_message);

                    // Esperamos respuesta
                    if let Some(MessagePayload::Block(block_payload)) =
                        node_manager.wait_for(vec!["block"]).first()
                    {
                        let _hash: [u8; 32] = block_payload.get_prev();
                        node_manager.blocks.push(block_payload.clone());
                    }
                }
            }
            _ => return Err("No inv message received".to_string()),
        }

        Ok(())
    }

    #[test]
    fn test_send_get_headers_and_get_blocks_from_a_date() -> Result<(), String> {
        let logger: Logger = Logger::stdout();
        let config = Config::new();

        let mut node_manager = NodeManager::new(config, &logger);
        node_manager.connect(vec!["5.9.149.16:18333".to_string()])?;
        node_manager.handshake();

        // Send getheaders message
        let hash_block_genesis: [u8; 32] = get_first_hash_reversed();
        let stop_hash = [0u8; 32];

        let get_headers_message = MessagePayload::GetHeaders(PayloadGetHeaders::new(
            70015,
            1,
            hash_block_genesis,
            stop_hash,
        ));
        node_manager.broadcast(&get_headers_message);
        node_manager.wait_for(vec!["headers"]).first();

        let initial_blocks = node_manager.get_blocks();

        let mut indice = 0;

        assert!(initial_blocks.len() > 0);

        let timestamp = 1337966303;

        if let Some(block_by_date) = node_manager.get_block_by_timestamp(timestamp) {
            // Create getblocks message
            let mut block_hash = block_by_date.get_prev();
            block_hash.reverse();

            let stop_hash = [0u8; 32];

            let get_blocks_message =
                MessagePayload::GetBlocks(PayloadGetBlocks::new(70015, 1, block_hash, stop_hash));

            // Send get block messages
            node_manager.broadcast(&get_blocks_message);

            // Receive inv messages
            let messages = node_manager.wait_for(vec!["inv"]);

            match messages.first() {
                Some(MessagePayload::Inv(inventories)) => {
                    for inv in inventories.iter() {
                        let get_data_message =
                            MessagePayload::GetData(PayloadGetData::new(1, *inv));

                        // Enviar el mensaje get data
                        node_manager.broadcast(&get_data_message);

                        // Esperamos respuesta
                        if let Some(MessagePayload::Block(block_payload)) =
                            node_manager.wait_for(vec!["block"]).first()
                        {
                            // Block actualizado
                            if let Some(index) =
                                node_manager.get_block_index_by_prev_hash(block_payload.get_prev())
                            {
                                // Just for assert
                                indice = index.clone();
                                node_manager.blocks[indice] = block_payload.clone();
                            }
                        }
                        break; // Pruebo solo un inv
                    }
                }
                _ => return Err("No inv message received".to_string()),
            }
        } else {
            println!("No se encontró un bloque a partir de esa fecha")
        }

        let final_blocks = node_manager.get_blocks();

        assert_ne!(initial_blocks[indice], final_blocks[indice]);

        Ok(())
    }

    #[test]
    #[ignore]
    fn test_complete_initial_block_download() -> Result<(), String> {
        let logger: Logger = Logger::stdout();
        let config = Config::new();

        let mut node_manager = NodeManager::new(config, &logger);
        node_manager.connect(vec!["5.9.149.16:18333".to_string()])?;
        node_manager.handshake();

        node_manager.initial_block_download()?;

        assert!(node_manager.get_blocks().len() >= 2000);
        std::fs::remove_file("block_headers.bin").unwrap();
        Ok(())
    }

    // Helpers functions for manager tests

    fn get_first_hash_reversed() -> [u8; 32] {
        let mut hash_block_genesis: [u8; 32] = [
            0x00, 0x00, 0x00, 0x00, 0x09, 0x33, 0xea, 0x01, 0xad, 0x0e, 0xe9, 0x84, 0x20, 0x97,
            0x79, 0xba, 0xae, 0xc3, 0xce, 0xd9, 0x0f, 0xa3, 0xf4, 0x08, 0x71, 0x95, 0x26, 0xf8,
            0xd7, 0x7f, 0x49, 0x43,
        ];
        hash_block_genesis.reverse();

        hash_block_genesis
    }
}
