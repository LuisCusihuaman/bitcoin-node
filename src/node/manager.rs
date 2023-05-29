use crate::config::Config;
use crate::node::message::block::Block;
use crate::node::message::get_blocks::PayloadGetBlocks;
use crate::node::message::get_data::PayloadGetData;
use crate::node::message::version::PayloadVersion;
use crate::node::message::MessagePayload;
use crate::node::p2p_connection::P2PConnection;
use crate::utils::date_to_timestamp;
use crate::{logger::Logger, node::message::get_headers::PayloadGetHeaders};
use rand::seq::SliceRandom;
use std::thread;

use std::fs;
use std::net::{IpAddr, ToSocketAddrs};

pub struct NodeNetwork {
    pub peer_connections: Vec<P2PConnection>,
}

impl NodeNetwork {
    pub fn connection_count(&self) -> usize {
        self.peer_connections
            .iter()
            .filter(|connection| connection.handshaked)
            .count()
    }
    pub fn new() -> NodeNetwork {
        NodeNetwork {
            peer_connections: vec![],
        }
    }
    pub fn handshake_complete(&mut self, peer_address: &String) {
        //self.logger
        //    .log(format!("Handshake complete with peer: {}", peer_address));
        println!("Handshake complete with peer: {}", peer_address);
        // added handshaked attribute of P2PConnection turned into true, filter first by peer_address
        if let Some(peer_connection) = self
            .peer_connections
            .iter_mut()
            .find(|connection| connection.peer_address == *peer_address)
        {
            peer_connection.handshaked();
        }
    }
    pub fn send_messages(&self, payloads: Vec<&MessagePayload>) {
        let mut threads = Vec::new();

        // TODO: connection must be at least one if not enter to infinite loop
        for (payload, connection) in payloads.iter().cloned().zip(
            self.peer_connections
                .iter()
                .cycle()
                .filter(|connection| connection.handshaked),
        ) {
            let mut conn = connection.clone();
            let payload = payload.clone();
            threads.push(thread::spawn(move || {
                conn.send(&payload).unwrap();
            }));
        }

        for thread in threads {
            thread.join().unwrap();
        }
    }

    pub fn send_to_all_peers(&self, payload: &MessagePayload) -> Result<(), String> {
        let mut threads = Vec::new();

        for connection in self.peer_connections.iter() {
            if connection.handshaked {
                let mut connection = connection.clone();
                let payload = payload.clone();
                threads.push(thread::spawn(move || {
                    if let Err(e) = connection.send(&payload) {
                        eprintln!("Error sending message to peer: {:?}", e);
                        // self.connection.handshaked = false; <-- CANT U DOIT BECAUSE ITS NOT A MUTABLE REFERENCE
                    }
                }));
            }
        }

        for thread in threads {
            thread.join().expect("Failed to join thread");
        }

        Ok(())
    }

    pub fn send_to_peer(
        &mut self,
        payload: &MessagePayload,
        peer_address: &String,
    ) -> Result<(), String> {
        if let Some(peer_connection) = self
            .peer_connections
            .iter_mut()
            .find(|connection| connection.peer_address == *peer_address)
        {
            if let Err(e) = peer_connection.send(payload) {
                eprintln!("Error sending message to peer: {:?}", e);
                peer_connection.handshaked = false;
            }
        }
        Ok(())
    }

    pub fn receive_from_all_peers(&mut self) -> Vec<(String, Vec<MessagePayload>)> {
        let mut threads = Vec::new();

        for connection in self.peer_connections.iter_mut() {
            let mut connection = connection.clone();
            threads.push(thread::spawn(move || connection.receive()));
        }

        let received_messages: Vec<_> = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .filter(|(_, messages)| !messages.is_empty())
            .collect();

        received_messages
    }

    fn get_one_peer_address(&self) -> String {
        let handshaked_connections: Vec<&P2PConnection> = self
            .peer_connections
            .iter()
            .filter(|connection| connection.handshaked)
            .collect();

        if let Some(peer_connection) = handshaked_connections.choose(&mut rand::thread_rng()) {
            peer_connection.peer_address.clone()
        } else {
            String::from("")
        }
    }
}

pub struct NodeManager<'a> {
    node_network: NodeNetwork,
    config: Config,
    logger: &'a Logger,
    blocks: Vec<Block>,
}

impl NodeManager<'_> {
    pub fn block_broadcasting(&mut self) -> Result<(), String> {
        loop {
            println!("helloooooo...")
        }
    }
    pub fn new(config: Config, logger: &Logger) -> NodeManager {
        NodeManager {
            config,
            node_network: NodeNetwork::new(),
            logger,
            blocks: vec![], // inicializar el block genesis (con el config)
        }
    }

    pub fn handshake(&mut self) {
        let payload_version_message = MessagePayload::Version(PayloadVersion::default_version());
        self.broadcast(&payload_version_message);
        self.wait_for(vec!["version", "verack"]);
    }

    pub fn wait_for(&mut self, commands: Vec<&str>) -> Vec<(String, Vec<MessagePayload>)> {
        let mut matched_messages: Vec<(String, Vec<MessagePayload>)> = Vec::new();

        let received_messages = self.node_network.receive_from_all_peers();

        for (peer_address, messages) in received_messages.iter() {
            let mut matched_peer_messages = Vec::new();

            for message in messages {
                match message {
                    MessagePayload::Verack => {
                        self.logger
                            .log(format!("Received verack from {}", peer_address));
                        self.node_network.handshake_complete(&peer_address);
                        if commands.contains(&"verack") {
                            matched_peer_messages.push(MessagePayload::Verack);
                        }
                    }
                    MessagePayload::Version(version) => {
                        self.send_to(peer_address.clone(), &MessagePayload::Verack);
                        self.logger
                            .log(format!("Received version from {}", peer_address));
                        if commands.contains(&"version") {
                            matched_peer_messages.push(MessagePayload::Version(version.clone()));
                        }
                    }
                    MessagePayload::BlockHeader(blocks) => {
                        self.logger
                            .log(format!("Received block headers from {}", peer_address));

                        // Primeros headers
                        if self.get_blocks().len() == 0 {
                            if commands.contains(&"headers") {
                                matched_peer_messages
                                    .push(MessagePayload::BlockHeader(blocks.clone()));
                            }
                            self.blocks.extend(blocks.clone());
                            Block::encode_blocks_to_file(&blocks, "block_headers.bin");
                        }

                        // Continuidad de la blockchain
                        if let Some(actual_last_block) = self.blocks.last() {
                            match blocks.first() {
                                Some(first_block) => {
                                    if actual_last_block.get_hash() == first_block.get_prev() {
                                        if commands.contains(&"headers") {
                                            // only i want to save msg on correct blockchain integrity
                                            matched_peer_messages
                                                .push(MessagePayload::BlockHeader(blocks.clone()));
                                        }
                                        self.blocks.extend(blocks.clone());
                                        Block::encode_blocks_to_file(&blocks, "block_headers.bin");
                                    }
                                }
                                None => {}
                            }
                        }
                    }
                    MessagePayload::Block(block) => {
                        self.logger
                            .log(format!("Received block from {}", peer_address));

                        if commands.contains(&"block") {
                            matched_peer_messages.push(MessagePayload::Block(block.clone()));
                        }

                        if let Some(index) = self.get_block_index_by_prev_hash(block.get_prev()) {
                            self.blocks[index] = block.clone();
                        }
                    }
                    MessagePayload::Inv(inv) => {
                        self.logger
                            .log(format!("Received inv from {}", peer_address));

                        if commands.contains(&"inv") {
                            matched_peer_messages.push(MessagePayload::Inv(inv.clone()));
                        }
                    }

                    _ => {}
                }
            }
            matched_messages.push((peer_address.clone(), matched_peer_messages));
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
            .resolve_hostname(&self.config.dns, self.config.port)
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
    pub fn send(&self, messages: Vec<&MessagePayload>) {
        self.node_network.send_messages(messages);
    }

    pub fn receive_all(&mut self) -> Vec<(String, Vec<MessagePayload>)> {
        self.node_network.receive_from_all_peers()
    }

    fn headers_first(&mut self) {
        let file_path = "block_headers.bin";

        if fs::metadata(file_path).is_ok() {
            // Blocks file already exists, no need to perform initial block download
            self.blocks = Block::decode_blocks_from_file(file_path);
        }
        println!("{:?} blocks loaded by file", self.blocks.len());
        self.initial_block_headers_download();
    }

    fn initial_block_headers_download(&mut self) {
        let mut last_block: [u8; 32] = if self.blocks.len() == 0 {
            get_hash_block_genesis()
        } else {
            let last_block_found = self.blocks.last().unwrap();
            last_block_found.get_hash()
        };

        let mut is_finished: bool = false;

        while !is_finished {
            let messages: Vec<MessagePayload> = self.send_get_headers_with_block_hash(&last_block);

            if let Some(block) = self.blocks.last() {
                last_block = block.get_hash().clone();
            }

            is_finished = messages.is_empty();
        }
    }

    fn send_get_headers_with_block_hash(&mut self, block_hash: &[u8; 32]) -> Vec<MessagePayload> {
        let stop_hash = [0u8; 32];

        let mut hash_reversed: [u8; 32] = block_hash.clone();
        hash_reversed.reverse();

        let payload_get_headers = PayloadGetHeaders::new(70015, 1, hash_reversed, stop_hash);
        let get_headers_message = MessagePayload::GetHeaders(payload_get_headers);

        let address = self.get_random_peer_address();
        self.send_to(address.clone(), &get_headers_message);
        let response: Vec<(String, Vec<MessagePayload>)> = self.wait_for(vec!["headers"]);
        filter_by(response, address)
    }

    pub fn initial_block_download(&mut self) -> Result<(), String> {
        self.headers_first();
        self.blocks_download();
        Ok(())
    }

    fn blocks_download(&mut self) {
        if let Some(timestamp) = date_to_timestamp("2023-04-11") {
            // TODO integrar fecha del config &self.config.download_blocks_since_date) {

            let blocks = self.get_blocks();

            let mut index = match self.get_block_index_by_timestamp(timestamp) {
                Some(index) => index,
                None => blocks.len(),
            };

            while index < blocks.len() {
                let block = blocks[index].clone();

                let mut block_hash: [u8; 32] = block.get_prev();
                block_hash.reverse();
                self.block_download_since_block_hash(&block_hash);

                index += 500;
            }
        }
    }

    fn block_download_since_block_hash(&mut self, block_hash: &[u8; 32]) {
        let stop_hash = [0u8; 32];

        let get_blocks_message =
            MessagePayload::GetBlocks(PayloadGetBlocks::new(70015, 1, *block_hash, stop_hash));

        // Send get block messages
        let address = self.get_random_peer_address();
        self.send_to(address.clone(), &get_blocks_message);

        // Receive inv messages
        let response = self.wait_for(vec!["inv"]);
        let messages = filter_by(response, address.clone());

        for message_inv in messages.iter() {
            if let MessagePayload::Inv(inventories) = message_inv {
                let get_data_message =
                    MessagePayload::GetData(PayloadGetData::new(500, inventories.clone()));
                self.send_to(address.clone(), &get_data_message);
                self.wait_for(vec!["block"]);
            }
        }
    }

    pub fn get_block_index_by_timestamp(&self, timestamp: u32) -> Option<usize> {
        for (index, block) in self.get_blocks().iter().enumerate() {
            if block.timestamp >= timestamp && block.txns.is_empty() {
                return Some(index);
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

    fn check_blockchain_integrity(&self) -> bool {
        let blocks = self.get_blocks();

        if blocks.len() == 0 {
            return true;
        }

        let mut index = 1;
        while index < blocks.len() {
            let prev_block = &blocks[index - 1];
            let actual_block = &blocks[index];

            if actual_block.get_prev() != prev_block.get_hash() {
                return false;
            }

            index += 1;
        }
        true
    }

    fn send_to(&mut self, peer_address: String, payload: &MessagePayload) {
        if let Err(e) = self.node_network.send_to_peer(payload, &peer_address) {
            self.logger
                .log(format!("Error sending message to peer: {:?}", e));
        }
    }

    fn get_random_peer_address(&self) -> String {
        self.node_network.get_one_peer_address()
    }
}

pub fn filter_by(
    messages: Vec<(String, Vec<MessagePayload>)>,
    address: String,
) -> Vec<MessagePayload> {
    let messages_from_peer = messages
        .iter()
        .find(|(peer_address, _)| peer_address == &address);
    match messages_from_peer {
        Some((_, messages)) => messages.clone(),
        None => vec![],
    }
}

fn get_hash_block_genesis() -> [u8; 32] {
    let mut hash_block_genesis: [u8; 32] = [
        0x00, 0x00, 0x00, 0x00, 0x09, 0x33, 0xea, 0x01, 0xad, 0x0e, 0xe9, 0x84, 0x20, 0x97, 0x79,
        0xba, 0xae, 0xc3, 0xce, 0xd9, 0x0f, 0xa3, 0xf4, 0x08, 0x71, 0x95, 0x26, 0xf8, 0xd7, 0x7f,
        0x49, 0x43,
    ];
    hash_block_genesis.reverse();

    hash_block_genesis
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::message::get_blocks::PayloadGetBlocks;
    use crate::node::message::get_data::PayloadGetData;
    use crate::node::message::get_headers::PayloadGetHeaders;
    use crate::node::message::version::PayloadVersion;

    #[test]
    fn test_get_all_ips_from_dns() {
        let logger = Logger::stdout();
        let config = Config::from_file("nodo.config")
            .map_err(|err| err.to_string())
            .unwrap();

        let mut node_manager = NodeManager::new(config, &logger);
        let node_network_ips = node_manager.get_initial_nodes().unwrap();
        assert_ne!(node_network_ips.len(), 0);
    }

    #[test]
    fn test_connect_node_with_external_nodes_not_refuse_connection() -> Result<(), String> {
        let logger = Logger::stdout();
        let config = Config::from_file("nodo.config").map_err(|err| err.to_string())?;

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
        node_manager.connect(vec!["5.9.73.173:18333".to_string()])?;

        let payload_version_message = MessagePayload::Version(PayloadVersion::default_version());
        node_manager.broadcast(&payload_version_message);

        let received_messages = node_manager.receive_all();

        let (_, _received_payloads) = received_messages.first().unwrap(); // TODO add an assert

        Ok(())
    }

    #[test]
    fn test_node_send_get_headers_receives_headers() -> Result<(), String> {
        let logger: Logger = Logger::stdout();
        let config = Config::from_file("nodo.config")
            .map_err(|err| err.to_string())
            .unwrap();

        let mut node_manager = NodeManager::new(config, &logger);
        node_manager.connect(vec!["93.157.187.23:18333".to_string()])?;
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
        fs::remove_file("block_headers.bin").unwrap();
        Ok(())
    }

    #[test]
    fn test_node_send_get_blocks_receives_inv() -> Result<(), String> {
        let logger: Logger = Logger::stdout();
        let config = Config::from_file("nodo.config")
            .map_err(|err| err.to_string())
            .unwrap();

        let mut node_manager = NodeManager::new(config, &logger);
        node_manager.connect(vec!["93.157.187.23:18333".to_string()])?;
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
        let response = node_manager.wait_for(vec!["inv"]);
        let messages_inv = filter_by(response, "93.157.187.23:18333".to_string());
        assert!(messages_inv.len() > 0);

        Ok(())
    }

    // #[test]
    // #[ignore]
    // fn test_node_send_get_blocks_receives_inv_sends_get_data() -> Result<(), String> {
    //     let logger: Logger = Logger::stdout();
    //     let config = Config::from_file("nodo.config")
    //         .map_err(|err| err.to_string())
    //         .unwrap();

    //     let mut node_manager = NodeManager::new(config, &logger);
    //     node_manager.connect(vec!["18.191.253.246:18333".to_string()])?;
    //     node_manager.handshake();

    //     let hash_beginning_project = get_first_hash_reversed();

    //     let stop_hash = [0u8; 32];

    //     let get_blocks_message = MessagePayload::GetBlocks(PayloadGetBlocks::new(
    //         70015,
    //         1,
    //         hash_beginning_project,
    //         stop_hash,
    //     ));

    //     node_manager.broadcast(&get_blocks_message);

    //     // Recibo inventario
    //     let response = node_manager.wait_for(vec!["inv"]);
    //     let messages = filter_by(response, "18.191.253.246:18333".to_string());

    //     match messages.first() {
    //         Some(MessagePayload::Inv(inventories)) => {

    //             let get_data_message = MessagePayload::GetData(PayloadGetData::new(inventories.len(), *inventories));

    //             // Enviar el mensaje get data
    //             node_manager.broadcast(&get_data_message);

    //             // Esperamos respuesta
    //             if let Some(MessagePayload::Block(block_payload)) = filter_by(
    //                 node_manager.wait_for(vec!["block"]),
    //                 "18.191.253.246:18333".to_string(),
    //             )
    //             .first()
    //             {
    //                 let _hash: [u8; 32] = block_payload.get_prev();

    //                 node_manager.blocks.push(block_payload.clone());
    //             }

    //         }
    //         _ => return Err("No inv message received".to_string()),
    //     }

    //     Ok(())
    // }

    #[test]
    fn test_send_get_blocks() -> Result<(), String> {
        let logger: Logger = Logger::stdout();
        let config = Config::new();

        let mut node_manager = NodeManager::new(config, &logger);
        node_manager.connect(vec!["5.9.149.16:18333".to_string()])?;
        node_manager.handshake();

        let file_path = "block_headers.bin";
        if fs::metadata(file_path).is_ok() {
            // Blocks file already exists, no need to perform initial block download
            node_manager.blocks = Block::decode_blocks_from_file(file_path);
        }

        let genesis_hash = get_first_hash_reversed();
        let stop_hash = [0u8; 32];

        let get_blocks_message: MessagePayload =
            MessagePayload::GetBlocks(PayloadGetBlocks::new(70015, 1, genesis_hash, stop_hash));

        // Send get block messages
        node_manager.send_to("5.9.149.16:18333".to_string(), &get_blocks_message);

        // Receive inv messages
        let reponse = node_manager.wait_for(vec!["inv"]);
        let messages = filter_by(reponse, "5.9.149.16:18333".to_string());

        match messages.first() {
            Some(MessagePayload::Inv(inventories)) => {
                let coso = 500; // JEJEJJ
                let get_data_message =
                    MessagePayload::GetData(PayloadGetData::new(coso, inventories.clone()));

                // Enviar el mensaje get data
                node_manager.send_to("5.9.149.16:18333".to_string(), &get_data_message);

                // Esperamos respuesta
                let result = node_manager.wait_for(vec!["block"]);
                filter_by(result, "5.9.149.16:18333".to_string());
            }
            _ => return Err("No inv message received".to_string()),
        }

        let blocks = node_manager.blocks;

        assert!(blocks[0].txns.len() > 0);

        Ok(())
    }

    #[test]
    #[ignore]
    fn test_complete_initial_block_download() -> Result<(), String> {
        let logger: Logger = Logger::stdout();
        let config = Config::from_file("nodo.config")
            .map_err(|err| err.to_string())
            .unwrap();

        let mut node_manager = NodeManager::new(config, &logger);
        node_manager.connect(vec!["5.9.149.16:18333".to_string()])?;
        node_manager.handshake();

        node_manager.initial_block_download()?;

        //assert!(node_manager.get_blocks().len() >= 2000);
        //std::fs::remove_file("block_headers.bin").unwrap();
        Ok(())
    }

    #[test]
    #[ignore]
    fn test_check_blockchain_integrity() -> Result<(), String> {
        let logger: Logger = Logger::stdout();
        let config = Config::from_file("nodo.config")
            .map_err(|err| err.to_string())
            .unwrap();

        let mut node_manager = NodeManager::new(config, &logger);
        node_manager.connect(vec!["5.9.149.16:18333".to_string()])?;
        node_manager.handshake();

        node_manager.initial_block_download()?;
        assert!(node_manager.check_blockchain_integrity());

        Ok(())
    }

    #[test]
    fn test_sends_messages_to_different_peers() -> Result<(), String> {
        let logger: Logger = Logger::stdout();
        let config = Config::new();

        let mut node_manager = NodeManager::new(config, &logger);
        node_manager.connect(vec![
            "5.9.149.16:18333".to_string(),
            "18.218.30.118:18333".to_string(),
        ])?;
        let verack1 = MessagePayload::Verack;
        let verack2 = MessagePayload::Verack;
        let verack3 = MessagePayload::Verack;

        node_manager.send(vec![&verack1, &verack2, &verack3]);
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
