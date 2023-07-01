use crate::logger::log;
use crate::net::message::block::Block;
use crate::net::message::get_data_inv::Inventory;
use crate::net::message::get_data_inv::PayloadGetDataInv;
use crate::net::message::get_headers::PayloadGetHeaders;
use crate::net::message::ping_pong::PayloadPingPong;
use crate::net::message::tx::Tx;
use crate::net::message::tx_status::PayloadTxStatus;
use crate::net::message::utxos_msg::PayloadUtxosMsg;
use crate::net::message::version::PayloadVersion;
use crate::net::message::MessagePayload;
use crate::net::message::TxStatus;
use crate::net::p2p_connection::P2PConnection;
use crate::node::network::NodeNetwork;
use crate::node::utxo::generate_utxos;
use crate::node::utxo::update_utxo_set;
use crate::node::utxo::Utxo;
use crate::utils::*;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::fs;
use std::net::TcpListener;
use std::net::{IpAddr, ToSocketAddrs};
use std::sync::mpsc::channel;
use std::sync::mpsc::Sender;
use std::thread::spawn;
use crate::node::config::Config;

use super::utxo::get_utxos_by_address;

pub struct NodeManager {
    node_network: NodeNetwork,
    config: Config,
    logger_tx: Sender<String>,
    blocks: Vec<Block>,
    utxo_set: HashMap<[u8; 20], Vec<Utxo>>, // utxo_set is a Hash with key <address> and value <OutPoint>
    blocks_btreemap: BTreeMap<[u8; 32], usize>,
    wallet_tnxs: HashMap<[u8; 32], TxStatus>,
}

impl NodeManager {
    pub fn new(config: Config, logger_tx: Sender<String>) -> NodeManager {
        let logger_tx_cloned = logger_tx.clone();
        NodeManager {
            config,
            node_network: NodeNetwork::new(logger_tx),
            logger_tx: logger_tx_cloned,
            blocks: vec![], // inicializar el block genesis (con el config)
            utxo_set: HashMap::new(),
            blocks_btreemap: BTreeMap::new(),
            wallet_tnxs: HashMap::new(),
        }
    }

    pub fn handshake(&mut self) {
        let payload_version_message = MessagePayload::Version(PayloadVersion::default_version());
        self.broadcast(&payload_version_message);
        self.wait_for(vec!["version", "verack"]);
    }

    // getBalance (wallet a nodo)
    // Si balance > amount
    // pedir UTXO -> getUTXOs (wallet a nodos)
    // devolver la lista de UTXO -> sendUTXOs (del nodo a wallet)
    // sendTx (wallet a nodo)
    // sendTx (nodo a nodos)

    pub fn wait_for(&mut self, commands: Vec<&str>) -> Vec<(String, Vec<MessagePayload>)> {
        let mut matched_messages: Vec<(String, Vec<MessagePayload>)> = Vec::new();

        let received_messages = self.node_network.receive_from_all_peers();

        for (peer_address, messages) in received_messages.iter() {
            let mut matched_peer_messages = Vec::new();

            for message in messages {
                let logger_tx = self.logger_tx.clone();

                match message {
                    MessagePayload::Verack => {
                        log(logger_tx, format!("Received verack from {}", peer_address));
                        self.node_network.handshake_complete(peer_address);
                        if commands.contains(&"verack") {
                            matched_peer_messages.push(MessagePayload::Verack);
                        }
                    }
                    MessagePayload::Version(version) => {
                        log(
                            self.logger_tx.clone(),
                            format!("Received version from {}", peer_address),
                        );
                        self.send_to(peer_address.clone(), &MessagePayload::Verack);

                        if commands.contains(&"version") {
                            matched_peer_messages.push(MessagePayload::Version(version.clone()));
                        }
                    }
                    MessagePayload::BlockHeader(blocks) => {
                        // Primeros headers
                        if self.get_blocks().is_empty() {
                            if commands.contains(&"headers") {
                                matched_peer_messages
                                    .push(MessagePayload::BlockHeader(blocks.clone()));
                            }
                            self.blocks.extend(blocks.clone());
                            Block::encode_blocks_to_file(blocks, "block_headers.bin");
                        }

                        // Continuidad de la blockchain
                        if let Some(actual_last_block) = self.blocks.last() {
                            if let Some(first_block) = blocks.first() {
                                if actual_last_block.get_hash() == first_block.get_prev() {
                                    if commands.contains(&"headers") {
                                        // only i want to save msg on correct blockchain integrity
                                        matched_peer_messages
                                            .push(MessagePayload::BlockHeader(blocks.clone()));
                                    }
                                    self.blocks.extend(blocks.clone());
                                    Block::encode_blocks_to_file(blocks, "block_headers.bin");
                                }
                            }
                        }
                        log(
                            self.logger_tx.clone(),
                            format!("Received {} headers from {}", blocks.len(), peer_address),
                        );
                    }
                    MessagePayload::Block(block) => {
                        if commands.contains(&"block") {
                            matched_peer_messages.push(MessagePayload::Block(block.clone()));
                        }

                        if !block.is_valid() {
                            log(self.logger_tx.clone(), format!("Block is not valid"));
                            continue;
                        }

                        let prev_index = match self.blocks_btreemap.get(&block.get_prev()) {
                            Some(index) => index.clone(),
                            None => match self.get_block_index_by_hash(block.get_prev()) {
                                Some(index) => index,
                                None => {
                                    log(
                                        self.logger_tx.clone(),
                                        format!("Previous block not found in the blockchain"),
                                    );
                                    continue;
                                }
                            },
                        };

                        if !self.utxo_set.is_empty() {
                            self.update_utxo_set(block.clone());
                        }

                        self.update_unconfirm_txns(block.clone().txns);

                        // For genesis block
                        if block.get_prev()
                            == [
                                0, 0, 0, 0, 9, 51, 234, 1, 173, 14, 233, 132, 32, 151, 121, 186,
                                174, 195, 206, 217, 15, 163, 244, 8, 113, 149, 38, 248, 215, 127,
                                73, 67,
                            ]
                        {
                            self.blocks[0] = block.clone();
                            log(
                                self.logger_tx.clone(),
                                format!("updated block with index 0"),
                            );
                        } else if prev_index + 1 == self.blocks.len() {
                            self.blocks.push(block.clone());
                            log(
                                self.logger_tx.clone(),
                                format!("new block with index {}", prev_index + 1),
                            );
                        } else {
                            self.blocks[prev_index + 1] = block.clone();
                            log(
                                self.logger_tx.clone(),
                                format!("updated block with index {}", prev_index + 1),
                            );
                        }
                    }
                    MessagePayload::Inv(inv) => {
                        log(
                            self.logger_tx.clone(),
                            format!("Received inv from {}", peer_address),
                        );

                        let inv = inv.clone();
                        let inv2 = inv.clone();
                        if inv.inv_type == 2 {
                            // TODO: make type
                            self.send_to(
                                peer_address.clone(),
                                &MessagePayload::GetData(PayloadGetDataInv {
                                    count: inv.count,
                                    inv_type: inv.inv_type,
                                    inventories: inv.inventories.clone(),
                                }),
                            );
                            self.wait_for(vec!["blocks"]);
                        }

                        if commands.contains(&"inv") {
                            matched_peer_messages.push(MessagePayload::Inv(inv2.clone()));
                        }
                    }
                    MessagePayload::Ping(ping) => {
                        log(
                            self.logger_tx.clone(),
                            format!("Received ping from {}", peer_address),
                        );

                        let ping1 = ping.clone();

                        self.send_to(
                            peer_address.clone(),
                            &MessagePayload::Pong(PayloadPingPong { nonce: ping1.nonce }),
                        );

                        if commands.contains(&"ping") {
                            matched_peer_messages.push(MessagePayload::Ping(ping.clone()));
                        }
                    }
                    MessagePayload::Pong(pong) => {
                        log(
                            self.logger_tx.clone(),
                            format!("Received pong from {}", peer_address),
                        );
                        if commands.contains(&"pong") {
                            matched_peer_messages.push(MessagePayload::Pong(pong.clone()));
                        }
                    }
                    MessagePayload::GetUTXOs(payload) => {
                        let utxos = get_utxos_by_address(&self.utxo_set, payload.address.clone());

                        if utxos.is_empty() {
                            log(
                                self.logger_tx.clone(),
                                format!(
                                    "No utxos found for address {}",
                                    get_address_base58(payload.address)
                                ),
                            );
                        }

                        self.send_to(
                            peer_address.clone(),
                            &MessagePayload::UTXOs(PayloadUtxosMsg {
                                utxos: utxos.clone(),
                            }),
                        );
                    }
                    MessagePayload::Tx(tx) => {
                        log(
                            self.logger_tx.clone(),
                            format!("Received tx from {}", peer_address),
                        );

                        let tx_message = MessagePayload::Tx(tx.clone());

                        self.wallet_tnxs.insert(tx.id, TxStatus::Unconfirmed);
                        self.broadcast(&tx_message);
                    }
                    MessagePayload::GetTxStatus(tx) => {
                        let tx_status = match self.wallet_tnxs.get(&tx.id) {
                            Some(status) => status.clone(),
                            None => TxStatus::Unknown,
                        };

                        self.send_to(
                            peer_address.clone(),
                            &MessagePayload::TxStatus(PayloadTxStatus {
                                tx_id: tx.id.clone(),
                                status: tx_status,
                            }),
                        );
                    }
                    _ => {
                        log(
                            self.logger_tx.clone(),
                            format!("Received unknown message from {}", peer_address),
                        );
                    }
                }
            }
            matched_messages.push((peer_address.clone(), matched_peer_messages));
        }
        matched_messages
    }

    fn update_unconfirm_txns(&mut self, tnxs: Vec<Tx>) {
        for tx in tnxs {
            if self.wallet_tnxs.contains_key(&tx.id) {
                self.wallet_tnxs.insert(tx.id, TxStatus::Confirmed);
            }
        }
    }

    fn update_utxo_set(&mut self, block: Block) {
        for tx in block.txns {
            generate_utxos(&mut self.utxo_set, &tx);
            update_utxo_set(&mut self.utxo_set, &tx);
        }
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
            match P2PConnection::connect(addr, self.logger_tx.clone()) {
                Ok(peer_connection) => {
                    self.node_network.peer_connections.push(peer_connection);
                }
                Err(_) => {
                    //TODO: only continue on timeout error
                    log(
                        self.logger_tx.clone(),
                        format!("Error connecting to peer {}", addr),
                    );
                    continue;
                }
            }
        }
        Ok(())
    }

    pub fn broadcast(&mut self, payload: &MessagePayload) {
        if let Err(e) = self.node_network.send_to_all_peers(payload) {
            log(
                self.logger_tx.clone(),
                format!("Error broadcasting message to peers: {:?}", e),
            );
        }
    }
    pub fn send(&self, messages: Vec<MessagePayload>) {
        self.node_network.send_messages(messages);
    }

    pub fn receive_all(&mut self) -> Vec<(String, Vec<MessagePayload>)> {
        self.node_network.receive_from_all_peers()
    }

    fn headers_first(&mut self) {
        let file_path = "block_headers.bin";

        if fs::metadata(file_path).is_ok() {
            // Blocks file already exists, no need to perform initial block download
            log(
                self.logger_tx.clone(),
                format!("Loading header blocks from file"),
            );
            self.blocks = Block::decode_blocks_from_file(file_path);
        }

        log(
            self.logger_tx.clone(),
            format!("{:?} blocks loaded by file", self.blocks.len()),
        );
        self.initial_block_headers_download();
    }

    fn initial_block_headers_download(&mut self) {
        let mut last_block: [u8; 32] = if self.blocks.is_empty() {
            get_hash_block_genesis()
        } else {
            let last_block_found = self.blocks.last().unwrap();
            last_block_found.get_hash()
        };

        let mut is_finished: bool = false;

        while !is_finished {
            let messages: Vec<MessagePayload> = self.send_get_headers_with_block_hash(&last_block);

            if let Some(block) = self.blocks.last() {
                last_block = block.get_hash();
            }

            is_finished = messages.is_empty();
        }

        self.init_block_btreemap();
    }

    fn init_block_btreemap(&mut self) {
        let blocks = self.get_blocks();

        log(
            self.logger_tx.clone(),
            format!("Generating block btreemap with {} blocks", blocks.len()),
        );

        for (index, block) in blocks.iter().enumerate() {
            self.blocks_btreemap.insert(block.get_hash(), index);
        }
    }

    fn send_get_headers_with_block_hash(&mut self, block_hash: &[u8; 32]) -> Vec<MessagePayload> {
        let stop_hash = [0u8; 32];

        let mut hash_reversed: [u8; 32] = *block_hash;
        hash_reversed.reverse();

        let payload_get_headers =
            PayloadGetHeaders::new(70015, 1, hash_reversed.to_vec(), stop_hash.to_vec());
        let get_headers_message = MessagePayload::GetHeaders(payload_get_headers);

        let address = self.get_random_peer_address();
        self.send_to(address.clone(), &get_headers_message);
        let response: Vec<(String, Vec<MessagePayload>)> = self.wait_for(vec!["headers"]);
        filter_by(response, address)
    }

    pub fn initial_block_download(&mut self) -> Result<(), String> {
        self.headers_first();
        self.blocks_download();
        self.init_utxo_set();
        Ok(())
    }

    fn init_utxo_set(&mut self) {
        let blocks = self.get_blocks();

        log(
            self.logger_tx.clone(),
            format!("Generating utxo set with {} blocks", blocks.len()),
        );

        for block in blocks.clone() {
            if block.txns.is_empty() {
                continue;
            }
            self.update_utxo_set(block);
        }
    }

    fn blocks_download(&mut self) {
        let timestamp = match date_to_timestamp("2023-06-07") {
            Some(timestamp) => timestamp,
            None => panic!("Error parsing date"),
        };

        // TODO: Integrate date from self.config.download_blocks_since_date
        let blocks = self.get_blocks();

        let index = match self.get_block_index_by_timestamp(timestamp) {
            Some(index) => index,
            None => blocks.len(),
        };

        let get_data_messages: &Vec<MessagePayload> = &blocks[index..]
            .chunks(25)
            .map(|chunk| {
                let inventories: Vec<Inventory> = chunk
                    .iter()
                    .map(|block| {
                        let mut block_hash: [u8; 32] = block.get_hash();
                        block_hash.reverse();

                        Inventory {
                            inv_type: 2,
                            hash: block_hash.to_vec(),
                        }
                    })
                    .collect();

                MessagePayload::GetData(PayloadGetDataInv {
                    count: inventories.len(),
                    inv_type: inventories[0].inv_type,
                    inventories: inventories,
                })
            })
            .collect();

        self.send(get_data_messages.clone());
        self.wait_for(vec!["block"]);
    }

    pub fn get_block_index_by_timestamp(&self, timestamp: u32) -> Option<usize> {
        for (index, block) in self.get_blocks().iter().enumerate() {
            if block.timestamp >= timestamp && block.txns.is_empty() {
                return Some(index);
            }
        }
        None
    }

    pub fn get_block_index_by_hash(&self, prev_hash: [u8; 32]) -> Option<usize> {
        for (index, block) in self.get_blocks().iter().enumerate().rev() {
            if block.get_hash() == prev_hash {
                return Some(index);
            }
        }

        // For genesis block
        if prev_hash
            == [
                0, 0, 0, 0, 9, 51, 234, 1, 173, 14, 233, 132, 32, 151, 121, 186, 174, 195, 206,
                217, 15, 163, 244, 8, 113, 149, 38, 248, 215, 127, 73, 67,
            ]
        {
            return Some(0);
        }

        None
    }

    pub fn send_to(&mut self, peer_address: String, payload: &MessagePayload) {
        if let Err(e) = self.node_network.send_to_peer(payload, &peer_address) {
            log(
                self.logger_tx.clone(),
                format!("Error sending message to peer: {:?}", e),
            );
        }
    }

    fn get_random_peer_address(&self) -> String {
        self.node_network.get_one_peer_address()
    }

    pub fn run(&mut self) {
        let (sender, rx) = channel();
        let listener = TcpListener::bind("127.0.0.1:18333").unwrap();
        let logger_tx = self.logger_tx.clone();

        log(
            self.logger_tx.clone(),
            format!("Listening on port 18333..."),
        );

        spawn(move || {
            listen_for_conn(logger_tx, listener, sender);
        });

        loop {
            self.wait_for(vec![]);

            match rx.try_recv() {
                Ok(conn) => {
                    self.node_network.peer_connections.push(conn);
                }
                Err(_) => {}
            }
        }
    }
}

fn listen_for_conn(
    logger_tx: Sender<String>,
    listener: TcpListener,
    sender: Sender<P2PConnection>,
) {
    loop {
        match listener.accept() {
            Ok((stream, addr)) => {
                stream.set_nonblocking(true).unwrap();

                log(
                    logger_tx.clone(),
                    format!("Wallet connected successfully: {addr}"),
                );

                let connection = P2PConnection {
                    logger_tx: logger_tx.clone(),
                    handshaked: true,
                    tcp_stream: stream,
                    peer_address: addr.to_string(),
                };

                sender.send(connection).unwrap();
            }
            Err(e) => {
                log(
                    logger_tx.clone(),
                    format!("couldn't connect to wallet: {e:?}"),
                );
            }
        }
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
