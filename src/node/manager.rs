use crate::logger::Logger;
use crate::net::request::Request;
use crate::net::response::Response;
use crate::net::router::Router;
use crate::net::server::Server;
use crate::node::block::Block;
use crate::node::message::version::PayloadVersion;
use crate::node::message::{Encoding, MessagePayload};
use crate::node::p2p_connection::P2PConnection;
use std::net::{IpAddr, ToSocketAddrs};
use std::thread;
use std::thread::Thread;
use std::time::Duration;

pub struct Config {
    pub addrs: String,
    pub port: u16,
}

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
            println!("Handshake complete");
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
        thread::sleep(Duration::from_millis(500));
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
            Some( (peer_address, messages)) => (peer_address.clone(), messages.clone()),
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::message::get_headers::PayloadGetHeaders;
    use crate::node::message::version::PayloadVersion;

    #[test]
    fn test_get_all_ips_from_dns() {
        let logger = Logger::stdout();
        let mut node_manager = NodeManager::new(
            Config {
                addrs: "seed.testnet.bitcoin.sprovoost.nl".to_string(),
                port: 80,
            },
            &logger,
        );
        let node_network_ips = node_manager.get_initial_nodes().unwrap();
        assert_ne!(node_network_ips.len(), 0);
    }

    #[test]
    fn test_connect_node_with_external_nodes_not_refuse_connection() -> Result<(), String> {
        let logger = Logger::stdout();
        let mut node_manager = NodeManager::new(
            Config {
                addrs: "seed.testnet.bitcoin.sprovoost.nl".to_string(),
                port: 80,
            },
            &logger,
        );
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
    fn test_node_send_and_recive() -> Result<(), String> {
        let logger = Logger::stdout();
        let mut node_manager = NodeManager::new(
            Config {
                addrs: "seed.testnet.bitcoin.sprovoost.nl".to_string(),
                port: 80,
            },
            &logger,
        );
        let node_network_ips = node_manager.get_initial_nodes().unwrap();
        let first_address_from_dns: Vec<String> = node_network_ips
            .iter()
            .map(|ip| format!("{}:18333", ip))
            .take(1)
            .collect();
        node_manager.connect(first_address_from_dns.clone())?;

        let payload_version_message = MessagePayload::Version(PayloadVersion::default_version());
        node_manager.broadcast(&payload_version_message);

        let received_messages = node_manager.receive_all();
        let (_, received_payloads) = received_messages.first().unwrap();
        //if let MessagePayload::Version(payload_version) = received_payloads {
        //    assert_eq!(payload_version.addr_trans_port, 0 /* default_version */);
        //}
        Ok(())
    }

    #[test]
    fn test_node_send_get_headers() -> Result<(), String> {
        let logger = Logger::stdout();
        let mut node_manager = NodeManager::new(
            Config {
                addrs: "seed.testnet.bitcoin.sprovoost.nl".to_string(),
                port: 80,
            },
            &logger,
        );

        let node_network_ips = node_manager.get_initial_nodes().unwrap();
        let first_address_from_dns: Vec<String> = node_network_ips
            .iter()
            .map(|ip| format!("{}:18333", ip))
            .take(1)
            .collect();
        node_manager.connect(first_address_from_dns.clone())?;

        node_manager.handshake();

        // Create getheaders message
        let hash_block_genesis: [u8; 32] = [
            0x00, 0x00, 0x00, 0x00, 0x09, 0x33, 0xea, 0x01, 0xad, 0x0e, 0xe9, 0x84, 0x20, 0x97,
            0x79, 0xba, 0xae, 0xc3, 0xce, 0xd9, 0x0f, 0xa3, 0xf4, 0x08, 0x71, 0x95, 0x26, 0xf8,
            0xd7, 0x7f, 0x49, 0x43,
        ];

        let stop_hash = [0u8; 32];

        let get_headers_message = MessagePayload::GetHeaders(PayloadGetHeaders::new(
            70015,
            1,
            hash_block_genesis,
            stop_hash,
        ));

        // Send getheaders message
        node_manager.broadcast(&get_headers_message);

        thread::sleep(Duration::from_millis(2000));
        node_manager.wait_for(vec!["headers"]);

        let blocks = node_manager.get_blocks();

        assert_ne!(blocks.len(), 0);
        Ok(())
    }

    #[test]
    fn test_complete_initial_block_download() -> Result<(), String> {
        let logger = Logger::stdout();
        let mut node_manager = NodeManager::new(
            Config {
                addrs: "seed.testnet.bitcoin.sprovoost.nl".to_string(),
                port: 80,
            },
            &logger,
        );

        let node_network_ips = node_manager.get_initial_nodes().unwrap();
        let first_address_from_dns: Vec<String> = node_network_ips
            .iter()
            .map(|ip| format!("{}:18333", ip))
            .take(1)
            .collect();
        node_manager.connect(first_address_from_dns.clone())?;

        node_manager.handshake();

        // Create getheaders message
        let hash_block_genesis: [u8; 32] = [
            0x00, 0x00, 0x00, 0x00, 0x09, 0x33, 0xea, 0x01, 0xad, 0x0e, 0xe9, 0x84, 0x20, 0x97,
            0x79, 0xba, 0xae, 0xc3, 0xce, 0xd9, 0x0f, 0xa3, 0xf4, 0x08, 0x71, 0x95, 0x26, 0xf8,
            0xd7, 0x7f, 0x49, 0x43,
        ];

        let stop_hash = [0u8; 32];

        let get_headers_message = MessagePayload::GetHeaders(PayloadGetHeaders::new(
            70015,
            1,
            hash_block_genesis,
            stop_hash,
        ));
    

        // Send getheaders message
        node_manager.broadcast(&get_headers_message);

        // Wait for headers message and parsing
        thread::sleep(Duration::from_millis(2000));
        node_manager.wait_for(vec!["headers"]);

        let last_block = match node_manager.get_blocks().last(){
            Some(bloque) => bloque.clone(),
            None => return Err("No blocks received".to_string()), // Err(Error::NoBlocksReceived)
        };

        let payload_get_headers_2 = PayloadGetHeaders::new(70015, 1, last_block.get_prev(), stop_hash);
        let get_headers_message_2 = MessagePayload::GetHeaders(payload_get_headers_2);
        
        node_manager.broadcast(&get_headers_message_2);

        // Wait for headers message and parsing
        thread::sleep(Duration::from_millis(2000));
        node_manager.wait_for(vec!["headers"]);

        Ok(())
    }
}
