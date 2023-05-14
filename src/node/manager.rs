use crate::node::message::{Encoding, MessagePayload};
use crate::node::p2p_connection::P2PConnection;
use std::net::{IpAddr, ToSocketAddrs};
use std::thread;
use std::time::Duration;
use crate::net::request::Request;
use crate::net::response::Response;
use crate::net::router::Router;
use crate::net::server::Server;
use crate::node::message::version::PayloadVersion;

pub struct NodeNetwork {
    pub peer_connections: Vec<P2PConnection>,
}

impl NodeNetwork {
    pub fn new() -> NodeNetwork {
        NodeNetwork {
            peer_connections: vec![],
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
            .filter_map(Result::ok).collect()
    }
}

pub struct NodeManager {
    node_network: NodeNetwork,
    config: Config,
}

impl NodeManager {
    pub fn wait_for(&mut self, commands: Vec<&str>) -> Vec<MessagePayload> {
        let mut matched_messages = Vec::new();
        loop {
            let received_messages = self.node_network.receive_from_all_peers();
            for (peer_address, message) in received_messages.first() {
                match message.first().unwrap() {
                    MessagePayload::Verack => {
                        println!("Received verack from {}", peer_address);
                        if commands.contains(&"verack") {
                            matched_messages.push(MessagePayload::Verack);
                        }
                    }
                    MessagePayload::Version(version) => {
                        self.broadcast(&MessagePayload::Verack);
                        if commands.contains(&"version") {
                            println!("Received version from {}", peer_address);
                            matched_messages.push(MessagePayload::Version(version.clone()));
                        }
                    }
                }
            }
            if matched_messages.len() == commands.len() {
                break;
            }
        }
        matched_messages
    }
}


pub struct Config {
    pub addrs: String,
    pub port: u16,
}

impl NodeManager {
    pub fn new(config: Config) -> NodeManager {
        NodeManager {
            config,
            node_network: NodeNetwork::new(),
        }
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
        let ips = self.resolve_hostname(&self.config.addrs, self.config.port)
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
                    //println!("Error connecting to peer {}: {}", addr, e);
                    continue;
                }
            }
        }
        Ok(())
    }

    pub fn broadcast(&mut self, payload: &MessagePayload) {
        self.node_network.send_to_all_peers(&payload);
    }

    pub fn receive_all(&mut self) -> Vec<(String, Vec<MessagePayload>)> {
        self.node_network.receive_from_all_peers()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::message::version::PayloadVersion;

    #[test]
    fn test_get_all_ips_from_dns() {
        let mut node_manager = NodeManager::new(Config {
            addrs: "seed.testnet.bitcoin.sprovoost.nl".to_string(),
            port: 80,
        });
        let node_network_ips = node_manager.get_initial_nodes().unwrap();
        assert_ne!(node_network_ips.len(), 0);
    }

    #[test]
    fn test_connect_node_with_external_nodes_not_refuse_connection() -> Result<(), String> {
        let mut node_manager = NodeManager::new(Config {
            addrs: "seed.testnet.bitcoin.sprovoost.nl".to_string(),
            port: 80,
        });
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
        let mut node_manager = NodeManager::new(Config {
            addrs: "seed.testnet.bitcoin.sprovoost.nl".to_string(),
            port: 80,
        });
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
}
