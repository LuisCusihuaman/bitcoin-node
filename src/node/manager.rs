use crate::node::p2p_connection::P2PConnection;
use std::net::{IpAddr, TcpListener, ToSocketAddrs};

pub struct NodeNetwork {
    peer_connections: Vec<P2PConnection>,
}

impl NodeNetwork {
    pub fn new() -> NodeNetwork {
        NodeNetwork {
            peer_connections: vec![],
        }
    }
}

pub struct NodeManager {
    node_network: NodeNetwork,
    config: Config,
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
    pub fn get_initial_nodes(&mut self) -> Result<Vec<String>, std::io::Error> {
        let ips = self.resolve_hostname(&self.config.addrs, self.config.port)?;
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
    //pub fn peers(&self) -> Vec<IpAddr> {
    //    self.node_network.clone()
    //}
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
