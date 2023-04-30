use std::net::{IpAddr, ToSocketAddrs};

pub struct NodeManager {
    node_network: Vec<IpAddr>,
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
            node_network: Vec::new(),
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
    pub fn load_initial_nodes(&mut self) -> Result<(), std::io::Error> {
        let ips = self.resolve_hostname(&self.config.addrs, self.config.port)?;
        self.node_network
            .extend(ips.into_iter().filter(|addr| addr.is_ipv4()));
        Ok(())
    }
    pub fn peers(&self) -> Vec<IpAddr> {
        self.node_network.clone()
    }
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
        node_manager.load_initial_nodes().unwrap();
        assert_ne!(node_manager.node_network.len(), 0);
    }
}
