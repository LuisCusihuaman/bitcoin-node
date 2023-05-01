use std::net::TcpStream;
use std::time::Duration;

pub struct P2PConnection {
    peer_address: String,
    tcp_stream: TcpStream,
}

impl P2PConnection {
    pub fn connect(addr: &String) -> Result<Self, String> {
        // TODO: save the peers that not pass the timeout
        let tcp_stream = TcpStream::connect_timeout(&addr.parse().unwrap(), Duration::from_secs(5))
            .map_err(|e| e.to_string())?;
        tcp_stream
            .set_nonblocking(true)
            .map_err(|e| e.to_string())?;
        Ok(Self {
            peer_address: addr.clone(),
            tcp_stream,
        })
    }
}
