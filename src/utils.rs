pub fn get_offset(buff: &[u8]) -> usize {
    let i: u8 = buff[0];

    if i == 0xfdu8 as u8 {
        2 as usize
    } else if i == 0xfeu8 as u8 {
        4 as usize
    } else if i == 0xffu8 as u8 {
        8 as usize
    } else {
        1 as usize // EDU PROBA CON 1 XD O.o
    }
}

pub fn read_le(bytes: &[u8]) -> usize {
    let mut result: usize = 0;
    let len_bytes = bytes.len();

    for i in 0..len_bytes {
        result |= (bytes[i] as usize) << (i * 8);
    }
    result
}

pub fn read_be(buffer: &[u8]) -> usize {
    let mut result = 0;
    for i in 0..buffer.len() {
        result += (buffer[i] as usize) << (8 * (buffer.len() - i - 1));
    }
    result
}

fn ipv4_to_ipv6_format(addr_recv: &String) -> ([u8; 16], u16) {
    match addr_recv.parse::<std::net::SocketAddr>() {
        Ok(addr) => {
            let ip: std::net::IpAddr = addr.ip();
            let port = addr.port();
            let mut ipv6 = [0u8; 16];
            match ip {
                std::net::IpAddr::V4(v4) => {
                    let octets = v4.octets();
                    ipv6[10] = 0xff;
                    ipv6[11] = 0xff;
                    ipv6[12] = octets[0];
                    ipv6[13] = octets[1];
                    ipv6[14] = octets[2];
                    ipv6[15] = octets[3];
                }
                std::net::IpAddr::V6(v6) => {
                    ipv6.copy_from_slice(&v6.octets());
                }
            }
            (ipv6, port)
        }
        Err(_) => ([0u8; 16], 0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_to_ipv6_format() {
        let (ipv6, port) = ipv4_to_ipv6_format(&"127.0.0.1:18333".to_string());
        assert_eq!(ipv6, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 127, 0, 0, 1]);
        assert_eq!(port, 18333);
    }
}

