use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;

pub struct Request {
    path: String,
    params: HashMap<String, String>,
}

impl Request {
    pub fn parse(stream: &mut TcpStream) -> Request {
        parse_internal(stream)
    }
    pub fn path(&self) -> String {
        self.path.to_string()
    }
}

fn parse_internal<T: Read + Write>(stream: T) -> Request {
    let mut lines = String::new();
    let mut reader = BufReader::new(stream);
    let _ = reader.read_line(&mut lines);
    let mut line = lines.split_whitespace();

    let path = match line.nth(0) {
        Some(e) => e,
        None => "/",
    };

    let path_querys: Vec<&str> = path.split("?").collect();
    let req_path = path_querys[0]; //?a=1
    let query_string = match path_querys.get(1).or(None) {
        Some(q) => {
            let tags: HashMap<String, String> = q
                .split('&')
                .map(|kv| kv.split('=').collect::<Vec<&str>>())
                .map(|vec| {
                    assert_eq!(vec.len(), 2);
                    (vec[0].to_string(), vec[1].to_string())
                })
                .collect();
            tags
        }
        None => HashMap::new(),
    };

    Request {
        path: req_path.to_string(),
        params: query_string,
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use std::io;

    /// MockTcpStream es una mock que implementa los traits Read y Write, los mismos que implementa el TcpStream
    struct MockTcpStream {
        read_data: Vec<u8>,
        write_data: Vec<u8>,
    }

    impl Read for MockTcpStream {
        /// Lee bytes del stream hasta completar el buffer y devuelve cuantos bytes fueron leidos
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.read_data.as_slice().read(buf)
        }
    }

    impl Write for MockTcpStream {
        /// Escribe el valor del buffer en el stream y devuelve cuantos bytes fueron escritos
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.write_data.write(buf)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.write_data.flush()
        }
    }

    #[test]
    fn test_parse_with_valid_params() {
        let mut mock = MockTcpStream {
            read_data: "/get?name=pepito\n".as_bytes().to_vec(),
            write_data: Vec::new(),
        };

        let req = parse_internal(&mut mock);

        assert_eq!(req.path, "/get");
        assert_eq!(req.params.len(), 1);
    }
}
