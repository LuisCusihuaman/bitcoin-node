use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::net::TcpStream;
pub struct Request {
    path: String,
    params: HashMap<String, String>,
}

impl Request {
    pub fn parse(stream: &mut TcpStream) -> Request {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_parse() {
        //let mut streamMockFromString = Buffer::new();
        //streamMockFromString.write(b"GET /get HTTP/1.1\r\n\r\n");
        //let req = Request::parse(&mut streamMockFromString);
        //assert_eq!(req.path, "/get");
        //assert_eq!(req.params.len(), 0);
    }
}
