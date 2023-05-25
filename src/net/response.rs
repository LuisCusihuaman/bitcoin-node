use std::io::Write;
use std::net::TcpStream;

pub struct Response {
    pub body: String,
}

impl Response {
    pub fn new(body: String) -> Response {
        Response { body }
    }
    pub fn json(body: String) -> Response {
        //TODO: check how to parse string to json
        // serialize Json converter {}
        Response::new(body)
    }
    pub fn result_into(&self, stream: &mut TcpStream) {
        let result = self.body.to_string();
        let _ = stream.write_all(result.as_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_response() {
        let response = Response::new("test".to_string());
        assert_eq!(response.body, "test".to_string());
    }

    // TODO: Agregar test para result_into
}
