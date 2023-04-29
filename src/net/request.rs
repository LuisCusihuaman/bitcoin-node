pub struct Request {}

impl Request {
    pub fn new() -> Request {
        Request {}
    }

    pub fn json(s: &str) -> String {
        let mut s = String::from(s);
        s.push_str("json");
        s
    }
}
