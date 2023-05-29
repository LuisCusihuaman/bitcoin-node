use crate::net::request::Request;
use crate::net::response::Response;
use crate::node::manager::NodeManager;

pub type Handler = fn(&mut NodeManager, Request) -> Response;

pub struct Route {
    pub pattern: String,
    pub callback: Handler,
}

pub struct Router {
    pub routes: Vec<Route>,
}

impl Router {
    pub fn new() -> Router {
        Router { routes: Vec::new() }
    }

    pub fn branch(&mut self, pattern: &str, f: Handler) {
        let r = Route {
            pattern: String::from(pattern),
            callback: f,
        };
        self.routes.push(r);
    }

    pub fn get_cant_branch(&mut self) -> usize {
        self.routes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_router_must_be_empty() {
        let mut router = Router::new();
        let _pattern = String::from("/home");
        let respuesta_esperado: usize = 0;

        assert_eq!(respuesta_esperado, router.get_cant_branch());
    }
}
