use app::net::request::Request;
use app::net::response::Response;
use app::net::router::Router;
use app::net::server::Server;
use app::node::handler::handler_handshake;
use app::node::manager::{Config, NodeManager};

fn main() {
    let mut router = Router::new();
    router.branch("/test", handler_handshake);
    let mut server = Server::new(router);
    server.run(&"127.0.0.1:8090").unwrap();
}
