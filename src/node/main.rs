use app::net::request::Request;
use app::net::response::Response;
use app::net::router::Router;
use app::net::server::Server;
use app::node::handler::handler_handshake;
use std::env;
use std::error::Error;
use std::io;

use app::config::Config;
use app::logger::Logger;

fn main() -> Result<(), Box<dyn Error>> {
    let filepath = env::args().nth(1).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "Se debe pasar el nombre del archivo como parametro",
        )
    })?;
    let config = Config::from_file(&filepath)?;
    let logger = Logger::new(&config)?;

    let mut router = Router::new();
    router.branch("/test", handler_handshake);
    let mut server = Server::new(router, &logger);
    server.run(&"127.0.0.1:8090").unwrap();
    Ok(())
}
