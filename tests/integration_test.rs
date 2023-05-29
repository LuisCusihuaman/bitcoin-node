use app::config::Config;
use app::logger::Logger;
use app::net::request::Request;
use app::net::response::Response;
use app::net::router::Router;
use app::net::server::Server;
use app::node::manager::NodeManager;
use std::{
    io::{BufRead, BufReader, Write},
    net::TcpStream,
    thread::{self},
    time::Duration,
};

#[test]
#[ignore]
fn test_al_pedir_un_balance_el_router_devuelve_resultado_esperado() -> std::io::Result<()> {
    // GIVEN
    let mut router = Router::new();
    router.branch(
        "/ping",
        |_node_manager: &mut NodeManager, _req: Request| -> Response {
            Response::json(String::from("pong"))
        },
    );
    let addrs = "127.0.0.1:8990";
    let config = Config::new();
    let handle = thread::spawn(move || {
        let logger = Logger::stdout();
        Server::new(router, &logger, config).run(&addrs).unwrap();
    });
    thread::sleep(Duration::from_millis(500));

    //client
    let mut socket = TcpStream::connect(addrs)?;
    socket.write("/ping\n".as_bytes())?;

    //get response from server
    let mut response = String::new();
    let mut reader = BufReader::new(socket);
    let line_bytes = reader.read_line(&mut response)?;

    assert_eq!(line_bytes, 4);
    assert_eq!(response, String::from("pong"));
    match handle.join() {
        Ok(_) => Ok(()),
        Err(_) => panic!("Se esperaba que el thread termine correctamente"),
    }
}
