use crate::net::request::Request;
use crate::net::router::{Handler, Router};
use std::net::{TcpListener, TcpStream};
use crate::net::response::Response;
use crate::node::manager::{Config, NodeManager};
use crate::node::message::MessagePayload;
use crate::node::message::version::PayloadVersion;

pub struct Server {
    router: Router,
    node_manager: NodeManager,
}

fn handler_handshake(node_manager: &mut NodeManager, req: Request) -> Response {
    let payload_version_message = MessagePayload::Version(PayloadVersion::default_version());
    node_manager.broadcast(&payload_version_message);
    let _ = node_manager.wait_for(vec!["verack"]);
    Response::json(String::from("pong"))
}

impl Server {
    pub fn new(router: Router) -> Server {
        Server {
            router,
            node_manager: NodeManager::new(Config {
                addrs: "seed.testnet.bitcoin.sprovoost.nl".to_string(),
                port: 80,
            }),
        }
    }

    pub fn run(&mut self, addr: &str) -> Result<(), String> {
        let listener = TcpListener::bind(addr).unwrap();
        self.router.branch("/balance", handler_handshake);

        let node_network_ips = self.node_manager.get_initial_nodes()?;
        self.node_manager.connect(
            node_network_ips.iter()
                .map(|ip| format!("{}:18333", ip))
                .collect()
        )?;
        //self.node_manager.handshake();
        println!("Listening to {}", addr);
        let connection = listener.accept().map_err(|e| e.to_string())?;
        let mut client_stream: TcpStream = connection.0;
        self.handle(&mut client_stream);

        Ok(())
    }

    fn handle(&mut self, stream: &mut TcpStream) {
        let req = Request::parse(stream);
        for r in &self.router.routes {
            if r.pattern == req.path() {
                self.dispatch(stream, r.callback, req);
                break;
            }
        }
    }

    fn dispatch(&mut self, stream: &mut TcpStream, handler: Handler, req: Request) {
        let response = (handler)(&mut self.node_manager, req);
        response.result_into(stream);
    }
}
