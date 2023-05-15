use crate::logger::Logger;
use crate::net::request::Request;
use crate::net::response::Response;
use crate::net::router::{Handler, Router};
use crate::node::manager::{Config, NodeManager};
use crate::node::message::version::PayloadVersion;
use crate::node::message::MessagePayload;
use std::net::{TcpListener, TcpStream};

pub struct Server<'a> {
    router: Router,
    node_manager: NodeManager<'a>,
    logger: &'a Logger,
}

impl Server<'_> {
    pub fn new(router: Router, logger: &Logger) -> Server {
        Server {
            router,
            logger,
            node_manager: NodeManager::new(
                Config {
                    addrs: "seed.testnet.bitcoin.sprovoost.nl".to_string(),
                    port: 80,
                },
                logger,
            ),
        }
    }

    pub fn run(&mut self, addr: &str) -> Result<(), String> {
        let listener = TcpListener::bind(addr).unwrap();
        let node_network_ips = self.node_manager.get_initial_nodes()?;
        self.node_manager.connect(
            node_network_ips
                .iter()
                .map(|ip| format!("{}:18333", ip))
                .take(1)
                .collect(),
        )?;
        self.node_manager.handshake();
        self.logger.log(format!("Server listening on {}", addr));
        //here can trigger another thread with a loop to receive all messages for keep connection alive with other nodes
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
