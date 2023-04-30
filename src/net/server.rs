use crate::net::request::Request;
use crate::net::router::{Handler, Router};
use std::net::{TcpListener, TcpStream};

pub struct Server {
    router: Router,
}

impl Server {
    pub fn new(router: Router) -> Server {
        Server { router: router }
    }

    pub fn run(&self, addr: &str) -> std::io::Result<()> {
        let listener = TcpListener::bind(addr).unwrap();
        println!("Listening to {}", addr);
        let connection = listener.accept()?;
        let mut client_stream: TcpStream = connection.0;
        self.handle(&mut client_stream);

        Ok(())
    }

    fn handle(&self, stream: &mut TcpStream) {
        let req = Request::parse(stream);
        for r in &self.router.routes {
            if r.pattern == req.path() {
                self.dispatch(stream, r.callback, req);
                break;
            }
        }
    }

    fn dispatch(&self, stream: &mut TcpStream, handler: Handler, req: Request) {
        let response = (handler)(req);
        response.result_into(stream);
    }
}
