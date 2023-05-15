use crate::net::request::Request;
use crate::net::response::Response;
use crate::node::manager::NodeManager;
use crate::node::message::version::PayloadVersion;
use crate::node::message::MessagePayload;

pub fn handler_handshake(node_manager: &mut NodeManager, _req: Request) -> Response {
    let payload_version_message = MessagePayload::Version(PayloadVersion::default_version());
    node_manager.broadcast(&payload_version_message);
    let _ = node_manager.wait_for(vec!["version", "verack"]);
    Response::json(String::from("communication with wallet complete!"))
}
