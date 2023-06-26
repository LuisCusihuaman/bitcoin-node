use crate::logger::log;
use crate::net::message::{Encoding, MessagePayload};
use crate::net::p2p_connection::P2PConnection;
use rand::seq::SliceRandom;
use std::sync::mpsc;
use std::sync::mpsc::Sender;
use std::thread;


pub struct NodeNetwork {
    pub logger_tx: Sender<String>,
    pub peer_connections: Vec<P2PConnection>,
}

impl NodeNetwork {
    pub fn connection_count(&self) -> usize {
        self.peer_connections
            .iter()
            .filter(|connection| connection.handshaked)
            .count()
    }

    pub fn new(logger_tx: Sender<String>) -> NodeNetwork {
        NodeNetwork {
            logger_tx,
            peer_connections: Vec::new(),
        }
    }

    pub fn handshake_complete(&mut self, peer_address: &String) {
        log(
            self.logger_tx.clone(),
            format!("Handshake complete with peer: {}", peer_address),
        );

        // added handshaked attribute of P2PConnection turned into true, filter first by peer_address
        if let Some(peer_connection) = self
            .peer_connections
            .iter_mut()
            .find(|connection| connection.peer_address == *peer_address)
        {
            peer_connection.handshaked();
        }
    }

    pub fn send_messages(&self, payloads: Vec<MessagePayload>) {
        let mut threads = Vec::new();
        let mut shuffled_connections = self.peer_connections.clone();
        shuffled_connections.shuffle(&mut rand::thread_rng());

        // TODO: connection must be at least one if not enter to infinite loop
        for (payload, connection) in payloads.iter().cloned().zip(
            shuffled_connections
                .iter()
                .cycle()
                .filter(|connection| connection.handshaked),
        ) {
            let mut conn = connection.clone();
            let payload = payload.clone();
            let logger_tx = self.logger_tx.clone();
            let (sender, receiver) = mpsc::channel();

            threads.push(thread::spawn(move || {
                if let Err(err) = conn.send(&payload) {
                    log(
                        logger_tx.clone(),
                        format!(
                            "Error sending message: {} for peer: {:?}",
                            err,
                            conn.peer_address.clone()
                        ),
                    );
                    if err == "Broken pipe (os error 32)" {
                        log(
                            logger_tx,
                            format!("Retry sending {} to other peer", payload.command_name()),
                        );
                        sender.send(payload).unwrap();
                    }
                }
            }));

            match receiver.recv() {
                Ok(msg) => {
                    self.send_messages(vec![msg]);
                }
                Err(_) => {}
            };
        }

        for thread in threads {
            thread.join().unwrap();
        }
    }

    pub fn send_to_all_peers(&self, payload: &MessagePayload) -> Result<(), String> {
        let mut threads = Vec::new();

        for connection in self.peer_connections.iter() {
            if connection.handshaked {
                let mut connection = connection.clone();
                let payload = payload.clone();
                let logger_tx = self.logger_tx.clone();

                threads.push(thread::spawn(move || {
                    if let Err(e) = connection.send(&payload) {
                        log(logger_tx, format!("Error sending message to peer: {:?}", e));
                        // self.connection.handshaked = false; <-- CANT U DOIT BECAUSE ITS NOT A MUTABLE REFERENCE
                    }
                }));
            }
        }

        for thread in threads {
            thread.join().expect("Failed to join thread");
        }

        Ok(())
    }

    pub fn send_to_peer(
        &mut self,
        payload: &MessagePayload,
        peer_address: &String,
    ) -> Result<(), String> {
        if let Some(peer_connection) = self
            .peer_connections
            .iter_mut()
            .find(|connection| connection.peer_address == *peer_address)
        {
            if let Err(e) = peer_connection.send(payload) {
                log(
                    self.logger_tx.clone(),
                    format!("Error sending message to peer: {:?}", e),
                );
                peer_connection.handshaked = false;
            }
        }
        Ok(())
    }

    pub fn receive_from_all_peers(&mut self) -> Vec<(String, Vec<MessagePayload>)> {
        let mut threads = Vec::new();
        let (sender, receiver) = mpsc::channel();

        for connection in self.peer_connections.iter_mut() {
            let mut connection = connection.clone();
            let sender = sender.clone();

            threads.push(thread::spawn(move || {
                let messages = connection.receive();
                sender.send(messages).unwrap();
            }));
        }
        for thread in threads {
            thread.join().unwrap();
        }
        drop(sender);

        let received_messages: Vec<_> = receiver
            .iter()
            .filter(|(_, messages)| !messages.is_empty())
            .collect();

        received_messages
    }

    pub fn get_one_peer_address(&self) -> String {
        let handshaked_connections: Vec<&P2PConnection> = self
            .peer_connections
            .iter()
            .filter(|connection| connection.handshaked)
            .collect();

        if let Some(peer_connection) = handshaked_connections.choose(&mut rand::thread_rng()) {
            peer_connection.peer_address.clone()
        } else {
            String::from("")
        }
    }
}
