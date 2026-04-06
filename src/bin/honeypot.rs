use std::sync::Arc;

use russh::server::Server as _;
use tokio::net::TcpListener;

use ssh_honeypot::server::{Config as HoneyConfig, Server};

#[tokio::main]
async fn main() {
    let honey_config = HoneyConfig::default();
    let config = honey_config.get_russh_config();
    let config = Arc::new(config);
    let mut sh = Server::new(honey_config);

    let socket = TcpListener::bind(("127.0.0.1", 2222)).await.unwrap();
    let server = sh.run_on_socket(config, &socket);

    server.await.unwrap()
}
