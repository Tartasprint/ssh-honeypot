use std::sync::Arc;

use russh::keys::ssh_key::rand_core::OsRng;
use russh::server::Server as _;
use russh::SshId;
use tokio::net::TcpListener;

use ssh_honeypot::server::{
    Server,
    Config as HoneyConfig,
};

const MAX_ATTEMPTS: usize = 5;

#[tokio::main]
async fn main() {
    let config = russh::server::Config {
        inactivity_timeout: Some(std::time::Duration::from_secs(60)),
        auth_rejection_time: std::time::Duration::from_secs(3),
        auth_rejection_time_initial: Some(std::time::Duration::from_secs(0)),
        server_id: SshId::Standard("SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u7".into()),
        max_auth_attempts: MAX_ATTEMPTS,
        keys: vec![
            ::russh::keys::PrivateKey::random(&mut OsRng, russh::keys::Algorithm::Ed25519).unwrap(),
        ],
        preferred: ::russh::Preferred {
            // kex: std::borrow::Cow::Owned(vec![russh::kex::DH_GEX_SHA256]),
            ..::russh::Preferred::default()
        },
        ..Default::default()
    };
    let config = Arc::new(config);
    let mut sh = Server::new(HoneyConfig::default());

    let socket = TcpListener::bind(("0.0.0.0", 2222)).await.unwrap();
    let server = sh.run_on_socket(config, &socket);

    server.await.unwrap()
}

