use std::sync::Arc;

use chrono::prelude::*;
use russh::keys::ssh_key::rand_core::OsRng;
use russh::keys::{Certificate, *};
use russh::server::{Msg, Server as _, Session};
use russh::*;
use tokio::net::TcpListener;
use tokio::sync::Mutex;

mod log;

#[tokio::main]
async fn main() {
    let config = russh::server::Config {
        inactivity_timeout: Some(std::time::Duration::from_secs(3600)),
        auth_rejection_time: std::time::Duration::from_secs(3),
        auth_rejection_time_initial: Some(std::time::Duration::from_secs(0)),
        keys: vec![
            russh::keys::PrivateKey::random(&mut OsRng, russh::keys::Algorithm::Ed25519).unwrap(),
        ],
        preferred: Preferred {
            // kex: std::borrow::Cow::Owned(vec![russh::kex::DH_GEX_SHA256]),
            ..Preferred::default()
        },
        ..Default::default()
    };
    let config = Arc::new(config);
    let mut sh = Server {
        counter: 0,
    };

    let socket = TcpListener::bind(("0.0.0.0", 2222)).await.unwrap();
    let server = sh.run_on_socket(config, &socket);

    server.await.unwrap()
}

#[derive(Clone)]
struct Server {
    counter: u64,
}

struct Handler {
    connection: u64,
    peer_address: Option<std::net::SocketAddr>,
}

impl Handler {
    fn log(&self, data: log::RecordKind) {
        (log::Record {
            time: Utc::now(),
            connection: self.connection,
            peer_address: self.peer_address,
            data,
        }).log();
    }

    fn available_methods(&self) -> MethodSet {
        let mut s = MethodSet::empty();
        s.push(MethodKind::Password);
        s.push(MethodKind::PublicKey);
        s
    }
}

impl Drop for Handler {
    fn drop(&mut self){
        self.log(log::RecordKind::StopConnection);
    }
}

impl server::Server for Server {
    type Handler = Handler;
    fn new_client(&mut self, peer_address: Option<std::net::SocketAddr>) -> Self::Handler {
        let r = Handler {
            connection: self.counter,
            peer_address,
        };
        r.log(log::RecordKind::StartConnection);
        self.counter +=1;
        r
    }
}

impl server::Handler for Handler {
    type Error = anyhow::Error;

    async fn auth_none(&mut self, user: &str) -> Result<server::Auth, Self::Error> {
        self.log(log::RecordKind::AuthNone{
            user: user.into(),
        });
        Ok(server::Auth::Reject { proceed_with_methods: Some(self.available_methods()), partial_success: false })
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        key: &ssh_key::PublicKey,
    ) -> Result<server::Auth, Self::Error> {
        self.log(log::RecordKind::PublicKey{
            user: user.into(),
            key: key.into(),
        });
        Ok(server::Auth::Reject { proceed_with_methods: Some(self.available_methods()), partial_success: false })
    }

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<server::Auth, Self::Error> {
        self.log(log::RecordKind::Password{
            user: user.into(),
            password: password.into(),
        });
        Ok(server::Auth::Reject { proceed_with_methods: Some(self.available_methods()), partial_success: false })
    }
}
