use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use pollster::FutureExt as _;
use russh::keys::ssh_key::rand_core::OsRng;
use russh::SshId;
use serde::Deserialize;

use crate::log;
use crate::ratelimit::RateLimiter;

#[derive(Deserialize)]
pub struct Config {
    pub max_attempts: usize,
    pub rate_limit: Duration,
    pub banner: String,
    pub bind_broadcast: bool,
}

impl Config {
    pub fn get_russh_config(&self) -> russh::server::Config {
        russh::server::Config {
            inactivity_timeout: Some(std::time::Duration::from_secs(60)),
            auth_rejection_time: std::time::Duration::from_secs(3),
            auth_rejection_time_initial: Some(std::time::Duration::from_secs(0)),
            server_id: SshId::Standard(self.banner.clone()),
            max_auth_attempts: self.max_attempts,
            keys: vec![::russh::keys::PrivateKey::random(
                &mut OsRng,
                russh::keys::Algorithm::Ed25519,
            )
            .unwrap()],
            preferred: ::russh::Preferred {
                // kex: std::borrow::Cow::Owned(vec![russh::kex::DH_GEX_SHA256]),
                ..::russh::Preferred::default()
            },
            ..Default::default()
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            max_attempts: 5,
            rate_limit: Duration::new(600, 1),
            banner: "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u7".into(),
            bind_broadcast: false,
        }
    }
}

pub struct Server {
    counter: u64,
    config: Arc<Config>,
    rate_limiter: RateLimiter,
}

impl Server {
    pub fn new(config: Config) -> Self {
        Self {
            config: Arc::new(config),
            counter: 0,
            rate_limiter: RateLimiter::new(),
        }
    }
}

pub struct Handler {
    connection: u64,
    attempts: usize,
    peer_address: Option<std::net::SocketAddr>,
    server_config: Arc<Config>,
}

impl Handler {
    fn new_attempt(&mut self) {
        self.attempts += 1;
    }

    fn log(&self, data: log::RecordKind) {
        (log::Record {
            time: Utc::now(),
            connection: self.connection,
            peer_address: self.peer_address,
            data,
        })
        .log();
    }

    fn available_methods(&self) -> ::russh::server::Auth {
        use russh::{MethodKind, MethodSet};
        if self.attempts <= self.server_config.max_attempts {
            let mut methods = MethodSet::empty();
            methods.push(MethodKind::Password);
            methods.push(MethodKind::PublicKey);
            ::russh::server::Auth::Reject {
                proceed_with_methods: Some(methods),
                partial_success: false,
            }
        } else {
            ::russh::server::Auth::Reject {
                proceed_with_methods: None,
                partial_success: false,
            }
        }
    }
}

impl Drop for Handler {
    fn drop(&mut self) {
        self.log(log::RecordKind::StopConnection);
    }
}

impl ::russh::server::Server for Server {
    type Handler = Handler;
    fn new_client(&mut self, peer_address: Option<std::net::SocketAddr>) -> Self::Handler {
        let r = Handler {
            connection: self.counter,
            attempts: 0,
            peer_address,
            server_config: self.config.clone(),
        };
        if let Some(sock_addr) = peer_address {
            let check = self
                .rate_limiter
                .check(sock_addr.ip(), self.config.rate_limit)
                .block_on();
            if !check {
                eprintln!("Rate exceeded");
            }
        }
        r.log(log::RecordKind::StartConnection);
        self.counter += 1;
        r
    }
}

impl ::russh::server::Handler for Handler {
    type Error = anyhow::Error;

    async fn auth_none(&mut self, user: &str) -> Result<::russh::server::Auth, Self::Error> {
        self.new_attempt();
        self.log(log::RecordKind::AuthNone { user: user.into() });
        Ok(self.available_methods())
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<::russh::server::Auth, Self::Error> {
        self.new_attempt();
        self.log(log::RecordKind::PublicKey {
            user: user.into(),
            key: key.into(),
        });
        Ok(self.available_methods())
    }

    async fn auth_password(
        &mut self,
        user: &str,
        password: &str,
    ) -> Result<::russh::server::Auth, Self::Error> {
        self.new_attempt();
        self.log(log::RecordKind::Password {
            user: user.into(),
            password: password.into(),
        });
        Ok(self.available_methods())
    }
}
