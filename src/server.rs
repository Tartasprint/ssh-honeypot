use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use pollster::FutureExt as _;

use crate::log;
use crate::ratelimit::RateLimiter;



pub struct Config {
    pub max_attempts: usize,
    pub rate_limit: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            max_attempts: 5,
            rate_limit: Duration::new(60, 0),
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
    fn new_attempt(&mut self){
        self.attempts += 1;
    }

    fn log(&self, data: log::RecordKind) {
        (log::Record {
            time: Utc::now(),
            connection: self.connection,
            peer_address: self.peer_address,
            data,
        }).log();
    }

    fn available_methods(&self) -> ::russh::server::Auth {
        use russh::{ MethodKind, MethodSet };
        if self.attempts <= self.server_config.max_attempts {
            let mut methods = MethodSet::empty();
            methods.push(MethodKind::Password);
            methods.push(MethodKind::PublicKey);
            ::russh::server::Auth::Reject { proceed_with_methods: Some(methods), partial_success: false }
        } else {
            ::russh::server::Auth::Reject { proceed_with_methods: None, partial_success: false }
        }
    }
}

impl Drop for Handler {
    fn drop(&mut self){
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
            let check = self.rate_limiter.check(sock_addr.ip(), self.config.rate_limit).block_on();
            if !check {
                println!("Rate exceeded");
            }
        }
        r.log(log::RecordKind::StartConnection);
        self.counter +=1;
        r
    }
}

impl ::russh::server::Handler for Handler {
    type Error = anyhow::Error;

    async fn auth_none(&mut self, user: &str) -> Result<::russh::server::Auth, Self::Error> {
        self.new_attempt();
        self.log(log::RecordKind::AuthNone{
            user: user.into(),
        });
        Ok(self.available_methods())
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<::russh::server::Auth, Self::Error> {
        self.new_attempt();
        self.log(log::RecordKind::PublicKey{
            user: user.into(),
            key: key.into(),
        });
        Ok(self.available_methods())
    }

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<::russh::server::Auth, Self::Error> {
        self.new_attempt();
        self.log(log::RecordKind::Password{
            user: user.into(),
            password: password.into(),
        });
        Ok(self.available_methods())
    }
}
