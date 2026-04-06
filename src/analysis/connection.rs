use std::collections::HashMap;
use std::hash::Hash;
use std::net::Ipv4Addr;

use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::log::{PublicKeyFingerprint, Record, RecordKind};

pub struct StableHashMap<T: Hash + Eq + Clone> {
    pub list: Vec<T>,
    pub map: HashMap<T, usize>,
}

impl<T: Hash + Eq + Clone> StableHashMap<T> {
    pub fn new() -> Self {
        Self {
            list: Vec::new(),
            map: HashMap::new(),
        }
    }

    pub fn insert(&mut self, item: &T) -> usize {
        *self.map.entry(item.clone()).or_insert_with(|| {
            self.list.push(item.clone());
            self.list.len() - 1
        })
    }
}

#[derive(Serialize)]
pub enum EventKind {
    Stop,
    AuthNone { user: usize },
    Password { user: usize, password: usize },
    PublicKey { user: usize, key: usize },
}

#[derive(Serialize)]
pub struct Event {
    delta: u64, // Up to 584 years in nanoseconds
    kind: EventKind,
}

#[derive(Serialize)]
pub struct Connection {
    ip: Ipv4Addr,
    port: u16,
    start: DateTime<Utc>,
    events: Vec<Event>,
    // In nanoseconds
    duration: u64,
}

impl Connection {
    fn new(peer: std::net::SocketAddr, start: DateTime<Utc>) -> Self {
        if let std::net::SocketAddr::V4(v4_socket_addr) = peer {
            Self {
                ip: *v4_socket_addr.ip(),
                port: v4_socket_addr.port(),
                start,
                events: Vec::new(),
                duration: 0,
            }
        } else {
            panic!("Unexpected IPv6");
        }
    }
}

pub struct Representation {
    pub passwords: StableHashMap<String>,
    pub users: StableHashMap<String>,
    pub fingerprints: StableHashMap<PublicKeyFingerprint>,
    pub connections: Vec<Connection>,
}

impl Representation {
    pub fn new() -> Self {
        Self {
            passwords: StableHashMap::new(),
            users: StableHashMap::new(),
            fingerprints: StableHashMap::new(),
            connections: Vec::new(),
        }
    }

    pub fn new_record(&mut self, record: Record) -> &mut Self {
        if let RecordKind::StartConnection = record.data {
            self.connections
                .push(Connection::new(record.peer_address.unwrap(), record.time));
            return self;
        };
        let connection = self
            .connections
            .get_mut(record.connection as usize)
            .unwrap();
        if connection.duration != 0 {
            record.log();
            panic!()
        }
        let delta = (record.time - connection.start).num_nanoseconds().unwrap();
        if delta < 0 {
            panic!("Negative duration!")
        }
        let delta = delta as u64;

        match record.data {
            RecordKind::StartConnection => unreachable!(),
            RecordKind::StopConnection => {
                connection.duration = delta;
            }
            RecordKind::AuthNone { user } => {
                let user_id = self.users.insert(&user);
                connection.events.push(Event {
                    delta,
                    kind: EventKind::AuthNone { user: user_id },
                });
            }
            RecordKind::Password { user, password } => {
                let user_id = self.users.insert(&user);
                let password_id = self.passwords.insert(&password);
                connection.events.push(Event {
                    delta,
                    kind: EventKind::Password {
                        user: user_id,
                        password: password_id,
                    },
                });
            }
            RecordKind::PublicKey { user, key } => {
                let user_id = self.users.insert(&user);
                let fingerprint_id = self.fingerprints.insert(&key);
                connection.events.push(Event {
                    delta,
                    kind: EventKind::PublicKey {
                        user: user_id,
                        key: fingerprint_id,
                    },
                });
            }
        };
        self
    }
}
