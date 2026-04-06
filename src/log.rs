use chrono::prelude::{DateTime, Utc};
use russh::keys::ssh_key::PublicKey;
use russh::keys::HashAlg;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, PartialEq, Eq, Hash, Clone)]
pub struct PublicKeyFingerprint {
    fingerprint: String,
    algorithm: String,
    comment: String,
}

impl From<&PublicKey> for PublicKeyFingerprint {
    fn from(pk: &PublicKey) -> Self {
        Self {
            fingerprint: pk.fingerprint(HashAlg::Sha512).to_string(),
            algorithm: pk.algorithm().to_string(),
            comment: pk.comment().into(),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub enum RecordKind {
    StartConnection,
    StopConnection,
    AuthNone {
        user: String,
    },
    Password {
        user: String,
        password: String,
    },
    PublicKey {
        user: String,
        key: PublicKeyFingerprint,
    },
}

#[derive(Serialize, Deserialize)]
pub struct Record {
    pub connection: u64,
    pub peer_address: Option<std::net::SocketAddr>,
    pub time: DateTime<Utc>,
    pub data: RecordKind,
}

impl Record {
    pub fn log(&self) {
        println!("{}", serde_json::to_string(&self).unwrap());
    }
}
