use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::{RootCertStore, ServerConfig};
use tokio_rustls::{server::TlsStream, TlsAcceptor};

fn load_certs(filename: &Path) -> Vec<CertificateDer<'static>> {
    CertificateDer::pem_file_iter(filename)
        .expect("cannot open certificate file")
        .map(|result| result.unwrap())
        .collect()
}

fn load_private_key(filename: &Path) -> PrivateKeyDer<'static> {
    PrivateKeyDer::from_pem_file(filename).expect("cannot read private key file")
}
fn get_config() -> ServerConfig {
    let client_auth = {
        let roots = load_certs(Path::new("ca.crt"));
        let mut client_auth_roots = RootCertStore::empty();
        for root in roots {
            client_auth_roots.add(root).unwrap();
        }
        WebPkiClientVerifier::builder(client_auth_roots.into())
            .build()
            .unwrap()
    };
    ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_client_cert_verifier(client_auth)
        .with_single_cert(
            load_certs(Path::new("server.crt")),
            load_private_key(Path::new("server.key")),
        )
        .unwrap()
}

pub trait MtlsServer {
    fn handle_connection(
        peer_addr: SocketAddr,
        stream: TlsStream<TcpStream>,
    ) -> impl std::future::Future<Output = io::Result<()>> + std::marker::Send;

    fn run() -> impl std::future::Future<Output = io::Result<()>> + Send {
        async {
            let config = get_config();
            let acceptor = TlsAcceptor::from(Arc::new(config));
            let listener = TcpListener::bind("127.0.0.1:8888").await.unwrap();
            loop {
                let (stream, peer_addr) = listener.accept().await?;
                let acceptor: TlsAcceptor = acceptor.clone();

                let fut = async move {
                    let stream = acceptor.accept(stream).await?;
                    Self::handle_connection(peer_addr, stream).await
                };

                tokio::spawn(async move {
                    if let Err(err) = fut.await {
                        eprintln!("{:?}", err);
                    }
                });
            }
        }
    }
}
