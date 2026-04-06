use std::net::SocketAddr;

use rustls_tokio_stream::TlsStream;
use ssh_honeypot::mtls::server::MtlsServer;
use tokio::io;
use tokio::io::{copy, sink, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use x509_parser::prelude::*;

pub struct AggregatorServer;

fn display_x509_info(x509: &X509Certificate<'_>) {
    let subject = x509.subject();
    let issuer = x509.issuer();
    println!("X.509 Subject: {}", subject);
    println!("X.509 Issuer: {}", issuer);
    println!(
        "X.509 serial: {}",
        x509.tbs_certificate.raw_serial_as_string()
    );
}

impl MtlsServer for AggregatorServer {
    async fn handle_connection(
        peer_addr: SocketAddr,
        mut stream: TlsStream<TcpStream>,
    ) -> io::Result<()> {
        let handshake = stream.handshake().await?;
        if let Some(peer_certificates) = handshake.peer_certificates {
            for certificate in peer_certificates {
                let certificate = &certificate.to_vec();
                let certificate = X509Certificate::from_der(certificate).unwrap();
                display_x509_info(&certificate.1);
            }
        }
        let mut output = sink();
        stream
            .write_all(
                &b"HTTP/1.0 200 ok\r\n\
            Connection: close\r\n\
            Content-length: 12\r\n\
            \r\n\
            Hello world!"[..],
            )
            .await?;
        stream.shutdown().await?;
        copy(&mut stream, &mut output).await?;
        println!("Hello: {}", peer_addr);

        Ok(()) as io::Result<()>
    }
}
#[tokio::main]
async fn main() {
    AggregatorServer::run().await;
}
