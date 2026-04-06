use std::net::SocketAddr;

use ssh_honeypot::mtls::server::MtlsServer;
use tokio::io;
use tokio::io::{copy, sink, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::server::TlsStream;

pub struct AggregatorServer;

impl MtlsServer for AggregatorServer {
    async fn handle_connection(
        peer_addr: SocketAddr,
        mut stream: TlsStream<TcpStream>,
    ) -> io::Result<()> {
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
