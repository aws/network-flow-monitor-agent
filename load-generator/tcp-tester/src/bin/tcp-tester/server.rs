use log::{debug, info};
use netns_rs::NetNs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};
use tokio::time::{sleep, Duration};

/// Namespace where the server runs.
static SERVER_NAMESPACE: &str = "nfm-perf-test-server";

// Function to handle each client connection asynchronously.
async fn handle_client(mut stream: TcpStream, response_delay_ms: u64) {
    if response_delay_ms > 0 {
        info!("Delaying response for {} ms", response_delay_ms);
        sleep(Duration::from_millis(response_delay_ms)).await;
    }
    stream.set_nodelay(true).unwrap();
    let mut buffer = [0; 16384];

    loop {
        let n = match stream.read(&mut buffer).await {
            Ok(0) => {
                debug!("Connection closed by client");
                return;
            }
            Ok(n) => n,
            Err(e) => {
                debug!("Failed to read from socket: {}", e);
                return;
            }
        };
        debug!("Received message size {}", n);

        if let Err(e) = stream.write_all(&buffer[0..n]).await {
            debug!("Failed to write to socket: {}", e);
            return;
        }
    }
}

/// Starts a server that will return the received message to the client.
pub async fn server(port: u16, response_delay_ms: u64) {
    let namespace = NetNs::get(SERVER_NAMESPACE).unwrap();
    let server_address = format!("0.0.0.0:{}", port).parse().unwrap();
    let server_socket = namespace.run(|_| TcpSocket::new_v4().unwrap()).unwrap();

    server_socket.bind(server_address).unwrap();
    server_socket.set_reuseaddr(true).unwrap();

    let listener = server_socket.listen(1024).unwrap();
    info!("Server listening on port {}", port);

    loop {
        debug!("waiting for connection...");
        let (stream, _) = listener.accept().await.unwrap();
        debug!("incoming message");
        tokio::spawn(handle_client(stream, response_delay_ms));
    }
}
