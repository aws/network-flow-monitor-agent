use tokio::net::TcpStream;

pub struct ConditionedTcpStream {
    pub stream: TcpStream,
}
