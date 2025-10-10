use nix::errno::Errno;

#[derive(Debug)]
pub enum ClientSocketError {
    SocketError(Errno),
    IoError(std::io::Error),
    NsError(netns_rs::Error),
}

impl From<std::io::Error> for ClientSocketError {
    fn from(e: std::io::Error) -> Self {
        ClientSocketError::IoError(e)
    }
}

impl From<netns_rs::Error> for ClientSocketError {
    fn from(e: netns_rs::Error) -> Self {
        ClientSocketError::NsError(e)
    }
}
