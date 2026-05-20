#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("bencode parse error: {0}")]
    Bencode(String),

    #[error("tracker error: {0}")]
    Tracker(String),

    #[error("peer handshake failed: {0}")]
    Handshake(String),

    #[error("piece verification failed for index {index}")]
    VerifyFailed { index: usize },

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("network error: {0}")]
    Network(String),

    #[error("crypto error: {0}")]
    Crypto(String),
}

pub type Result<T> = std::result::Result<T, Error>;
