//! Error type shared by the whole crate.

use std::io;

/// Crate-wide result alias.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Everything that can go wrong while proxying a connection.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Transport-level I/O failure.
    #[error("i/o error: {0}")]
    Io(#[from] io::Error),

    /// The peer sent something that violates the wire protocol.
    #[error("protocol error: {0}")]
    Protocol(String),

    /// TLS setup or handshake failure.
    #[error("tls error: {0}")]
    Tls(String),

    /// Authentication exchange failure.
    #[error("authentication error: {0}")]
    Auth(String),

    /// A user-supplied hook failed.
    #[error("hook error: {0}")]
    Hook(String),

    /// The connection was closed by the peer (cleanly or not).
    #[error("connection closed by peer")]
    ConnectionClosed,

    /// Anything else.
    #[error("{0}")]
    Other(String),
}

impl Error {
    /// Build a [`Error::Protocol`] from anything printable.
    pub fn protocol(msg: impl Into<String>) -> Self {
        Error::Protocol(msg.into())
    }

    /// Build a [`Error::Tls`] from anything printable.
    pub fn tls(msg: impl Into<String>) -> Self {
        Error::Tls(msg.into())
    }

    /// Build a [`Error::Auth`] from anything printable.
    pub fn auth(msg: impl Into<String>) -> Self {
        Error::Auth(msg.into())
    }

    /// Build a [`Error::Hook`] from anything printable.
    pub fn hook(msg: impl Into<String>) -> Self {
        Error::Hook(msg.into())
    }

    /// Build a [`Error::Other`] from anything printable.
    pub fn other(msg: impl Into<String>) -> Self {
        Error::Other(msg.into())
    }

    /// True when the error simply means "the peer went away".
    pub fn is_disconnect(&self) -> bool {
        matches!(self, Error::ConnectionClosed)
            || matches!(self, Error::Io(e) if matches!(
                e.kind(),
                io::ErrorKind::UnexpectedEof
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::BrokenPipe
            ))
    }
}

impl From<rustls::Error> for Error {
    fn from(e: rustls::Error) -> Self {
        Error::Tls(e.to_string())
    }
}
