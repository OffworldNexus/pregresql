//! Proxy configuration types.

use std::net::SocketAddr;
use std::path::PathBuf;

/// Where the proxy should listen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListenAddr {
    /// A TCP listener.
    Tcp(SocketAddr),
    /// A Unix-domain socket listener.
    Unix(PathBuf),
}

/// How to verify the upstream server's certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VerifyMode {
    /// Full WebPKI validation against the configured CA bundle.
    #[default]
    Full,
    /// Accept any certificate. Useful for self-signed servers in tests; it
    /// disables the protection against active man-in-the-middle attackers.
    None,
}

/// TLS options used when connecting to the upstream server.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TlsClientOptions {
    /// Certificate validation mode.
    pub verify: VerifyMode,
    /// PEM bundle of trusted CAs. Required when `verify` is [`VerifyMode::Full`].
    pub ca_file: Option<PathBuf>,
    /// Optional client certificate and private key (mutual TLS).
    pub client_cert: Option<(PathBuf, PathBuf)>,
}

/// Where the upstream server lives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Endpoint {
    /// A TCP endpoint.
    Tcp {
        /// Host name or address.
        host: String,
        /// Port.
        port: u16,
    },
    /// A Unix-domain socket path.
    Unix {
        /// Socket path.
        path: PathBuf,
    },
}

impl Endpoint {
    /// Convenience constructor for a TCP endpoint.
    pub fn tcp(host: impl Into<String>, port: u16) -> Self {
        Endpoint::Tcp {
            host: host.into(),
            port,
        }
    }

    /// Convenience constructor for a Unix-domain socket endpoint.
    pub fn unix(path: impl Into<PathBuf>) -> Self {
        Endpoint::Unix { path: path.into() }
    }
}

/// Whether (and how) to use TLS towards the upstream server.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum UpstreamTls {
    /// Never send an `SSLRequest`.
    #[default]
    Disable,
    /// Try TLS, fall back to plaintext when the server declines. This is what
    /// libpq's `sslmode=prefer` does.
    Prefer(TlsClientOptions),
    /// Require TLS; fail the connection when the server declines.
    Require(TlsClientOptions),
}

impl UpstreamTls {
    /// The options, if TLS is requested at all.
    pub fn options(&self) -> Option<&TlsClientOptions> {
        match self {
            UpstreamTls::Disable => None,
            UpstreamTls::Prefer(o) | UpstreamTls::Require(o) => Some(o),
        }
    }

    /// True when a failure to negotiate TLS must abort the connection.
    pub fn is_required(&self) -> bool {
        matches!(self, UpstreamTls::Require(_))
    }
}

/// TLS material the proxy presents to incoming clients.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsServerOptions {
    /// PEM certificate chain.
    pub cert_file: PathBuf,
    /// PEM private key.
    pub key_file: PathBuf,
    /// Optional PEM bundle of CAs used to verify client certificates.
    pub client_ca_file: Option<PathBuf>,
}

/// Top-level proxy configuration.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// Addresses to listen on.
    pub listen: Vec<ListenAddr>,
    /// Certificate to present to clients that ask for TLS.
    pub tls: Option<TlsServerOptions>,
    /// Reject clients that do not negotiate TLS (needs [`ProxyConfig::tls`]).
    pub require_tls: bool,
    /// Largest regular protocol message accepted, in bytes.
    pub max_message_length: usize,
    /// Largest number of concurrently served connections.
    pub max_connections: Option<usize>,
    /// Whether to unlink an existing Unix socket path before binding.
    pub replace_unix_socket: bool,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            listen: vec![ListenAddr::Tcp(([127, 0, 0, 1], 6432).into())],
            tls: None,
            require_tls: false,
            max_message_length: crate::protocol::MAX_MESSAGE_LENGTH,
            max_connections: None,
            replace_unix_socket: true,
        }
    }
}

impl ProxyConfig {
    /// Add a listener address.
    pub fn listen_on(mut self, addr: ListenAddr) -> Self {
        self.listen.push(addr);
        self
    }
}
