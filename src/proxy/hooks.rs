//! The two hooks that give the proxy its behaviour.
//!
//! * [`AuthHook`] decides how the incoming client authenticates and resolves
//!   the upstream target to connect to.
//! * [`QueryHook`] authorises individual statements.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;

use crate::proxy::config::UpstreamTls;

/// Process credentials of a Unix-domain socket peer, as attached by the kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UnixCredentials {
    /// Process id of the sender.
    pub pid: i32,
    /// User id of the sender.
    pub uid: u32,
    /// Group id of the sender.
    pub gid: u32,
}

/// Where an inbound connection came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transport {
    /// A Unix-domain socket.
    ///
    /// Two independent sources of peer credentials are recorded:
    ///
    /// * `peer_pid`/`peer_uid`/`peer_gid` come from `SO_PEERCRED` (Linux) or
    ///   `getpeereid` (BSD/macOS, where there is no pid and `peer_pid` is
    ///   `Some(-1)`). They are **unreliable under gVisor** (for example on
    ///   DigitalOcean App Platform), which reports the *listener's* own
    ///   credentials for every accepted connection.
    /// * `message_credentials` is the `SCM_CREDENTIALS` the kernel attached to
    ///   the first message the client sent, read with `SO_PASSCRED`. See
    ///   [`Transport::message_credentials`].
    Unix {
        /// Path the proxy is listening on (empty for unnamed sockets).
        path: PathBuf,
        /// Peer process id from `SO_PEERCRED`, when the platform exposes it.
        peer_pid: Option<i32>,
        /// Peer user id from `SO_PEERCRED`/`getpeereid`.
        peer_uid: Option<u32>,
        /// Peer group id from `SO_PEERCRED`/`getpeereid`.
        peer_gid: Option<u32>,
        /// Kernel-attached credentials of the client's first message
        /// (`SCM_CREDENTIALS`). Only available on Linux and Android; `None`
        /// elsewhere, or when the proxy could not enable `SO_PASSCRED`.
        message_credentials: Option<UnixCredentials>,
    },
    /// A TCP socket.
    Tcp {
        /// Remote address.
        peer: SocketAddr,
        /// Local address.
        local: SocketAddr,
    },
}

impl Transport {
    /// True when the connection arrived over a Unix-domain socket.
    pub fn is_unix(&self) -> bool {
        matches!(self, Transport::Unix { .. })
    }

    /// The peer's uid according to `SO_PEERCRED`/`getpeereid`, when known.
    ///
    /// Under gVisor this is the uid of the *listening* process, not of the
    /// client; prefer [`Transport::message_uid`] where it is available.
    pub fn peer_uid(&self) -> Option<u32> {
        match self {
            Transport::Unix { peer_uid, .. } => *peer_uid,
            Transport::Tcp { .. } => None,
        }
    }

    /// The `SCM_CREDENTIALS` the kernel attached to the first message the
    /// client sent over a Unix-domain socket (Linux and Android only).
    ///
    /// The client does not have to do anything for this: when the receiving
    /// socket has `SO_PASSCRED` set, the kernel attaches the sending process's
    /// pid, uid and gid to every message, and a sender can only claim other
    /// credentials explicitly if it has the privilege to (`CAP_SYS_ADMIN`,
    /// `CAP_SETUID`, `CAP_SETGID`). These are the credentials of whichever
    /// process wrote the first bytes of the connection (normally the client
    /// itself; the socket could have been handed to another process
    /// afterwards).
    pub fn message_credentials(&self) -> Option<UnixCredentials> {
        match self {
            Transport::Unix {
                message_credentials,
                ..
            } => *message_credentials,
            Transport::Tcp { .. } => None,
        }
    }

    /// The uid from [`Transport::message_credentials`], when known.
    pub fn message_uid(&self) -> Option<u32> {
        self.message_credentials().map(|c| c.uid)
    }
}

/// TLS properties of the inbound connection.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TlsInfo {
    /// Whether TLS was negotiated with the client.
    pub negotiated: bool,
    /// The client's certificate chain leaf, DER encoded, when it presented one.
    pub peer_certificate: Option<Bytes>,
}

/// Everything the hooks may want to know about the inbound connection.
#[derive(Debug, Clone)]
pub struct InboundConnection {
    /// Monotonic connection number, unique per proxy process.
    pub id: u64,
    /// Where the connection came from.
    pub transport: Transport,
    /// TLS properties.
    pub tls: TlsInfo,
    /// The protocol version word from the startup packet.
    pub protocol_version: i32,
    /// The startup parameters, in wire order.
    pub params: Vec<(String, String)>,
    /// The tag of the listener that accepted the connection, for listeners
    /// handed to the proxy with [`Proxy::add_unix_listener`] or
    /// [`Proxy::add_tcp_listener`]. `None` for listeners from
    /// [`ProxyConfig::listen`](crate::proxy::ProxyConfig::listen).
    ///
    /// [`Proxy::add_unix_listener`]: crate::proxy::Proxy::add_unix_listener
    /// [`Proxy::add_tcp_listener`]: crate::proxy::Proxy::add_tcp_listener
    pub listener_tag: Option<Arc<str>>,
}

impl InboundConnection {
    /// The tag of the listener that accepted the connection, if any.
    pub fn listener_tag(&self) -> Option<&str> {
        self.listener_tag.as_deref()
    }

    /// The `user` startup parameter.
    pub fn user(&self) -> Option<&str> {
        self.param("user")
    }

    /// The `database` startup parameter.
    pub fn database(&self) -> Option<&str> {
        self.param("database")
    }

    /// The `application_name` startup parameter.
    pub fn application_name(&self) -> Option<&str> {
        self.param("application_name")
    }

    /// The `options` startup parameter.
    pub fn options(&self) -> Option<&str> {
        self.param("options")
    }

    /// Whether the client asked for a replication session.
    pub fn is_replication(&self) -> bool {
        !matches!(
            self.param("replication"),
            None | Some("false") | Some("0") | Some("")
        )
    }

    /// Look up any startup parameter.
    pub fn param(&self, name: &str) -> Option<&str> {
        self.params
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

/// How the proxy should authenticate the incoming client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ClientAuthMethod {
    /// Ask for nothing (PostgreSQL's `trust`).
    #[default]
    Trust,
    /// Ask for the password in the clear.
    Cleartext,
    /// Ask for an MD5 challenge response.
    Md5,
    /// Perform a SCRAM-SHA-256 exchange.
    ScramSha256,
}

pub use crate::proxy::config::Endpoint;

/// The upstream server, and the identity to use towards it.
#[derive(Debug, Clone)]
pub struct UpstreamTarget {
    /// Where to connect.
    pub endpoint: Endpoint,
    /// How to protect the upstream connection.
    pub tls: UpstreamTls,
    /// Role to authenticate as against the upstream server.
    pub user: String,
    /// Password for that role, when the server requires one.
    pub password: Option<String>,
    /// Database to request; falls back to the client's `database` parameter.
    pub database: Option<String>,
    /// Extra startup parameters to send upstream (overriding the client's).
    pub params: Vec<(String, String)>,
}

impl UpstreamTarget {
    /// A minimal target: TCP endpoint, matching user, no TLS.
    pub fn tcp(host: impl Into<String>, port: u16, user: impl Into<String>) -> Self {
        Self {
            endpoint: Endpoint::tcp(host, port),
            tls: UpstreamTls::Disable,
            user: user.into(),
            password: None,
            database: None,
            params: Vec::new(),
        }
    }
}

/// The context handed to [`AuthHook::resolve_upstream`].
#[derive(Debug)]
pub struct AuthContext<'a> {
    /// Everything observed about the inbound connection.
    pub connection: &'a InboundConnection,
    /// The user name from the startup packet.
    pub user: &'a str,
    /// The method the client used to authenticate to the proxy.
    pub method: ClientAuthMethod,
    /// Whether the proxy was able to *verify* the client's proof. This is
    /// `false` when no password was available (see
    /// [`AuthHook::password_for_user`]) and the proxy therefore accepted the
    /// client unauthenticated.
    pub verified: bool,
    /// The plaintext password, when the exchange revealed it: this is the
    /// password the client supplied for cleartext authentication, or the
    /// expected password the proxy used to verify an MD5/SCRAM exchange.
    pub password: Option<&'a str>,
}

/// An authentication failure reported by a hook.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthError {
    /// SQLSTATE to report to the client.
    pub sqlstate: String,
    /// Human-readable message.
    pub message: String,
}

impl AuthError {
    /// Build an error with an explicit SQLSTATE.
    pub fn new(sqlstate: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            sqlstate: sqlstate.into(),
            message: message.into(),
        }
    }

    /// `28P01 invalid_password`.
    pub fn invalid_password(message: impl Into<String>) -> Self {
        Self::new("28P01", message)
    }

    /// `28000 invalid_authorization_specification`.
    pub fn rejected(message: impl Into<String>) -> Self {
        Self::new("28000", message)
    }
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.message, self.sqlstate)
    }
}

impl std::error::Error for AuthError {}

/// The authentication hook.
///
/// The proxy calls the three methods in this order:
///
/// 1. [`AuthHook::client_auth_method`] — how should the client authenticate?
/// 2. [`AuthHook::password_for_user`] — what password should the proxy use to
///    verify the client's proof? (Skipped for [`ClientAuthMethod::Trust`].)
/// 3. [`AuthHook::resolve_upstream`] — given what was observed, where do we
///    actually send this session?
#[async_trait]
pub trait AuthHook: Send + Sync + 'static {
    /// How the proxy should authenticate the incoming client.
    ///
    /// The default is [`ClientAuthMethod::Trust`], in which case the proxy
    /// accepts the client immediately and passes no credentials to the hook.
    fn client_auth_method(&self, _connection: &InboundConnection) -> ClientAuthMethod {
        ClientAuthMethod::Trust
    }

    /// The password the proxy should use to verify the client's proof.
    ///
    /// * For [`ClientAuthMethod::Md5`] and [`ClientAuthMethod::ScramSha256`]
    ///   this is required for verification; without it the proxy cannot check
    ///   the client's response and accepts it unverified
    ///   (`AuthContext::verified == false`).
    /// * For [`ClientAuthMethod::Cleartext`] the password the client sent is
    ///   compared against this value when it is present.
    ///
    /// Note that the value returned here is the *expected* password, not the
    /// password the client sent — but for any successful exchange they are the
    /// same, and [`AuthContext::password`] only ever exposes a password that
    /// was actually proven.
    fn password_for_user(&self, _connection: &InboundConnection, _user: &str) -> Option<String> {
        None
    }

    /// Resolve the upstream target for an authenticated client.
    ///
    /// Returning `Err` aborts the connection with a `FATAL` `ErrorResponse`
    /// carrying the hook's SQLSTATE.
    async fn resolve_upstream(&self, ctx: AuthContext<'_>) -> Result<UpstreamTarget, AuthError>;
}

/// Which protocol-level construct a query came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryKind {
    /// A `Query` (simple protocol) message.
    Simple,
    /// A `Parse` message.
    Parse,
    /// A `Bind` message.
    Bind,
    /// An `Execute` message.
    Execute,
    /// A legacy `FunctionCall` message.
    FunctionCall,
}

impl QueryKind {
    /// True for the two kinds that carry SQL text chosen by the client.
    pub fn carries_sql(self) -> bool {
        matches!(self, QueryKind::Simple | QueryKind::Parse)
    }
}

/// The context handed to [`QueryHook::authorize`].
#[derive(Debug)]
pub struct QueryContext<'a> {
    /// The connection id, as in [`InboundConnection::id`].
    pub connection_id: u64,
    /// Everything observed about the inbound connection when it was set up
    /// (transport, credentials, listener tag, TLS state, startup packet). This
    /// is the same value the [`AuthHook`] saw.
    pub connection: &'a InboundConnection,
    /// The user the client logged in as (to the proxy).
    pub user: &'a str,
    /// The user the proxy logged in as (to the upstream server).
    pub upstream_user: &'a str,
    /// The transaction status reported by the last `ReadyForQuery`.
    pub transaction_status: crate::protocol::TransactionStatus,
    /// Which message produced this call.
    pub kind: QueryKind,
    /// The SQL text. For `Bind`/`Execute` this is the SQL of the underlying
    /// prepared statement; for `FunctionCall` it is empty.
    pub sql: &'a str,
    /// The prepared-statement name, for `Parse`.
    pub statement_name: Option<&'a str>,
    /// The portal name, for `Bind`/`Execute`.
    pub portal_name: Option<&'a str>,
    /// Whether the referenced prepared statement is known to the proxy. When
    /// this is `false` for a `Bind`/`Execute`, the client is referring to a
    /// statement the proxy never authorised.
    pub statement_known: bool,
    /// Bound parameter values, for `Bind` (only populated when the proxy
    /// decoded them; `None` means "not available").
    pub parameters: Option<&'a [Option<Bytes>]>,
}

/// What the query hook decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryDecision {
    /// Let the statement through unchanged.
    Allow,
    /// Replace the SQL text. Only meaningful for [`QueryKind::Simple`] and
    /// [`QueryKind::Parse`]; for any other kind the proxy treats it as a
    /// rejection.
    Rewrite(String),
    /// Reject the statement, sending a synthetic `ErrorResponse` to the client.
    Deny {
        /// SQLSTATE to report; defaults to `42501 insufficient_privilege`.
        sqlstate: Option<String>,
        /// Human-readable message.
        message: String,
    },
}

impl QueryDecision {
    /// Reject with the default SQLSTATE and a message.
    pub fn deny(message: impl Into<String>) -> Self {
        QueryDecision::Deny {
            sqlstate: None,
            message: message.into(),
        }
    }

    /// Reject with an explicit SQLSTATE.
    pub fn deny_with(sqlstate: impl Into<String>, message: impl Into<String>) -> Self {
        QueryDecision::Deny {
            sqlstate: Some(sqlstate.into()),
            message: message.into(),
        }
    }

    /// The SQLSTATE this decision will report, if it is a rejection.
    pub fn sqlstate(&self) -> Option<&str> {
        match self {
            QueryDecision::Deny { sqlstate, .. } => sqlstate.as_deref(),
            _ => None,
        }
    }
}

/// The query hook.
///
/// `authorize` is called before the proxy forwards a statement to the upstream
/// server, for every [`QueryKind`]. Returning [`QueryDecision::Deny`] makes the
/// proxy answer the client itself without ever telling the upstream server
/// about the statement.
#[async_trait]
pub trait QueryHook: Send + Sync + 'static {
    /// Authorise (or reject) a statement.
    async fn authorize(&self, ctx: QueryContext<'_>) -> QueryDecision;
}

/// A [`QueryHook`] that allows everything. Handy for a transparent proxy.
#[derive(Debug, Clone, Copy, Default)]
pub struct AllowAllQueries;

#[async_trait]
impl QueryHook for AllowAllQueries {
    async fn authorize(&self, _ctx: QueryContext<'_>) -> QueryDecision {
        QueryDecision::Allow
    }
}
