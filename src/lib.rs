//! `pregresql` — a mostly-transparent proxy for the PostgreSQL frontend/backend
//! wire protocol, with pluggable authentication and query-policy hooks.
//!
//! The crate re-implements the PostgreSQL v3.0 protocol in pure Rust: startup
//! handling, SSL/GSSENC negotiation, trust/cleartext/MD5/SCRAM-SHA-256
//! authentication (both as server towards the client and as client towards the
//! upstream server), the simple and extended query protocols, the COPY
//! sub-protocol, cancellation, and asynchronous notifications.
//!
//! Two hooks drive the proxy's behaviour:
//!
//! * [`proxy::AuthHook`] is consulted when a client connects. It decides how
//!   the client authenticates to the proxy and, once the client's credentials
//!   have been observed (and, when possible, verified), returns the actual
//!   upstream target to connect to.
//! * [`proxy::QueryHook`] is consulted before every statement is executed and
//!   may allow it, rewrite it, or reject it with a synthetic `ErrorResponse`.
//!
//! See the `pregresql-proxy` binary for a full worked example, and `README.md`
//! for the design notes and observed limitations.

pub mod auth;
pub mod error;
pub mod protocol;
pub mod proxy;

pub use error::{Error, Result};
pub use proxy::{
    AuthContext, AuthError, AuthHook, ClientAuthMethod, Endpoint, InboundConnection, Proxy,
    ProxyConfig, QueryContext, QueryDecision, QueryHook, QueryKind, TlsInfo, Transport,
    UpstreamTarget, UpstreamTls, VerifyMode,
};

/// The protocol version implemented by this crate (3.0).
pub const PROTOCOL_VERSION: i32 = protocol::codec::PROTOCOL_VERSION_3_0;
