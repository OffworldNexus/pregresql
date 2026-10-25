//! The proxy: configuration, hooks, listeners and per-connection sessions.
//!
//! The public surface is intentionally small:
//!
//! ```no_run
//! use std::sync::Arc;
//! use pregresql::proxy::{AllowAllQueries, Proxy, ProxyConfig};
//! # use pregresql::proxy::{AuthContext, AuthError, AuthHook, UpstreamTarget};
//! # use async_trait::async_trait;
//! # struct MyAuth;
//! # #[async_trait]
//! # impl AuthHook for MyAuth {
//! #     async fn resolve_upstream(&self, _ctx: AuthContext<'_>) -> Result<UpstreamTarget, AuthError> {
//! #         Ok(UpstreamTarget::tcp("127.0.0.1", 5432, "postgres"))
//! #     }
//! # }
//! # async fn run() -> pregresql::Result<()> {
//! let proxy = Proxy::new(
//!     ProxyConfig::default(),
//!     Arc::new(MyAuth),
//!     Arc::new(AllowAllQueries),
//! )?;
//! proxy.run().await
//! # }
//! ```

pub mod cancel;
pub mod config;
pub mod hooks;
pub mod server;
pub mod session;
pub mod stream;
pub mod tls;

pub use cancel::{CancelRegistry, CancelTarget};
pub use config::{
    ListenAddr, ProxyConfig, TlsClientOptions, TlsServerOptions, UpstreamTls, VerifyMode,
};
pub use hooks::{
    AllowAllQueries, AuthContext, AuthError, AuthHook, ClientAuthMethod, Endpoint,
    InboundConnection, QueryContext, QueryDecision, QueryHook, QueryKind, TlsInfo, Transport,
    UpstreamTarget,
};
pub use server::Proxy;
pub use stream::{AsyncReadWrite, BoxedStream, RawStream};
