//! Cancellation support.
//!
//! A `CancelRequest` arrives on a *fresh* connection. Because the proxy hands
//! the client its own `(pid, secret)` pair instead of the upstream server's, it
//! keeps a registry mapping its own keys to the upstream connection so that it
//! can re-issue the cancellation against the real server.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tokio::io::AsyncWriteExt;

use crate::error::{Error, Result};
use crate::protocol::startup::cancel_request_bytes;
use crate::proxy::config::{Endpoint, UpstreamTls};
use crate::proxy::stream::{BoxedStream, RawStream};

/// Where a `CancelRequest` should be forwarded.
#[derive(Debug, Clone)]
pub struct CancelTarget {
    /// Upstream server to contact.
    pub endpoint: Endpoint,
    /// TLS mode to use for that contact.
    pub tls: UpstreamTls,
    /// Backend pid, as reported by the upstream server.
    pub pid: i32,
    /// Backend secret, as reported by the upstream server.
    pub secret: i32,
}

/// A process-wide map of `(proxy pid, proxy secret) -> upstream backend`.
#[derive(Debug, Default)]
pub struct CancelRegistry {
    inner: Mutex<HashMap<(i32, i32), CancelTarget>>,
}

impl CancelRegistry {
    /// Create a shared registry.
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Remember the upstream backend for a session.
    pub fn register(&self, pid: i32, secret: i32, target: CancelTarget) {
        if let Ok(mut map) = self.inner.lock() {
            map.insert((pid, secret), target);
        }
    }

    /// Forget a session.
    pub fn unregister(&self, pid: i32, secret: i32) {
        if let Ok(mut map) = self.inner.lock() {
            map.remove(&(pid, secret));
        }
    }

    /// Look up the upstream backend for a pair of proxy credentials.
    pub fn lookup(&self, pid: i32, secret: i32) -> Option<CancelTarget> {
        self.inner
            .lock()
            .ok()
            .and_then(|map| map.get(&(pid, secret)).cloned())
    }

    /// Number of live sessions (useful in tests).
    pub fn len(&self) -> usize {
        self.inner.lock().map(|m| m.len()).unwrap_or(0)
    }

    /// True when no session is registered.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Open a connection to the upstream server and send a `CancelRequest`.
pub async fn forward_cancel(target: &CancelTarget) -> Result<()> {
    let mut stream = RawStream::connect(&target.endpoint).await?;
    let host = host_of(&target.endpoint).to_string();

    let mut stream: BoxedStream = match &target.tls {
        UpstreamTls::Disable => Box::new(stream),
        UpstreamTls::Prefer(options) => {
            if stream.ssl_request().await? {
                stream.start_tls_client(&host, options).await?
            } else {
                Box::new(stream)
            }
        }
        UpstreamTls::Require(options) => {
            if !stream.ssl_request().await? {
                return Err(Error::tls(
                    "upstream server does not support TLS but TLS was required",
                ));
            }
            stream.start_tls_client(&host, options).await?
        }
    };

    stream
        .write_all(&cancel_request_bytes(target.pid, target.secret))
        .await?;
    stream.flush().await?;
    // The server does not reply to a cancel request; close and move on.
    let _ = stream.shutdown().await;
    Ok(())
}

fn host_of(endpoint: &Endpoint) -> &str {
    match endpoint {
        Endpoint::Tcp { host, .. } => host,
        Endpoint::Unix { .. } => "localhost",
    }
}

/// Convenience wrapper: look up and forward in one step.
pub async fn handle_cancel_request(
    registry: &CancelRegistry,
    pid: i32,
    secret: i32,
) -> Result<bool> {
    let Some(target) = registry.lookup(pid, secret) else {
        return Ok(false);
    };
    forward_cancel(&target).await?;
    Ok(true)
}

/// Marker error for "no such backend key".
pub fn unknown_backend_key(pid: i32, secret: i32) -> Error {
    Error::other(format!(
        "cancel request for unknown backend key (pid={pid}, secret={secret})"
    ))
}
