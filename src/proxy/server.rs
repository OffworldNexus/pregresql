//! Listener plumbing: bind (or adopt) sockets, accept connections, negotiate
//! the startup phase (including TLS) and hand the connection to a [`Session`].

use std::future::Future;
use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};
use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use rand::Rng;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UnixListener};
use tokio_rustls::TlsAcceptor;

use crate::error::{Error, Result};
use crate::protocol::codec::decode_startup_packet;
use crate::protocol::message::fatal_response;
use crate::protocol::startup::StartupPacket;
use crate::proxy::cancel::{handle_cancel_request, CancelRegistry};
use crate::proxy::config::{ListenAddr, ProxyConfig};
use crate::proxy::hooks::{AuthHook, QueryHook, TlsInfo, Transport};
use crate::proxy::session::Session;
use crate::proxy::stream::{unix_peer_cred, BoxedStream, RawStream};

/// A listener bound by the embedding application and handed to the proxy.
enum AdoptedListener {
    Unix(std::os::unix::net::UnixListener, Arc<str>),
    Tcp(std::net::TcpListener, Arc<str>),
}

/// The first packet of a connection, once any TLS negotiation is finished.
enum FirstPacket {
    Startup(crate::protocol::startup::StartupParams),
    Cancel { pid: i32, secret: i32 },
}

/// A running proxy: configuration plus the two hooks.
pub struct Proxy {
    config: ProxyConfig,
    auth: Arc<dyn AuthHook>,
    query: Arc<dyn QueryHook>,
    cancels: Arc<CancelRegistry>,
    tls_acceptor: Option<TlsAcceptor>,
    next_connection: AtomicU64,
    next_pid: AtomicI32,
    semaphore: Option<Arc<tokio::sync::Semaphore>>,
    adopted: Vec<AdoptedListener>,
}

impl std::fmt::Debug for Proxy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Proxy")
            .field("listen", &self.config.listen)
            .field("tls", &self.tls_acceptor.is_some())
            .field("adopted_listeners", &self.adopted.len())
            .finish_non_exhaustive()
    }
}

impl Proxy {
    /// Build a proxy. Fails if the TLS material cannot be loaded.
    pub fn new(
        config: ProxyConfig,
        auth: Arc<dyn AuthHook>,
        query: Arc<dyn QueryHook>,
    ) -> Result<Self> {
        let tls_acceptor = match &config.tls {
            None => None,
            Some(options) => {
                let server_config = crate::proxy::tls::server_config(
                    &options.cert_file,
                    &options.key_file,
                    options.client_ca_file.as_deref(),
                )?;
                Some(TlsAcceptor::from(server_config))
            }
        };
        if config.require_tls && tls_acceptor.is_none() {
            return Err(Error::other(
                "require_tls is set but no TLS certificate was configured",
            ));
        }
        let semaphore = config
            .max_connections
            .map(|n| Arc::new(tokio::sync::Semaphore::new(n)));
        Ok(Self {
            config,
            auth,
            query,
            cancels: CancelRegistry::new(),
            tls_acceptor,
            next_connection: AtomicU64::new(1),
            next_pid: AtomicI32::new(1_000_000),
            semaphore,
            adopted: Vec::new(),
        })
    }

    /// Serve an already-bound Unix-domain socket listener, alongside the
    /// addresses in [`ProxyConfig::listen`].
    ///
    /// Every connection it accepts carries `tag` in
    /// [`InboundConnection::listener_tag`](crate::proxy::InboundConnection::listener_tag),
    /// so hooks can tell the listeners apart. A typical use is one listener
    /// per client identity, each protected by file permissions — the kernel
    /// then enforces who may `connect()` to which tag. The listener is
    /// typically inherited from a parent process (via
    /// [`FromRawFd`](std::os::fd::FromRawFd)); it may be in blocking mode, the
    /// proxy switches it to non-blocking when it starts serving.
    ///
    /// The proxy never unlinks the socket file of an adopted listener. On
    /// Linux and Android it enables `SO_PASSCRED` on it, see
    /// [`Transport::message_credentials`].
    pub fn add_unix_listener(
        &mut self,
        listener: std::os::unix::net::UnixListener,
        tag: impl Into<String>,
    ) -> &mut Self {
        let tag: String = tag.into();
        self.adopted
            .push(AdoptedListener::Unix(listener, Arc::from(tag)));
        self
    }

    /// Serve an already-bound TCP listener, alongside the addresses in
    /// [`ProxyConfig::listen`]. See [`Proxy::add_unix_listener`] for the role
    /// of `tag`.
    pub fn add_tcp_listener(
        &mut self,
        listener: std::net::TcpListener,
        tag: impl Into<String>,
    ) -> &mut Self {
        let tag: String = tag.into();
        self.adopted
            .push(AdoptedListener::Tcp(listener, Arc::from(tag)));
        self
    }

    /// The cancellation registry (mostly useful for tests).
    pub fn cancels(&self) -> &Arc<CancelRegistry> {
        &self.cancels
    }

    /// Serve until `shutdown` resolves.
    ///
    /// Binds every address in [`ProxyConfig::listen`] and serves those plus
    /// the listeners added with [`Proxy::add_unix_listener`] and
    /// [`Proxy::add_tcp_listener`].
    pub async fn run_until<F: Future<Output = ()>>(mut self, shutdown: F) -> Result<()> {
        let adopted = std::mem::take(&mut self.adopted);
        let proxy = Arc::new(self);
        let mut listeners = Vec::new();

        for addr in proxy.config.listen.clone() {
            match addr {
                ListenAddr::Tcp(addr) => {
                    let listener = TcpListener::bind(addr).await.map_err(|e| {
                        Error::other(format!("cannot bind tcp listener on {addr}: {e}"))
                    })?;
                    tracing::info!(%addr, "listening for PostgreSQL clients over TCP");
                    let proxy = Arc::clone(&proxy);
                    listeners.push(tokio::spawn(async move {
                        proxy.serve_tcp(listener, None).await
                    }));
                }
                ListenAddr::Unix(path) => {
                    if proxy.config.replace_unix_socket {
                        match std::fs::remove_file(&path) {
                            Ok(()) => {}
                            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                            Err(e) => {
                                return Err(Error::other(format!(
                                    "cannot remove stale socket {}: {e}",
                                    path.display()
                                )))
                            }
                        }
                    }
                    let listener = UnixListener::bind(&path).map_err(|e| {
                        Error::other(format!("cannot bind unix socket {}: {e}", path.display()))
                    })?;
                    tracing::info!(path = %path.display(), "listening for PostgreSQL clients over a Unix socket");
                    let proxy = Arc::clone(&proxy);
                    listeners.push(tokio::spawn(async move {
                        proxy.serve_unix(listener, None).await
                    }));
                }
            }
        }

        for adopted in adopted {
            match adopted {
                AdoptedListener::Tcp(listener, tag) => {
                    let listener = listener
                        .set_nonblocking(true)
                        .and_then(|()| TcpListener::from_std(listener))
                        .map_err(|e| {
                            Error::other(format!("cannot adopt tcp listener {tag:?}: {e}"))
                        })?;
                    match listener.local_addr() {
                        Ok(addr) => {
                            tracing::info!(%addr, tag = %tag, "listening for PostgreSQL clients over an adopted TCP listener")
                        }
                        Err(_) => {
                            tracing::info!(tag = %tag, "listening for PostgreSQL clients over an adopted TCP listener")
                        }
                    }
                    let proxy = Arc::clone(&proxy);
                    listeners.push(tokio::spawn(async move {
                        proxy.serve_tcp(listener, Some(tag)).await
                    }));
                }
                AdoptedListener::Unix(listener, tag) => {
                    let listener = listener
                        .set_nonblocking(true)
                        .and_then(|()| UnixListener::from_std(listener))
                        .map_err(|e| {
                            Error::other(format!("cannot adopt unix listener {tag:?}: {e}"))
                        })?;
                    let path = listener
                        .local_addr()
                        .ok()
                        .and_then(|addr| addr.as_pathname().map(|p| p.display().to_string()))
                        .unwrap_or_default();
                    tracing::info!(path = %path, tag = %tag, "listening for PostgreSQL clients over an adopted Unix socket");
                    let proxy = Arc::clone(&proxy);
                    listeners.push(tokio::spawn(async move {
                        proxy.serve_unix(listener, Some(tag)).await
                    }));
                }
            }
        }

        shutdown.await;
        for listener in listeners {
            listener.abort();
        }
        Ok(())
    }

    /// Serve forever.
    pub async fn run(self) -> Result<()> {
        self.run_until(std::future::pending()).await
    }

    async fn acquire_slot(&self) -> Option<tokio::sync::OwnedSemaphorePermit> {
        match &self.semaphore {
            None => None,
            Some(semaphore) => Some(
                Arc::clone(semaphore)
                    .acquire_owned()
                    .await
                    .expect("connection semaphore is never closed"),
            ),
        }
    }

    async fn serve_tcp(
        self: Arc<Self>,
        listener: TcpListener,
        tag: Option<Arc<str>>,
    ) -> Result<()> {
        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(error = %e, "accept failed");
                    continue;
                }
            };
            let _ = stream.set_nodelay(true);
            let local = match stream.local_addr() {
                Ok(addr) => addr,
                Err(_) => peer,
            };
            let permit = self.acquire_slot().await;
            let transport = Transport::Tcp { peer, local };
            let proxy = Arc::clone(&self);
            let tag = tag.clone();
            tokio::spawn(async move {
                let _permit = permit;
                let buf = BytesMut::with_capacity(16 * 1024);
                proxy
                    .serve(RawStream::Tcp(stream), transport, tag, buf)
                    .await;
            });
        }
    }

    async fn serve_unix(
        self: Arc<Self>,
        listener: UnixListener,
        tag: Option<Arc<str>>,
    ) -> Result<()> {
        // Accepted sockets inherit SO_PASSCRED from the listener on Linux, so
        // data a client writes before it is even accepted carries credentials.
        #[cfg(any(target_os = "linux", target_os = "android"))]
        if let Err(e) = crate::proxy::stream::set_passcred(&listener) {
            tracing::debug!(error = %e, "cannot enable SO_PASSCRED on the unix listener");
        }
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(error = %e, "accept failed");
                    continue;
                }
            };
            let path = match listener.local_addr() {
                Ok(addr) => addr.as_pathname().map(|p| p.to_path_buf()),
                Err(_) => None,
            };
            let cred = unix_peer_cred(&stream);
            let permit = self.acquire_slot().await;
            let proxy = Arc::clone(&self);
            let tag = tag.clone();
            tokio::spawn(async move {
                let _permit = permit;
                let mut buf = BytesMut::with_capacity(16 * 1024);
                let message_credentials = match first_unix_read(&stream, &mut buf).await {
                    Ok(credentials) => credentials,
                    Err(e) => {
                        if !e.is_disconnect() {
                            tracing::debug!(error = %e, "first read from unix client failed");
                        }
                        return;
                    }
                };
                let transport = Transport::Unix {
                    path: path.unwrap_or_default(),
                    peer_pid: cred.map(|c| c.0),
                    peer_uid: cred.map(|c| c.1),
                    peer_gid: cred.map(|c| c.2),
                    message_credentials,
                };
                proxy
                    .serve(RawStream::Unix(stream), transport, tag, buf)
                    .await;
            });
        }
    }

    /// Serve one accepted connection. `buf` holds any bytes already read from
    /// the client (see [`first_unix_read`]).
    async fn serve(
        self: Arc<Self>,
        raw: RawStream,
        transport: Transport,
        listener_tag: Option<Arc<str>>,
        mut buf: BytesMut,
    ) {
        let id = self.next_connection.fetch_add(1, Ordering::Relaxed);
        let pid = self.next_pid.fetch_add(1, Ordering::Relaxed);
        let mut secret_bytes = [0u8; 4];
        rand::thread_rng().fill(&mut secret_bytes);
        let secret = i32::from_ne_bytes(secret_bytes);

        let (mut client, first, tls) = match self.negotiate(Some(raw), &mut buf).await {
            Ok(v) => v,
            Err(e) => {
                if !e.is_disconnect() {
                    tracing::debug!(connection = id, error = %e, "startup negotiation failed");
                }
                return;
            }
        };

        let startup = match first {
            FirstPacket::Cancel { pid, secret } => {
                tracing::debug!(connection = id, pid, "handling cancel request");
                match handle_cancel_request(&self.cancels, pid, secret).await {
                    Ok(true) => tracing::debug!(connection = id, pid, "cancel forwarded"),
                    Ok(false) => {
                        tracing::debug!(
                            connection = id,
                            pid,
                            "cancel request for unknown backend key"
                        )
                    }
                    Err(e) => {
                        tracing::debug!(connection = id, error = %e, "cancel forwarding failed")
                    }
                }
                return;
            }
            FirstPacket::Startup(startup) => startup,
        };

        if self.config.require_tls && !tls.negotiated {
            let frame = fatal_response("28000", "TLS is required for this proxy");
            let _ = client.write_all(&frame.encode()).await;
            return;
        }

        if startup.user().is_none() {
            let frame = fatal_response(
                "28000",
                "no PostgreSQL user name specified in startup packet",
            );
            let _ = client.write_all(&frame.encode()).await;
            return;
        }

        tracing::debug!(
            connection = id,
            user = startup.user().unwrap_or_default(),
            database = startup.database().unwrap_or_default(),
            tls = tls.negotiated,
            "accepted connection"
        );

        let session = Session::new(
            id,
            client as BoxedStream,
            buf,
            startup,
            transport,
            listener_tag,
            tls,
            Arc::clone(&self.auth),
            Arc::clone(&self.query),
            Arc::clone(&self.cancels),
            self.config.max_message_length,
            pid,
            secret,
        );
        if let Err(e) = session.run().await {
            if !e.is_disconnect() {
                tracing::debug!(connection = id, error = %e, "session ended with an error");
            }
        }
    }

    /// Drive the startup phase: TLS negotiation, then the first startup packet.
    async fn negotiate(
        &self,
        mut raw: Option<RawStream>,
        buf: &mut BytesMut,
    ) -> Result<(BoxedStream, FirstPacket, TlsInfo)> {
        let mut tls = TlsInfo::default();

        loop {
            let stream = raw
                .as_mut()
                .ok_or_else(|| Error::other("stream already consumed"))?;
            let packet = read_first_packet(stream, buf).await?;
            match packet {
                StartupPacket::SslRequest => match self.tls_acceptor.clone() {
                    None => {
                        stream.write_all(b"N").await?;
                        stream.flush().await?;
                    }
                    Some(acceptor) => {
                        stream.write_all(b"S").await?;
                        stream.flush().await?;
                        crate::proxy::stream::expect_empty(buf, "before the TLS handshake")?;
                        let consumed = raw.take().expect("stream is present");
                        let tls_stream = consumed.upgrade_to_tls_server(acceptor).await?;
                        tls.negotiated = true;
                        tls.peer_certificate = tls_stream
                            .get_ref()
                            .1
                            .peer_certificates()
                            .and_then(|certs| certs.first())
                            .map(|cert| Bytes::copy_from_slice(cert.as_ref()));
                        let mut boxed: BoxedStream = Box::new(tls_stream);
                        return match read_first_packet(&mut boxed, buf).await? {
                            StartupPacket::Startup(params) => {
                                Ok((boxed, FirstPacket::Startup(params), tls))
                            }
                            StartupPacket::CancelRequest { pid, secret } => {
                                Ok((boxed, FirstPacket::Cancel { pid, secret }, tls))
                            }
                            other => Err(Error::protocol(format!(
                                "unexpected startup packet after TLS negotiation: {other:?}"
                            ))),
                        };
                    }
                },
                StartupPacket::GssEncRequest => {
                    stream.write_all(b"N").await?;
                    stream.flush().await?;
                }
                StartupPacket::Startup(params) => {
                    let boxed: BoxedStream = Box::new(raw.take().expect("stream is present"));
                    return Ok((boxed, FirstPacket::Startup(params), tls));
                }
                StartupPacket::CancelRequest { pid, secret } => {
                    let boxed: BoxedStream = Box::new(raw.take().expect("stream is present"));
                    return Ok((boxed, FirstPacket::Cancel { pid, secret }, tls));
                }
            }
        }
    }
}

/// Perform the first read of an accepted Unix connection.
///
/// On Linux and Android this is a `recvmsg` that also collects the
/// `SCM_CREDENTIALS` the kernel attached to the client's first message; the data
/// lands in `buf`, where the startup negotiation decodes it from. Elsewhere this
/// reads nothing and returns `None`, leaving the first read to the negotiation.
#[cfg(any(target_os = "linux", target_os = "android"))]
async fn first_unix_read(
    stream: &tokio::net::UnixStream,
    buf: &mut BytesMut,
) -> Result<Option<crate::proxy::hooks::UnixCredentials>> {
    // Normally inherited from the listener; set it again in case it was not
    // (e.g. a listener whose flags could not be changed).
    if let Err(e) = crate::proxy::stream::set_passcred(stream) {
        tracing::debug!(error = %e, "cannot enable SO_PASSCRED on the unix connection");
        return Ok(None);
    }
    crate::proxy::stream::read_buf_with_credentials(stream, buf).await
}

/// See the Linux version: other platforms have no `SCM_CREDENTIALS`.
#[cfg(not(any(target_os = "linux", target_os = "android")))]
async fn first_unix_read(
    _stream: &tokio::net::UnixStream,
    _buf: &mut BytesMut,
) -> Result<Option<crate::proxy::hooks::UnixCredentials>> {
    Ok(None)
}

/// Read one startup-phase packet from any reader.
async fn read_first_packet<R: AsyncRead + Unpin>(
    stream: &mut R,
    buf: &mut BytesMut,
) -> Result<StartupPacket> {
    loop {
        let decoded = { decode_startup_packet(buf)? };
        if let Some(packet) = decoded {
            return Ok(packet);
        }
        buf.reserve(16 * 1024);
        let n = stream.read_buf(buf).await?;
        if n == 0 {
            return Err(Error::ConnectionClosed);
        }
    }
}
