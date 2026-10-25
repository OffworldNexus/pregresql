//! Adopted (pre-bound) listeners, listener tags, `SCM_CREDENTIALS`, and the
//! connection details handed to the query hook — all over real sockets.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use bytes::{BufMut, BytesMut};
use pregresql::protocol::codec::{decode_frame, Frame};
use pregresql::protocol::message::ErrorFields;
use pregresql::protocol::startup::StartupParams;
use pregresql::proxy::{
    AuthContext, AuthError, AuthHook, Endpoint, InboundConnection, Proxy, ProxyConfig,
    QueryContext, QueryDecision, QueryHook, UpstreamTarget,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::oneshot;

const TIMEOUT: Duration = Duration::from_secs(10);

/// A short, unique scratch directory (Unix socket paths are limited to ~104
/// bytes on macOS, so this stays under `/tmp` rather than `$TMPDIR`).
struct ScratchDir(PathBuf);

impl ScratchDir {
    fn new() -> Self {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = PathBuf::from(format!("/tmp/pgq-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("create scratch dir");
        Self(path)
    }

    fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Records every connection the auth hook sees, then either rejects it or
/// sends it to `upstream`.
#[derive(Default)]
struct RecordingAuth {
    seen: Mutex<Vec<InboundConnection>>,
    upstream: Option<PathBuf>,
}

#[async_trait]
impl AuthHook for RecordingAuth {
    async fn resolve_upstream(&self, ctx: AuthContext<'_>) -> Result<UpstreamTarget, AuthError> {
        self.seen.lock().unwrap().push(ctx.connection.clone());
        match &self.upstream {
            None => Err(AuthError::rejected(format!(
                "rejected by test hook (tag {:?})",
                ctx.connection.listener_tag()
            ))),
            Some(path) => Ok(UpstreamTarget {
                endpoint: Endpoint::unix(path),
                ..UpstreamTarget::tcp("unused", 0, "upstream_role")
            }),
        }
    }
}

/// Records the connection behind every statement and denies it.
#[derive(Default)]
struct RecordingQueries {
    seen: Mutex<Vec<(u64, InboundConnection, String)>>,
}

#[async_trait]
impl QueryHook for RecordingQueries {
    async fn authorize(&self, ctx: QueryContext<'_>) -> QueryDecision {
        self.seen.lock().unwrap().push((
            ctx.connection_id,
            ctx.connection.clone(),
            ctx.sql.to_string(),
        ));
        QueryDecision::deny(format!(
            "denied for tag {}",
            ctx.connection.listener_tag().unwrap_or("-")
        ))
    }
}

fn config() -> ProxyConfig {
    ProxyConfig {
        listen: Vec::new(),
        ..ProxyConfig::default()
    }
}

/// Start the proxy; dropping the returned sender stops it.
fn start(proxy: Proxy) -> oneshot::Sender<()> {
    let (tx, rx) = oneshot::channel::<()>();
    tokio::spawn(proxy.run_until(async move {
        let _ = rx.await;
    }));
    tx
}

fn startup_bytes(user: &str) -> Vec<u8> {
    StartupParams::new(vec![
        ("user".to_string(), user.to_string()),
        ("database".to_string(), "testdb".to_string()),
        ("application_name".to_string(), "listeners-test".to_string()),
    ])
    .to_bytes()
    .to_vec()
}

fn ssl_request_bytes() -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&8i32.to_be_bytes());
    out.extend_from_slice(&80877103i32.to_be_bytes());
    out
}

async fn read_frame<S: AsyncRead + Unpin>(stream: &mut S, buf: &mut BytesMut) -> Frame {
    tokio::time::timeout(TIMEOUT, async {
        loop {
            if let Some(frame) = decode_frame(buf, 1 << 20).expect("valid frame") {
                return frame;
            }
            buf.reserve(4096);
            let n = stream.read_buf(buf).await.expect("read");
            assert!(n > 0, "proxy closed the connection unexpectedly");
        }
    })
    .await
    .expect("timed out waiting for a message")
}

/// Read until the proxy's FATAL `ErrorResponse` and return its message.
async fn read_fatal<S: AsyncRead + Unpin>(stream: &mut S) -> String {
    let mut buf = BytesMut::new();
    loop {
        let frame = read_frame(stream, &mut buf).await;
        if frame.tag == b'E' {
            let fields = ErrorFields::parse(&frame.body).expect("error fields");
            assert_eq!(fields.severity(), Some("FATAL"));
            return fields.message().unwrap_or_default().to_string();
        }
    }
}

/// Bind a listener the way an embedding application would, before the proxy
/// exists.
fn bind_unix(path: &Path) -> std::os::unix::net::UnixListener {
    std::os::unix::net::UnixListener::bind(path).expect("bind unix listener")
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn assert_own_credentials(connection: &InboundConnection) {
    let credentials = connection
        .transport
        .message_credentials()
        .expect("SCM_CREDENTIALS of the first message");
    // SAFETY: plain libc getters without preconditions.
    let (pid, uid, gid) = unsafe { (libc::getpid(), libc::getuid(), libc::getgid()) };
    assert_eq!(credentials.pid, pid);
    assert_eq!(credentials.uid, uid);
    assert_eq!(credentials.gid, gid);
    assert_eq!(connection.transport.message_uid(), Some(uid));
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn assert_own_credentials(connection: &InboundConnection) {
    assert_eq!(connection.transport.message_credentials(), None);
    assert_eq!(connection.transport.message_uid(), None);
}

fn assert_startup_parsed(connection: &InboundConnection, user: &str) {
    assert_eq!(connection.user(), Some(user));
    assert_eq!(connection.database(), Some("testdb"));
    assert_eq!(connection.application_name(), Some("listeners-test"));
}

#[tokio::test]
async fn adopted_unix_listener_carries_its_tag() {
    let dir = ScratchDir::new();
    let path = dir.join("a.sock");
    let auth = Arc::new(RecordingAuth::default());
    let mut proxy = Proxy::new(
        config(),
        auth.clone(),
        Arc::new(RecordingQueries::default()),
    )
    .unwrap();
    proxy.add_unix_listener(bind_unix(&path), "view-a");
    let _stop = start(proxy);

    let mut client = tokio::net::UnixStream::connect(&path).await.unwrap();
    client.write_all(&startup_bytes("alice")).await.unwrap();
    let message = read_fatal(&mut client).await;
    assert!(message.contains("view-a"), "{message}");

    let seen = auth.seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].listener_tag(), Some("view-a"));
    assert!(seen[0].transport.is_unix());
    assert_startup_parsed(&seen[0], "alice");
    assert_own_credentials(&seen[0]);
    assert!(path.exists(), "adopted sockets are never unlinked");
}

#[tokio::test]
async fn each_adopted_listener_has_its_own_tag_and_config_listeners_have_none() {
    let dir = ScratchDir::new();
    let configured = dir.join("c.sock");
    let a = dir.join("a.sock");
    let b = dir.join("b.sock");
    let auth = Arc::new(RecordingAuth::default());
    let mut proxy = Proxy::new(
        config().listen_on(pregresql::proxy::ListenAddr::Unix(configured.clone())),
        auth.clone(),
        Arc::new(RecordingQueries::default()),
    )
    .unwrap();
    proxy
        .add_unix_listener(bind_unix(&a), "a")
        .add_unix_listener(bind_unix(&b), "b");
    let _stop = start(proxy);

    for (path, user) in [(&b, "bob"), (&a, "alice")] {
        let mut client = tokio::net::UnixStream::connect(path).await.unwrap();
        client.write_all(&startup_bytes(user)).await.unwrap();
        read_fatal(&mut client).await;
    }
    // The configured listener is bound inside `run_until`; wait for it.
    let mut client = tokio::time::timeout(TIMEOUT, async {
        loop {
            match tokio::net::UnixStream::connect(&configured).await {
                Ok(stream) => break stream,
                Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
            }
        }
    })
    .await
    .unwrap();
    client.write_all(&startup_bytes("carol")).await.unwrap();
    read_fatal(&mut client).await;

    let seen = auth.seen.lock().unwrap();
    let tags: Vec<_> = seen
        .iter()
        .map(|c| {
            (
                c.user().unwrap().to_string(),
                c.listener_tag().map(str::to_string),
            )
        })
        .collect();
    assert_eq!(
        tags,
        vec![
            ("bob".to_string(), Some("b".to_string())),
            ("alice".to_string(), Some("a".to_string())),
            ("carol".to_string(), None),
        ]
    );
    for connection in seen.iter() {
        assert_own_credentials(connection);
    }
}

#[tokio::test]
async fn adopted_tcp_listener_carries_its_tag() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let auth = Arc::new(RecordingAuth::default());
    let mut proxy = Proxy::new(
        config(),
        auth.clone(),
        Arc::new(RecordingQueries::default()),
    )
    .unwrap();
    proxy.add_tcp_listener(listener, "tcp-tag");
    let _stop = start(proxy);

    let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
    client.write_all(&startup_bytes("tom")).await.unwrap();
    read_fatal(&mut client).await;

    let seen = auth.seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].listener_tag(), Some("tcp-tag"));
    assert!(!seen[0].transport.is_unix());
    assert_eq!(seen[0].transport.message_credentials(), None);
    assert_startup_parsed(&seen[0], "tom");
}

/// The client writes its whole startup packet before the proxy has even
/// started, let alone accepted: the credentials and every byte must survive.
#[tokio::test]
async fn startup_written_before_accept_is_read_with_credentials() {
    let dir = ScratchDir::new();
    let path = dir.join("early.sock");
    let listener = bind_unix(&path);

    let mut early = std::os::unix::net::UnixStream::connect(&path).unwrap();
    early.write_all(&startup_bytes("early")).unwrap();

    let auth = Arc::new(RecordingAuth::default());
    let mut proxy = Proxy::new(
        config(),
        auth.clone(),
        Arc::new(RecordingQueries::default()),
    )
    .unwrap();
    proxy.add_unix_listener(listener, "early-tag");
    let _stop = start(proxy);

    early.set_nonblocking(true).unwrap();
    let mut client = tokio::net::UnixStream::from_std(early).unwrap();
    read_fatal(&mut client).await;

    let seen = auth.seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].listener_tag(), Some("early-tag"));
    assert_startup_parsed(&seen[0], "early");
    assert_own_credentials(&seen[0]);
}

/// `SSLRequest` first, then a startup packet split across two writes: the
/// first read only sees part of the startup phase, the rest must follow it.
#[tokio::test]
async fn ssl_request_then_fragmented_startup_is_decoded_intact() {
    let dir = ScratchDir::new();
    let path = dir.join("frag.sock");
    let auth = Arc::new(RecordingAuth::default());
    let mut proxy = Proxy::new(
        config(),
        auth.clone(),
        Arc::new(RecordingQueries::default()),
    )
    .unwrap();
    proxy.add_unix_listener(bind_unix(&path), "frag");
    let _stop = start(proxy);

    let mut client = tokio::net::UnixStream::connect(&path).await.unwrap();
    client.write_all(&ssl_request_bytes()).await.unwrap();
    let mut answer = [0u8; 1];
    tokio::time::timeout(TIMEOUT, client.read_exact(&mut answer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&answer, b"N");

    let startup = startup_bytes("fragmented");
    let (head, tail) = startup.split_at(7);
    client.write_all(head).await.unwrap();
    client.flush().await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    client.write_all(tail).await.unwrap();
    read_fatal(&mut client).await;

    let seen = auth.seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert_startup_parsed(&seen[0], "fragmented");
    assert_own_credentials(&seen[0]);
}

/// A client that connects and leaves without a byte must not disturb the
/// listener.
#[tokio::test]
async fn client_closing_before_sending_is_a_plain_disconnect() {
    let dir = ScratchDir::new();
    let path = dir.join("eof.sock");
    let auth = Arc::new(RecordingAuth::default());
    let mut proxy = Proxy::new(
        config(),
        auth.clone(),
        Arc::new(RecordingQueries::default()),
    )
    .unwrap();
    proxy.add_unix_listener(bind_unix(&path), "eof");
    let _stop = start(proxy);

    for _ in 0..3 {
        drop(tokio::net::UnixStream::connect(&path).await.unwrap());
    }
    let mut client = tokio::net::UnixStream::connect(&path).await.unwrap();
    client.write_all(&startup_bytes("after")).await.unwrap();
    read_fatal(&mut client).await;

    let seen = auth.seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert_startup_parsed(&seen[0], "after");
}

/// A minimal upstream: trust authentication, one `BackendKeyData`, then
/// `ReadyForQuery`, then it just waits.
async fn fake_upstream(listener: tokio::net::UnixListener) {
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            return;
        };
        tokio::spawn(async move {
            let mut len = [0u8; 4];
            if stream.read_exact(&mut len).await.is_err() {
                return;
            }
            let len = i32::from_be_bytes(len) as usize;
            let mut rest = vec![0u8; len.saturating_sub(4)];
            if stream.read_exact(&mut rest).await.is_err() {
                return;
            }
            let mut out = BytesMut::new();
            out.extend_from_slice(&frame(b'R', &0i32.to_be_bytes()));
            let mut key = BytesMut::new();
            key.put_i32(4242);
            key.put_i32(77);
            out.extend_from_slice(&frame(b'K', &key));
            out.extend_from_slice(&frame(b'Z', b"I"));
            if stream.write_all(&out).await.is_err() {
                return;
            }
            let mut sink = [0u8; 1024];
            while matches!(stream.read(&mut sink).await, Ok(n) if n > 0) {}
        });
    }
}

fn frame(tag: u8, body: &[u8]) -> Vec<u8> {
    Frame::new(tag, body.to_vec()).encode().to_vec()
}

async fn write_query<S: AsyncWrite + Unpin>(stream: &mut S, sql: &str) {
    let mut body = sql.as_bytes().to_vec();
    body.push(0);
    stream.write_all(&frame(b'Q', &body)).await.unwrap();
}

#[tokio::test]
async fn query_hook_sees_the_connection_and_its_tag() {
    let dir = ScratchDir::new();
    let upstream_path = dir.join("up.sock");
    let proxy_path = dir.join("px.sock");
    tokio::spawn(fake_upstream(
        tokio::net::UnixListener::bind(&upstream_path).unwrap(),
    ));

    let auth = Arc::new(RecordingAuth {
        seen: Mutex::default(),
        upstream: Some(upstream_path),
    });
    let queries = Arc::new(RecordingQueries::default());
    let mut proxy = Proxy::new(config(), auth.clone(), queries.clone()).unwrap();
    proxy.add_unix_listener(bind_unix(&proxy_path), "view-q");
    let _stop = start(proxy);

    let mut client = tokio::net::UnixStream::connect(&proxy_path).await.unwrap();
    client.write_all(&startup_bytes("quinn")).await.unwrap();
    let mut buf = BytesMut::new();
    loop {
        let frame = read_frame(&mut client, &mut buf).await;
        assert_ne!(frame.tag, b'E', "session setup failed");
        if frame.tag == b'Z' {
            break;
        }
    }

    write_query(&mut client, "SELECT 1").await;
    let error = read_frame(&mut client, &mut buf).await;
    assert_eq!(error.tag, b'E');
    let fields = ErrorFields::parse(&error.body).unwrap();
    assert_eq!(fields.message(), Some("denied for tag view-q"));
    assert_eq!(read_frame(&mut client, &mut buf).await.tag, b'Z');

    write_query(&mut client, "SELECT 2").await;
    assert_eq!(read_frame(&mut client, &mut buf).await.tag, b'E');
    assert_eq!(read_frame(&mut client, &mut buf).await.tag, b'Z');
    client.write_all(&frame(b'X', &[])).await.unwrap();

    let auth_seen = auth.seen.lock().unwrap();
    let seen = queries.seen.lock().unwrap();
    assert_eq!(seen.len(), 2);
    for (connection_id, connection, _) in seen.iter() {
        assert_eq!(*connection_id, connection.id);
        assert_eq!(connection.id, auth_seen[0].id);
        assert_eq!(connection.listener_tag(), Some("view-q"));
        assert_eq!(connection.transport, auth_seen[0].transport);
        assert_startup_parsed(connection, "quinn");
        assert_own_credentials(connection);
    }
    assert_eq!(seen[0].2, "SELECT 1");
    assert_eq!(seen[1].2, "SELECT 2");
}
