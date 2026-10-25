//! Socket plumbing: a small enum over TCP and Unix streams, plus helpers to
//! upgrade either kind to TLS and to read Unix peer credentials.

use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpStream, UnixStream};
use tokio_rustls::server::TlsStream as ServerTlsStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::error::{Error, Result};
use crate::protocol::startup::ssl_request_bytes;
use crate::proxy::config::{Endpoint, TlsClientOptions};

/// Anything that can carry a PostgreSQL stream.
pub trait AsyncReadWrite: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + ?Sized> AsyncReadWrite for T {}

/// A boxed, type-erased bidirectional stream.
pub type BoxedStream = Box<dyn AsyncReadWrite>;

/// A freshly accepted or freshly connected stream, before any TLS decision.
#[derive(Debug)]
pub enum RawStream {
    /// Plain TCP.
    Tcp(TcpStream),
    /// Plain Unix-domain socket.
    Unix(UnixStream),
}

impl RawStream {
    /// Connect to an upstream endpoint.
    pub async fn connect(endpoint: &Endpoint) -> Result<Self> {
        match endpoint {
            Endpoint::Tcp { host, port } => {
                let stream = TcpStream::connect((host.as_str(), *port))
                    .await
                    .map_err(|e| {
                        Error::other(format!("cannot connect to upstream {host}:{port}: {e}"))
                    })?;
                // Latency matters for a proxy; never delay small protocol messages.
                let _ = stream.set_nodelay(true);
                Ok(RawStream::Tcp(stream))
            }
            Endpoint::Unix { path } => {
                let stream = UnixStream::connect(path).await.map_err(|e| {
                    Error::other(format!(
                        "cannot connect to upstream socket {}: {e}",
                        path.display()
                    ))
                })?;
                Ok(RawStream::Unix(stream))
            }
        }
    }

    /// Peer credentials for a Unix socket, when the platform provides them.
    pub fn unix_peer_cred(&self) -> Option<(i32, u32, u32)> {
        match self {
            RawStream::Unix(s) => unix_peer_cred(s),
            RawStream::Tcp(_) => None,
        }
    }

    /// Send an `SSLRequest` and read the server's single-byte answer.
    ///
    /// Returns `true` when the server agreed to a TLS handshake (answered `S`).
    pub async fn ssl_request(&mut self) -> Result<bool> {
        self.write_all(&ssl_request_bytes()).await?;
        self.flush().await?;
        let mut answer = [0u8; 1];
        self.read_exact(&mut answer).await.map_err(|e| {
            Error::other(format!(
                "upstream closed the connection during TLS negotiation: {e}"
            ))
        })?;
        match answer[0] {
            b'S' => Ok(true),
            b'N' => Ok(false),
            other => Err(Error::protocol(format!(
                "unexpected response to SSLRequest: 0x{other:02x}"
            ))),
        }
    }

    /// Perform the *client* side of a TLS handshake, after a successful
    /// [`RawStream::ssl_request`].
    pub async fn start_tls_client(
        self,
        host: &str,
        options: &TlsClientOptions,
    ) -> Result<BoxedStream> {
        let config = crate::proxy::tls::client_config(options)?;
        let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
            .map_err(|e| Error::tls(format!("invalid server name {host:?}: {e}")))?;
        let connector = TlsConnector::from(config);
        let stream: BoxedStream = match self {
            RawStream::Tcp(s) => Box::new(connector.connect(server_name, s).await?),
            RawStream::Unix(s) => Box::new(connector.connect(server_name, s).await?),
        };
        Ok(stream)
    }

    /// Perform the *server* side of a TLS handshake.
    pub async fn upgrade_to_tls_server(
        self,
        acceptor: TlsAcceptor,
    ) -> Result<ServerTlsStream<RawStream>> {
        let stream = acceptor.accept(self).await?;
        Ok(stream)
    }
}

impl AsyncRead for RawStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            RawStream::Tcp(s) => Pin::new(s).poll_read(cx, buf),
            RawStream::Unix(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for RawStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            RawStream::Tcp(s) => Pin::new(s).poll_write(cx, buf),
            RawStream::Unix(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            RawStream::Tcp(s) => Pin::new(s).poll_flush(cx),
            RawStream::Unix(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            RawStream::Tcp(s) => Pin::new(s).poll_shutdown(cx),
            RawStream::Unix(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

/// Box a raw stream.
pub fn boxed<T: AsyncReadWrite + 'static>(stream: T) -> BoxedStream {
    Box::new(stream)
}

/// Read Unix peer credentials via `SO_PEERCRED` (Linux) or `getpeereid` (BSD).
#[cfg(unix)]
pub fn unix_peer_cred(stream: &UnixStream) -> Option<(i32, u32, u32)> {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        let fd = stream.as_raw_fd();
        let mut cred = libc::ucred {
            pid: 0,
            uid: 0,
            gid: 0,
        };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        // SAFETY: `cred` is a properly sized, initialized buffer for SO_PEERCRED.
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                &mut cred as *mut libc::ucred as *mut libc::c_void,
                &mut len,
            )
        };
        if rc == 0 {
            Some((cred.pid, cred.uid, cred.gid))
        } else {
            None
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        use std::os::fd::AsRawFd;
        let fd = stream.as_raw_fd();
        let mut uid: libc::uid_t = 0;
        let mut gid: libc::gid_t = 0;
        // SAFETY: both pointers are valid out-parameters for getpeereid.
        let rc = unsafe { libc::getpeereid(fd, &mut uid, &mut gid) };
        if rc == 0 {
            Some((-1, uid, gid))
        } else {
            None
        }
    }
}

#[cfg(not(unix))]
pub fn unix_peer_cred(_stream: &UnixStream) -> Option<(i32, u32, u32)> {
    None
}

/// Fill `buf` with one more chunk of data from `stream`.
///
/// Returns the number of bytes read; zero means end of stream.
pub async fn fill(stream: &mut BoxedStream, buf: &mut BytesMut) -> Result<usize> {
    buf.reserve(16 * 1024);
    let n = stream.read_buf(buf).await?;
    Ok(n)
}

/// Fail when a buffer still holds bytes that belonged to the previous protocol
/// phase (for example, data sent before a TLS handshake completed).
pub fn expect_empty(buf: &BytesMut, what: &str) -> Result<()> {
    if buf.is_empty() {
        Ok(())
    } else {
        Err(Error::protocol(format!(
            "unexpected {} bytes of trailing data {what}",
            buf.len()
        )))
    }
}

/// Ask the kernel to attach `SCM_CREDENTIALS` to every message received on
/// `socket` (`SO_PASSCRED`). Works on listening sockets too: on Linux, accepted
/// sockets inherit the flag from their listener.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn set_passcred(socket: &impl std::os::fd::AsRawFd) -> std::io::Result<()> {
    let one: libc::c_int = 1;
    // SAFETY: `one` is a valid `c_int` option value of the advertised length.
    let rc = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PASSCRED,
            &one as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Perform one read from `stream` with `recvmsg`, appending the data to `buf`
/// and returning the `SCM_CREDENTIALS` the kernel attached to it.
///
/// This is meant for the very first read of a connection, on a socket with
/// `SO_PASSCRED` set (see [`set_passcred`]). It reads whatever is available —
/// exactly like `read_buf` would — so the caller keeps decoding from `buf` as
/// if nothing special had happened: no byte is lost or reordered.
///
/// Returns [`Error::ConnectionClosed`] when the peer closed the connection
/// before sending anything. File descriptors the peer may have passed with
/// `SCM_RIGHTS` are closed immediately.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub async fn read_buf_with_credentials(
    stream: &UnixStream,
    buf: &mut BytesMut,
) -> Result<Option<crate::proxy::hooks::UnixCredentials>> {
    buf.reserve(16 * 1024);
    loop {
        stream.readable().await?;
        let spare = buf.spare_capacity_mut();
        let outcome = stream.try_io(tokio::io::Interest::READABLE, || {
            recvmsg_with_credentials(stream, spare)
        });
        match outcome {
            Ok((0, _)) => return Err(Error::ConnectionClosed),
            Ok((n, credentials)) => {
                // SAFETY: the kernel initialised the first `n` spare bytes.
                unsafe { buf.set_len(buf.len() + n) };
                return Ok(credentials);
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::Interrupted =>
            {
                continue
            }
            Err(e) => return Err(e.into()),
        }
    }
}

/// The blocking-free `recvmsg` behind [`read_buf_with_credentials`].
#[cfg(any(target_os = "linux", target_os = "android"))]
fn recvmsg_with_credentials(
    stream: &UnixStream,
    spare: &mut [std::mem::MaybeUninit<u8>],
) -> std::io::Result<(usize, Option<crate::proxy::hooks::UnixCredentials>)> {
    use std::os::fd::AsRawFd;

    // Room for one `ucred` plus a few stray descriptors; `cmsghdr` alignment.
    #[repr(C, align(8))]
    struct ControlBuffer([u8; 128]);

    let mut control = ControlBuffer([0; 128]);
    // SAFETY: CMSG_SPACE only does arithmetic.
    let needed = unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::ucred>() as libc::c_uint) };
    debug_assert!(needed as usize <= control.0.len());

    let mut iov = libc::iovec {
        iov_base: spare.as_mut_ptr() as *mut libc::c_void,
        iov_len: spare.len(),
    };
    // SAFETY: an all-zero `msghdr` is a valid empty header.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.0.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = control.0.len() as _;

    // SAFETY: `msg` points at a live iovec over writable (if uninitialised)
    // memory and at a live, aligned control buffer of the advertised sizes.
    let n = unsafe { libc::recvmsg(stream.as_raw_fd(), &mut msg, libc::MSG_CMSG_CLOEXEC) };
    if n < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let mut credentials = None;
    // SAFETY: `msg` was filled in by the kernel; the CMSG_* macros walk the
    // control buffer within `msg_controllen`, and payloads are read unaligned.
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            let header = &*cmsg;
            let data = libc::CMSG_DATA(cmsg);
            let payload = (header.cmsg_len as usize).saturating_sub(libc::CMSG_LEN(0) as usize);
            if header.cmsg_level == libc::SOL_SOCKET {
                if header.cmsg_type == libc::SCM_CREDENTIALS
                    && payload >= std::mem::size_of::<libc::ucred>()
                {
                    let cred = std::ptr::read_unaligned(data as *const libc::ucred);
                    credentials = Some(crate::proxy::hooks::UnixCredentials {
                        pid: cred.pid,
                        uid: cred.uid,
                        gid: cred.gid,
                    });
                } else if header.cmsg_type == libc::SCM_RIGHTS {
                    let count = payload / std::mem::size_of::<libc::c_int>();
                    for i in 0..count {
                        let fd = std::ptr::read_unaligned((data as *const libc::c_int).add(i));
                        libc::close(fd);
                    }
                }
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
    }
    Ok((n as usize, credentials))
}
