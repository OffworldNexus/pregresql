//! The startup phase of the protocol: `StartupMessage`, `SSLRequest`,
//! `GSSENCRequest` and `CancelRequest`.

use bytes::{BufMut, Bytes, BytesMut};

use crate::error::{Error, Result};
use crate::protocol::codec::{
    Reader, CANCEL_REQUEST_CODE, GSSENC_REQUEST_CODE, PROTOCOL_VERSION_3_0, SSL_REQUEST_CODE,
};

/// One of the four untagged packets a frontend may send before the regular
/// message stream begins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartupPacket {
    /// A normal `StartupMessage`.
    Startup(StartupParams),
    /// The frontend wants to negotiate TLS (`SSLRequest`).
    SslRequest,
    /// The frontend wants to negotiate GSSAPI encryption (`GSSENCRequest`).
    GssEncRequest,
    /// The frontend wants to cancel a query running on another connection.
    CancelRequest {
        /// PID given to the frontend in the `BackendKeyData` of the target session.
        pid: i32,
        /// Secret key given to the frontend in the `BackendKeyData` of the target session.
        secret: i32,
    },
}

impl StartupPacket {
    /// Decode a startup-phase packet body (everything after the length word).
    pub fn parse(body: &[u8]) -> Result<Self> {
        let mut r = Reader::new(body);
        let code = r.i32()?;
        match code {
            SSL_REQUEST_CODE => Ok(StartupPacket::SslRequest),
            GSSENC_REQUEST_CODE => Ok(StartupPacket::GssEncRequest),
            CANCEL_REQUEST_CODE => {
                let pid = r.i32()?;
                let secret = r.i32()?;
                Ok(StartupPacket::CancelRequest { pid, secret })
            }
            version => {
                if (version >> 16) != 3 {
                    return Err(Error::protocol(format!(
                        "unsupported protocol version {}.{} (this proxy implements 3.0)",
                        version >> 16,
                        version & 0xffff
                    )));
                }
                let mut params = Vec::new();
                // Pairs of NUL-terminated strings, terminated by an empty name.
                loop {
                    if r.is_empty() {
                        break;
                    }
                    let name = r.cstr()?;
                    if name.is_empty() {
                        break;
                    }
                    if r.is_empty() {
                        return Err(Error::protocol(
                            "startup packet ends in the middle of a name/value pair",
                        ));
                    }
                    let value = r.cstr()?;
                    params.push((name.to_string(), value.to_string()));
                }
                Ok(StartupPacket::Startup(StartupParams { version, params }))
            }
        }
    }
}

/// A decoded `StartupMessage`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartupParams {
    /// The raw protocol version word (major in the high 16 bits).
    pub version: i32,
    /// The name/value pairs, in the order they appeared on the wire.
    pub params: Vec<(String, String)>,
}

impl StartupParams {
    /// Build a startup message from a parameter list, forcing protocol 3.0.
    pub fn new(params: Vec<(String, String)>) -> Self {
        Self {
            version: PROTOCOL_VERSION_3_0,
            params,
        }
    }

    /// Major protocol version.
    pub fn major_version(&self) -> i32 {
        (self.version >> 16) & 0xffff
    }

    /// Minor protocol version.
    pub fn minor_version(&self) -> i32 {
        self.version & 0xffff
    }

    /// Look up a parameter by name.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.params
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    /// Set (or append) a parameter.
    pub fn set(&mut self, name: &str, value: impl Into<String>) {
        let value = value.into();
        match self.params.iter_mut().find(|(k, _)| k == name) {
            Some(slot) => slot.1 = value,
            None => self.params.push((name.to_string(), value)),
        }
    }

    /// Remove a parameter.
    pub fn remove(&mut self, name: &str) {
        self.params.retain(|(k, _)| k != name);
    }

    /// The `user` parameter (required by the protocol).
    pub fn user(&self) -> Option<&str> {
        self.get("user")
    }

    /// The `database` parameter.
    pub fn database(&self) -> Option<&str> {
        self.get("database")
    }

    /// The `replication` parameter.
    pub fn replication(&self) -> Option<&str> {
        self.get("replication")
    }

    /// True when the frontend asked for a replication (walsender) session.
    pub fn is_replication(&self) -> bool {
        !matches!(
            self.replication(),
            None | Some("false") | Some("0") | Some("")
        )
    }

    /// Protocol options (names beginning with `_pq_.`) that this proxy does not
    /// understand. PostgreSQL reports these in `NegotiateProtocolVersion`.
    pub fn unrecognized_options(&self) -> Vec<&str> {
        self.params
            .iter()
            .filter(|(k, _)| k.starts_with("_pq_."))
            .map(|(k, _)| k.as_str())
            .collect()
    }

    /// Serialize the packet, including the leading length word.
    pub fn to_bytes(&self) -> Bytes {
        let mut body = BytesMut::new();
        body.put_i32(self.version);
        for (k, v) in &self.params {
            body.put_slice(k.as_bytes());
            body.put_u8(0);
            body.put_slice(v.as_bytes());
            body.put_u8(0);
        }
        body.put_u8(0); // terminator

        let mut out = BytesMut::with_capacity(body.len() + 4);
        out.put_i32((body.len() + 4) as i32);
        out.put_slice(&body);
        out.freeze()
    }
}

/// The eight bytes of an `SSLRequest` packet.
pub fn ssl_request_bytes() -> Bytes {
    let mut out = BytesMut::with_capacity(8);
    out.put_i32(8);
    out.put_i32(SSL_REQUEST_CODE);
    out.freeze()
}

/// The eight bytes of a `GSSENCRequest` packet.
pub fn gssenc_request_bytes() -> Bytes {
    let mut out = BytesMut::with_capacity(8);
    out.put_i32(8);
    out.put_i32(GSSENC_REQUEST_CODE);
    out.freeze()
}

/// The sixteen bytes of a `CancelRequest` packet.
pub fn cancel_request_bytes(pid: i32, secret: i32) -> Bytes {
    let mut out = BytesMut::with_capacity(16);
    out.put_i32(16);
    out.put_i32(CANCEL_REQUEST_CODE);
    out.put_i32(pid);
    out.put_i32(secret);
    out.freeze()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_roundtrip() {
        let params = StartupParams::new(vec![
            ("user".into(), "alice".into()),
            ("database".into(), "app".into()),
            ("application_name".into(), "psql".into()),
        ]);
        let bytes = params.to_bytes();
        // 4 (len) + 4 (version) + payload + 1 (terminator)
        let mut buf = BytesMut::from(&bytes[..]);
        let decoded = crate::protocol::codec::decode_startup_packet(&mut buf)
            .unwrap()
            .unwrap();
        assert_eq!(decoded, StartupPacket::Startup(params));
        assert!(buf.is_empty());
    }

    #[test]
    fn ssl_request_is_recognised() {
        let bytes = ssl_request_bytes();
        let mut buf = BytesMut::from(&bytes[..]);
        let decoded = crate::protocol::codec::decode_startup_packet(&mut buf)
            .unwrap()
            .unwrap();
        assert_eq!(decoded, StartupPacket::SslRequest);
    }

    #[test]
    fn cancel_request_is_recognised() {
        let bytes = cancel_request_bytes(42, 0xdead_beef_u32 as i32);
        let mut buf = BytesMut::from(&bytes[..]);
        let decoded = crate::protocol::codec::decode_startup_packet(&mut buf)
            .unwrap()
            .unwrap();
        assert_eq!(
            decoded,
            StartupPacket::CancelRequest {
                pid: 42,
                secret: 0xdead_beef_u32 as i32
            }
        );
    }

    #[test]
    fn replication_flag() {
        let mut p = StartupParams::new(vec![("user".into(), "r".into())]);
        assert!(!p.is_replication());
        p.set("replication", "database");
        assert!(p.is_replication());
        p.set("replication", "false");
        assert!(!p.is_replication());
    }

    #[test]
    fn version_2_is_rejected() {
        let mut body = BytesMut::new();
        body.put_i32(131_072); // protocol 2.0
        assert!(StartupPacket::parse(&body).is_err());
    }
}
