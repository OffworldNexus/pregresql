//! Typed decoders and encoders for the protocol messages the proxy cares about.
//!
//! Every other message is relayed untouched, so this module only covers the
//! messages whose contents influence proxying decisions (query lifecycle,
//! authentication, session setup) plus the ones the proxy itself synthesizes
//! (`ErrorResponse`, `ReadyForQuery`, `ParameterStatus`, `BackendKeyData`, ...).

use bytes::{Bytes, BytesMut};

use crate::error::{Error, Result};
use crate::protocol::codec::{Frame, Reader, Writer};

// ---------------------------------------------------------------------------
// Frontend messages
// ---------------------------------------------------------------------------

/// `Query` ('Q') — a simple-protocol query string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryMessage {
    /// The SQL text (possibly several statements separated by semicolons).
    pub sql: String,
}

impl QueryMessage {
    /// Decode a `Query` body.
    pub fn parse(body: &[u8]) -> Result<Self> {
        let mut r = Reader::new(body);
        let sql = r.cstr()?;
        Ok(Self {
            sql: sql.to_string(),
        })
    }

    /// Encode into a body.
    pub fn encode_body(&self) -> Bytes {
        let mut w = Writer::new();
        w.cstr(&self.sql);
        w.into_bytes()
    }

    /// Encode into a complete frame.
    pub fn to_frame(&self) -> Frame {
        Frame::new(b'Q', self.encode_body())
    }
}

/// `Parse` ('P') — prepares a statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseMessage {
    /// Destination prepared-statement name (empty means the unnamed statement).
    pub name: String,
    /// The SQL text. The protocol forbids multiple statements here.
    pub sql: String,
    /// Prespecified parameter type OIDs (may be empty or shorter than the
    /// number of placeholders).
    pub param_types: Vec<i32>,
}

impl ParseMessage {
    /// Decode a `Parse` body.
    pub fn parse(body: &[u8]) -> Result<Self> {
        let mut r = Reader::new(body);
        let name = r.cstr()?.to_string();
        let sql = r.cstr()?.to_string();
        let n = r.i16()?;
        if n < 0 {
            return Err(Error::protocol("negative parameter type count"));
        }
        let mut param_types = Vec::with_capacity(n as usize);
        for _ in 0..n {
            param_types.push(r.i32()?);
        }
        Ok(Self {
            name,
            sql,
            param_types,
        })
    }

    /// Encode into a body.
    pub fn encode_body(&self) -> Bytes {
        let mut w = Writer::new();
        w.cstr(&self.name)
            .cstr(&self.sql)
            .i16(self.param_types.len() as i16);
        for oid in &self.param_types {
            w.i32(*oid);
        }
        w.into_bytes()
    }

    /// Encode into a complete frame.
    pub fn to_frame(&self) -> Frame {
        Frame::new(b'P', self.encode_body())
    }
}

/// `Bind` ('B') — binds parameters into a portal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindMessage {
    /// Destination portal (empty means the unnamed portal).
    pub portal: String,
    /// Source prepared statement (empty means the unnamed statement).
    pub statement: String,
    /// Parameter format codes (0 = text, 1 = binary).
    pub param_formats: Vec<i16>,
    /// Parameter values; `None` represents SQL `NULL`.
    pub params: Vec<Option<Bytes>>,
    /// Result-column format codes.
    pub result_formats: Vec<i16>,
}

impl BindMessage {
    /// Decode a `Bind` body.
    pub fn parse(body: &[u8]) -> Result<Self> {
        let mut r = Reader::new(body);
        let portal = r.cstr()?.to_string();
        let statement = r.cstr()?.to_string();

        let nformats = r.i16()?;
        if nformats < 0 {
            return Err(Error::protocol("negative parameter format count"));
        }
        let mut param_formats = Vec::with_capacity(nformats as usize);
        for _ in 0..nformats {
            param_formats.push(r.i16()?);
        }

        let nparams = r.i16()?;
        if nparams < 0 {
            return Err(Error::protocol("negative parameter count"));
        }
        let mut params = Vec::with_capacity(nparams as usize);
        for _ in 0..nparams {
            let len = r.i32()?;
            if len == -1 {
                params.push(None);
            } else if len < 0 {
                return Err(Error::protocol("invalid parameter length"));
            } else {
                params.push(Some(Bytes::copy_from_slice(r.bytes(len as usize)?)));
            }
        }

        let nresults = r.i16()?;
        if nresults < 0 {
            return Err(Error::protocol("negative result format count"));
        }
        let mut result_formats = Vec::with_capacity(nresults as usize);
        for _ in 0..nresults {
            result_formats.push(r.i16()?);
        }

        Ok(Self {
            portal,
            statement,
            param_formats,
            params,
            result_formats,
        })
    }
}

/// `Describe` ('D') — asks for a statement or portal description.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DescribeMessage {
    /// `b'S'` for a prepared statement, `b'P'` for a portal.
    pub kind: u8,
    /// Name of the object (empty for the unnamed one).
    pub name: String,
}

impl DescribeMessage {
    /// Decode a `Describe` body.
    pub fn parse(body: &[u8]) -> Result<Self> {
        let mut r = Reader::new(body);
        let kind = r.u8()?;
        let name = r.cstr()?.to_string();
        Ok(Self { kind, name })
    }
}

/// `Execute` ('E') — runs a portal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecuteMessage {
    /// Portal to execute (empty for the unnamed portal).
    pub portal: String,
    /// Maximum number of rows to return; 0 means "no limit".
    pub max_rows: i32,
}

impl ExecuteMessage {
    /// Decode an `Execute` body.
    pub fn parse(body: &[u8]) -> Result<Self> {
        let mut r = Reader::new(body);
        let portal = r.cstr()?.to_string();
        let max_rows = r.i32()?;
        Ok(Self { portal, max_rows })
    }
}

/// `Close` ('C') — drops a statement or portal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloseMessage {
    /// `b'S'` for a prepared statement, `b'P'` for a portal.
    pub kind: u8,
    /// Name of the object (empty for the unnamed one).
    pub name: String,
}

impl CloseMessage {
    /// Decode a `Close` body.
    pub fn parse(body: &[u8]) -> Result<Self> {
        let mut r = Reader::new(body);
        let kind = r.u8()?;
        let name = r.cstr()?.to_string();
        Ok(Self { kind, name })
    }
}

/// `PasswordMessage` / `SASLInitialResponse` / `SASLResponse` / `GSSResponse`
/// — all of which share the `'p'` tag and are distinguished by context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PasswordResponse {
    /// A cleartext password or an MD5 response.
    Password(String),
    /// The first SASL message, naming the mechanism.
    SaslInitial {
        /// The selected SASL mechanism.
        mechanism: String,
        /// The mechanism-specific initial response (`None` when the client sent -1).
        data: Option<Bytes>,
    },
    /// A subsequent SASL message.
    Sasl(Bytes),
    /// GSSAPI/SSPI data (unsupported, but recognised).
    Gss(Bytes),
}

impl PasswordResponse {
    /// Decode an `'p'` body as a cleartext/MD5 password message.
    pub fn parse_password(body: &[u8]) -> Result<String> {
        let mut r = Reader::new(body);
        Ok(r.cstr()?.to_string())
    }

    /// Decode an `'p'` body as `SASLInitialResponse`.
    pub fn parse_sasl_initial(body: &[u8]) -> Result<Self> {
        let mut r = Reader::new(body);
        let mechanism = r.cstr()?.to_string();
        let len = r.i32()?;
        let data = if len < 0 {
            None
        } else {
            Some(Bytes::copy_from_slice(r.bytes(len as usize)?))
        };
        Ok(PasswordResponse::SaslInitial { mechanism, data })
    }

    /// Encode a cleartext password response.
    pub fn password_frame(password: &str) -> Frame {
        let mut w = Writer::new();
        w.cstr(password);
        Frame::new(b'p', w.into_bytes())
    }

    /// Encode a `SASLInitialResponse`.
    pub fn sasl_initial_frame(mechanism: &str, data: &[u8]) -> Frame {
        let mut w = Writer::new();
        w.cstr(mechanism).i32(data.len() as i32).bytes(data);
        Frame::new(b'p', w.into_bytes())
    }

    /// Encode a `SASLResponse`.
    pub fn sasl_response_frame(data: &[u8]) -> Frame {
        Frame::new(b'p', Bytes::copy_from_slice(data))
    }
}

// ---------------------------------------------------------------------------
// Backend messages
// ---------------------------------------------------------------------------

/// The variants of the `Authentication` ('R') message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Authentication {
    /// Authentication succeeded.
    Ok,
    /// Kerberos V5 (unsupported).
    KerberosV5,
    /// A cleartext password is requested.
    CleartextPassword,
    /// An MD5 challenge with the given four-byte salt.
    Md5Password([u8; 4]),
    /// SCM credential (unsupported).
    ScmCredential,
    /// GSSAPI (unsupported).
    Gss,
    /// A GSSAPI/SSPI continuation.
    GssContinue(Bytes),
    /// SSPI (unsupported).
    Sspi,
    /// SASL: the offered mechanisms, in server preference order.
    Sasl(Vec<String>),
    /// A SASL challenge.
    SaslContinue(Bytes),
    /// The final SASL message from the server.
    SaslFinal(Bytes),
    /// An authentication method this proxy does not know.
    Unknown(i32),
}

impl Authentication {
    /// Decode an `'R'` body.
    pub fn parse(body: &[u8]) -> Result<Self> {
        let mut r = Reader::new(body);
        let code = r.i32()?;
        Ok(match code {
            0 => Authentication::Ok,
            2 => Authentication::KerberosV5,
            3 => Authentication::CleartextPassword,
            5 => {
                let b = r.bytes(4)?;
                Authentication::Md5Password([b[0], b[1], b[2], b[3]])
            }
            6 => Authentication::ScmCredential,
            7 => Authentication::Gss,
            8 => Authentication::GssContinue(Bytes::copy_from_slice(r.rest())),
            9 => Authentication::Sspi,
            10 => {
                let mut mechanisms = Vec::new();
                loop {
                    if r.is_empty() {
                        break;
                    }
                    let m = r.cstr()?;
                    if m.is_empty() {
                        break;
                    }
                    mechanisms.push(m.to_string());
                }
                Authentication::Sasl(mechanisms)
            }
            11 => Authentication::SaslContinue(Bytes::copy_from_slice(r.rest())),
            12 => Authentication::SaslFinal(Bytes::copy_from_slice(r.rest())),
            other => Authentication::Unknown(other),
        })
    }

    /// Encode into a body.
    pub fn encode_body(&self) -> Bytes {
        let mut w = Writer::new();
        match self {
            Authentication::Ok => {
                w.i32(0);
            }
            Authentication::KerberosV5 => {
                w.i32(2);
            }
            Authentication::CleartextPassword => {
                w.i32(3);
            }
            Authentication::Md5Password(salt) => {
                w.i32(5).bytes(salt);
            }
            Authentication::ScmCredential => {
                w.i32(6);
            }
            Authentication::Gss => {
                w.i32(7);
            }
            Authentication::GssContinue(d) => {
                w.i32(8).bytes(d);
            }
            Authentication::Sspi => {
                w.i32(9);
            }
            Authentication::Sasl(mechs) => {
                w.i32(10);
                for m in mechs {
                    w.cstr(m);
                }
                w.u8(0);
            }
            Authentication::SaslContinue(d) => {
                w.i32(11).bytes(d);
            }
            Authentication::SaslFinal(d) => {
                w.i32(12).bytes(d);
            }
            Authentication::Unknown(code) => {
                w.i32(*code);
            }
        }
        w.into_bytes()
    }

    /// Encode into a complete frame.
    pub fn to_frame(&self) -> Frame {
        Frame::new(b'R', self.encode_body())
    }
}

/// `BackendKeyData` ('K').
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackendKeyData {
    /// Backend process id.
    pub pid: i32,
    /// Secret key used for cancellation.
    pub secret: i32,
}

impl BackendKeyData {
    /// Decode a `'K'` body.
    pub fn parse(body: &[u8]) -> Result<Self> {
        let mut r = Reader::new(body);
        Ok(Self {
            pid: r.i32()?,
            secret: r.i32()?,
        })
    }

    /// Encode into a complete frame.
    pub fn to_frame(self) -> Frame {
        let mut w = Writer::new();
        w.i32(self.pid).i32(self.secret);
        Frame::new(b'K', w.into_bytes())
    }
}

/// `ParameterStatus` ('S').
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParameterStatus {
    /// Parameter name.
    pub name: String,
    /// Parameter value.
    pub value: String,
}

impl ParameterStatus {
    /// Decode an `'S'` body.
    pub fn parse(body: &[u8]) -> Result<Self> {
        let mut r = Reader::new(body);
        Ok(Self {
            name: r.cstr()?.to_string(),
            value: r.cstr()?.to_string(),
        })
    }

    /// Encode into a complete frame.
    pub fn to_frame(&self) -> Frame {
        let mut w = Writer::new();
        w.cstr(&self.name).cstr(&self.value);
        Frame::new(b'S', w.into_bytes())
    }
}

/// `NegotiateProtocolVersion` ('v').
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiateProtocolVersion {
    /// Newest minor protocol version the server supports.
    pub newest_minor: i32,
    /// Protocol options the server did not recognise.
    pub unrecognized_options: Vec<String>,
}

impl NegotiateProtocolVersion {
    /// Decode a `'v'` body.
    pub fn parse(body: &[u8]) -> Result<Self> {
        let mut r = Reader::new(body);
        let newest_minor = r.i32()?;
        let count = r.i32()?;
        let mut unrecognized_options = Vec::new();
        for _ in 0..count.max(0) {
            unrecognized_options.push(r.cstr()?.to_string());
        }
        Ok(Self {
            newest_minor,
            unrecognized_options,
        })
    }

    /// Encode into a complete frame.
    pub fn to_frame(&self) -> Frame {
        let mut w = Writer::new();
        w.i32(self.newest_minor)
            .i32(self.unrecognized_options.len() as i32);
        for o in &self.unrecognized_options {
            w.cstr(o);
        }
        Frame::new(b'v', w.into_bytes())
    }
}

/// The transaction-status byte carried by `ReadyForQuery`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TransactionStatus {
    /// Not in a transaction block.
    #[default]
    Idle,
    /// Inside a transaction block.
    InTransaction,
    /// Inside a failed transaction block.
    Failed,
}

impl TransactionStatus {
    /// Decode the single status byte.
    pub fn from_byte(b: u8) -> Self {
        match b {
            b'T' => TransactionStatus::InTransaction,
            b'E' => TransactionStatus::Failed,
            _ => TransactionStatus::Idle,
        }
    }

    /// The byte used on the wire.
    pub fn to_byte(self) -> u8 {
        match self {
            TransactionStatus::Idle => b'I',
            TransactionStatus::InTransaction => b'T',
            TransactionStatus::Failed => b'E',
        }
    }
}

/// Decode the status byte of a `ReadyForQuery` body.
pub fn parse_ready_for_query(body: &[u8]) -> Result<TransactionStatus> {
    let mut r = Reader::new(body);
    Ok(TransactionStatus::from_byte(r.u8()?))
}

/// Serialize a `ReadyForQuery` frame.
pub fn ready_for_query(status: TransactionStatus) -> Frame {
    Frame::new(b'Z', Bytes::from(vec![status.to_byte()]))
}

/// `RowDescription`, as needed by tests and tooling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldDescription {
    /// Column name.
    pub name: String,
    /// Source table OID (0 when not a table column).
    pub table_oid: i32,
    /// Source column attribute number (0 when not a table column).
    pub column_id: i16,
    /// Data type OID.
    pub type_oid: i32,
    /// Type size (`typlen`).
    pub type_size: i16,
    /// Type modifier (`atttypmod`).
    pub type_modifier: i32,
    /// Format code (0 text, 1 binary).
    pub format: i16,
}

// ---------------------------------------------------------------------------
// Error and notice messages
// ---------------------------------------------------------------------------

/// The identified fields of an `ErrorResponse`/`NoticeResponse`.
///
/// Field codes are documented in section 55.8 of the PostgreSQL manual. The
/// order of fields is preserved so that responses produced by the upstream
/// server can be forwarded byte-for-byte.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ErrorFields {
    /// The `(field code, value)` pairs, in wire order.
    pub fields: Vec<(u8, String)>,
}

impl ErrorFields {
    /// Build the minimal well-formed field set: `S`, `V`, `C` and `M`.
    pub fn new(severity: &str, code: &str, message: &str) -> Self {
        Self {
            fields: vec![
                (b'S', severity.to_string()),
                (b'V', severity.to_string()),
                (b'C', code.to_string()),
                (b'M', message.to_string()),
            ],
        }
    }

    /// Add or replace a field.
    pub fn push(&mut self, code: u8, value: impl Into<String>) -> &mut Self {
        self.fields.retain(|(c, _)| *c != code);
        self.fields.push((code, value.into()));
        self
    }

    /// Get a field by code.
    pub fn get(&self, code: u8) -> Option<&str> {
        self.fields
            .iter()
            .find(|(c, _)| *c == code)
            .map(|(_, v)| v.as_str())
    }

    /// The severity (`S`).
    pub fn severity(&self) -> Option<&str> {
        self.get(b'S')
    }

    /// The SQLSTATE code (`C`).
    pub fn code(&self) -> Option<&str> {
        self.get(b'C')
    }

    /// The human-readable message (`M`).
    pub fn message(&self) -> Option<&str> {
        self.get(b'M')
    }

    /// Decode the body of an `ErrorResponse`/`NoticeResponse`.
    pub fn parse(body: &[u8]) -> Result<Self> {
        let mut r = Reader::new(body);
        let mut fields = Vec::new();
        loop {
            let code = r.u8()?;
            if code == 0 {
                break;
            }
            fields.push((code, r.cstr()?.to_string()));
        }
        Ok(Self { fields })
    }

    /// Encode into a complete frame with the given tag (`b'E'` or `b'N'`).
    pub fn to_frame_with_tag(&self, tag: u8) -> Frame {
        let mut w = Writer::new();
        for (code, value) in &self.fields {
            w.u8(*code).cstr(value);
        }
        w.u8(0);
        Frame::new(tag, w.into_bytes())
    }

    /// Encode as an `ErrorResponse`.
    pub fn to_error_frame(&self) -> Frame {
        self.to_frame_with_tag(b'E')
    }

    /// Encode as a `NoticeResponse`.
    pub fn to_notice_frame(&self) -> Frame {
        self.to_frame_with_tag(b'N')
    }
}

/// Build an `ErrorResponse` with severity `ERROR`.
pub fn error_response(code: &str, message: impl Into<String>) -> Frame {
    ErrorFields::new("ERROR", code, &message.into()).to_error_frame()
}

/// Build an `ErrorResponse` with severity `FATAL`, used to abort a startup.
pub fn fatal_response(code: &str, message: impl Into<String>) -> Frame {
    ErrorFields::new("FATAL", code, &message.into()).to_error_frame()
}

/// Build an `ErrorResponse` with severity `FATAL` and a `detail` field.
pub fn fatal_response_with_detail(code: &str, message: impl Into<String>, detail: &str) -> Frame {
    let mut fields = ErrorFields::new("FATAL", code, &message.into());
    fields.push(b'D', detail);
    fields.to_error_frame()
}

/// Serialize a `CommandComplete` frame (used by tests and tooling).
pub fn command_complete(tag: &str) -> Frame {
    let mut w = Writer::new();
    w.cstr(tag);
    Frame::new(b'C', w.into_bytes())
}

/// Serialize an `EmptyQueryResponse`.
pub fn empty_query_response() -> Frame {
    Frame::new(b'I', BytesMut::new().freeze())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_query_roundtrip() {
        let q = QueryMessage {
            sql: "SELECT 1".into(),
        };
        let frame = q.to_frame();
        assert_eq!(QueryMessage::parse(&frame.body).unwrap(), q);

        let p = ParseMessage {
            name: "s1".into(),
            sql: "SELECT $1".into(),
            param_types: vec![23],
        };
        let frame = p.to_frame();
        assert_eq!(ParseMessage::parse(&frame.body).unwrap(), p);
    }

    #[test]
    fn bind_roundtrip_with_nulls() {
        let body_of = |msg: &BindMessage| -> Bytes {
            let mut w = Writer::new();
            w.cstr(&msg.portal).cstr(&msg.statement);
            w.i16(msg.param_formats.len() as i16);
            for f in &msg.param_formats {
                w.i16(*f);
            }
            w.i16(msg.params.len() as i16);
            for p in &msg.params {
                match p {
                    None => {
                        w.i32(-1);
                    }
                    Some(b) => {
                        w.i32(b.len() as i32).bytes(b);
                    }
                }
            }
            w.i16(msg.result_formats.len() as i16);
            for f in &msg.result_formats {
                w.i16(*f);
            }
            w.into_bytes()
        };
        let msg = BindMessage {
            portal: "p".into(),
            statement: "s".into(),
            param_formats: vec![0, 1],
            params: vec![Some(Bytes::from_static(b"abc")), None],
            result_formats: vec![0],
        };
        let body = body_of(&msg);
        assert_eq!(BindMessage::parse(&body).unwrap(), msg);
    }

    #[test]
    fn authentication_roundtrip() {
        for auth in [
            Authentication::Ok,
            Authentication::CleartextPassword,
            Authentication::Md5Password([1, 2, 3, 4]),
            Authentication::Sasl(vec!["SCRAM-SHA-256".into()]),
            Authentication::SaslContinue(Bytes::from_static(b"r=abc,s=xyz,i=4096")),
            Authentication::SaslFinal(Bytes::from_static(b"v=signature")),
        ] {
            let frame = auth.to_frame();
            assert_eq!(Authentication::parse(&frame.body).unwrap(), auth);
        }
    }

    #[test]
    fn error_fields_roundtrip() {
        let mut f = ErrorFields::new("ERROR", "42501", "denied");
        f.push(b'D', "the detail");
        let frame = f.to_error_frame();
        let decoded = ErrorFields::parse(&frame.body).unwrap();
        assert_eq!(decoded.severity(), Some("ERROR"));
        assert_eq!(decoded.code(), Some("42501"));
        assert_eq!(decoded.message(), Some("denied"));
        assert_eq!(decoded.get(b'D'), Some("the detail"));
    }

    #[test]
    fn ready_for_query_status() {
        assert_eq!(
            parse_ready_for_query(&ready_for_query(TransactionStatus::Failed).body).unwrap(),
            TransactionStatus::Failed
        );
    }

    #[test]
    fn negotiate_version_roundtrip() {
        let n = NegotiateProtocolVersion {
            newest_minor: 0,
            unrecognized_options: vec!["_pq_.foo".into()],
        };
        let frame = n.to_frame();
        assert_eq!(NegotiateProtocolVersion::parse(&frame.body).unwrap(), n);
    }
}
