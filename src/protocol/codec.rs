//! Message framing and primitive encoding helpers.

use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::error::{Error, Result};
use crate::protocol::startup::StartupPacket;

/// Protocol version 3.0, as found in the `StartupMessage`.
pub const PROTOCOL_VERSION_3_0: i32 = 196_608;

/// Magic code sent by a frontend that wants to negotiate TLS.
pub const SSL_REQUEST_CODE: i32 = 80_877_103;
/// Magic code sent by a frontend that wants to negotiate GSSAPI encryption.
pub const GSSENC_REQUEST_CODE: i32 = 80_877_104;
/// Magic code sent by a frontend that wants to cancel a running query.
pub const CANCEL_REQUEST_CODE: i32 = 80_877_102;

/// `MAX_STARTUP_PACKET_LENGTH` from `src/include/libpq/pqcomm.h`.
pub const MAX_STARTUP_PACKET_LENGTH: usize = 10_000;
/// Upper bound we accept for a regular protocol message. PostgreSQL itself
/// allows up to 1 GiB for `CopyData`/`DataRow`.
pub const MAX_MESSAGE_LENGTH: usize = 1 << 30;

/// One already-framed protocol message: the type byte plus its body (that is,
/// everything after the length word, not including the type byte).
///
/// The body is a reference-counted [`Bytes`] slice of the read buffer so that
/// untouched messages can be forwarded without a copy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// The message type tag (e.g. `b'Q'`, `b'R'`).
    pub tag: u8,
    /// The message payload, excluding the tag and the length word.
    pub body: Bytes,
}

impl Frame {
    /// Build a frame from a tag and a payload.
    pub fn new(tag: u8, body: impl Into<Bytes>) -> Self {
        Self {
            tag,
            body: body.into(),
        }
    }

    /// Serialize the frame into a freshly allocated buffer.
    pub fn encode(&self) -> Bytes {
        encode_frame(self.tag, &self.body)
    }

    /// Total on-the-wire size of the frame.
    pub fn encoded_len(&self) -> usize {
        1 + 4 + self.body.len()
    }

    /// A cursor over the frame body.
    pub fn reader(&self) -> Reader<'_> {
        Reader::new(&self.body)
    }
}

/// Serialize `body` as a protocol message with the given `tag`.
pub fn encode_frame(tag: u8, body: &[u8]) -> Bytes {
    let mut out = BytesMut::with_capacity(1 + 4 + body.len());
    out.put_u8(tag);
    out.put_i32((body.len() + 4) as i32);
    out.put_slice(body);
    out.freeze()
}

/// Try to pull one regular protocol message out of `buf`.
///
/// Returns `Ok(None)` when there are not yet enough bytes for a complete
/// message; the caller should read more and try again.
pub fn decode_frame(buf: &mut BytesMut, max_len: usize) -> Result<Option<Frame>> {
    if buf.len() < 5 {
        return Ok(None);
    }
    let tag = buf[0];
    let len = i32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
    if len < 4 {
        return Err(Error::protocol(format!(
            "invalid message length {len} for message type '{}'",
            printable(tag)
        )));
    }
    if len as usize > max_len {
        return Err(Error::protocol(format!(
            "message of type '{}' exceeds the configured maximum ({} > {max_len})",
            printable(tag),
            len
        )));
    }
    let total = 1 + len as usize;
    if buf.len() < total {
        return Ok(None);
    }
    buf.advance(5);
    let body = buf.split_to(len as usize - 4).freeze();
    Ok(Some(Frame { tag, body }))
}

/// Try to pull an (untagged) startup-phase packet out of `buf`.
///
/// The startup phase is the only phase in which messages do not begin with a
/// type byte: they are just a length word followed by a payload.
pub fn decode_startup_packet(buf: &mut BytesMut) -> Result<Option<StartupPacket>> {
    if buf.len() < 4 {
        return Ok(None);
    }
    let len = i32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
    if (len as usize) < 8 {
        return Err(Error::protocol(format!(
            "invalid startup packet length {len}"
        )));
    }
    if len as usize > MAX_STARTUP_PACKET_LENGTH {
        return Err(Error::protocol(format!(
            "startup packet of {len} bytes exceeds the protocol maximum of {MAX_STARTUP_PACKET_LENGTH}"
        )));
    }
    if buf.len() < len as usize {
        return Ok(None);
    }
    buf.advance(4);
    let body = buf.split_to(len as usize - 4);
    StartupPacket::parse(&body).map(Some)
}

fn printable(tag: u8) -> String {
    if tag.is_ascii_graphic() {
        (tag as char).to_string()
    } else {
        format!("\\x{tag:02x}")
    }
}

/// A borrowing cursor over a message body with checked reads.
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// Wrap a byte slice.
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Number of bytes left.
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// True when the cursor reached the end.
    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.remaining() < n {
            return Err(Error::protocol(format!(
                "message truncated: wanted {n} bytes, {} left",
                self.remaining()
            )));
        }
        let out = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    /// Read a single byte.
    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    /// Read a big-endian `int16`.
    pub fn i16(&mut self) -> Result<i16> {
        let b = self.take(2)?;
        Ok(i16::from_be_bytes([b[0], b[1]]))
    }

    /// Read a big-endian `int32`.
    pub fn i32(&mut self) -> Result<i32> {
        let b = self.take(4)?;
        Ok(i32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Read `n` raw bytes.
    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        self.take(n)
    }

    /// Read the rest of the body.
    pub fn rest(&mut self) -> &'a [u8] {
        let out = &self.buf[self.pos..];
        self.pos = self.buf.len();
        out
    }

    /// Read a NUL-terminated string as raw bytes (the NUL is consumed).
    pub fn cstr_bytes(&mut self) -> Result<&'a [u8]> {
        let rel = self.buf[self.pos..]
            .iter()
            .position(|b| *b == 0)
            .ok_or_else(|| Error::protocol("unterminated string in message"))?;
        let out = &self.buf[self.pos..self.pos + rel];
        self.pos += rel + 1;
        Ok(out)
    }

    /// Read a NUL-terminated UTF-8 string.
    pub fn cstr(&mut self) -> Result<&'a str> {
        let raw = self.cstr_bytes()?;
        std::str::from_utf8(raw).map_err(|e| Error::protocol(format!("invalid UTF-8 string: {e}")))
    }
}

/// A growable encoder for message bodies.
#[derive(Debug, Default, Clone)]
pub struct Writer {
    buf: BytesMut,
}

impl Writer {
    /// An empty writer.
    pub fn new() -> Self {
        Self {
            buf: BytesMut::new(),
        }
    }

    /// The bytes written so far.
    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }

    /// Finish and hand out the buffer.
    pub fn into_bytes(self) -> Bytes {
        self.buf.freeze()
    }

    /// Write a single byte.
    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.buf.put_u8(v);
        self
    }

    /// Write a big-endian `int16`.
    pub fn i16(&mut self, v: i16) -> &mut Self {
        self.buf.put_i16(v);
        self
    }

    /// Write a big-endian `int32`.
    pub fn i32(&mut self, v: i32) -> &mut Self {
        self.buf.put_i32(v);
        self
    }

    /// Write raw bytes.
    pub fn bytes(&mut self, v: &[u8]) -> &mut Self {
        self.buf.put_slice(v);
        self
    }

    /// Write a NUL-terminated string.
    pub fn cstr(&mut self, v: &str) -> &mut Self {
        self.buf.put_slice(v.as_bytes());
        self.buf.put_u8(0);
        self
    }

    /// Frame the accumulated body with `tag`.
    pub fn finish(self, tag: u8) -> Frame {
        Frame::new(tag, self.buf.freeze())
    }

    /// Frame the accumulated body with `tag` and serialize it.
    pub fn finish_encoded(self, tag: u8) -> Bytes {
        encode_frame(tag, &self.buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrip() {
        let encoded = encode_frame(b'Q', b"SELECT 1");
        let mut buf = BytesMut::from(&encoded[..]);
        let frame = decode_frame(&mut buf, MAX_MESSAGE_LENGTH)
            .unwrap()
            .expect("complete frame");
        assert_eq!(frame.tag, b'Q');
        assert_eq!(&frame.body[..], b"SELECT 1");
        assert!(buf.is_empty());
        assert_eq!(frame.encode(), encoded);
    }

    #[test]
    fn frame_needs_more_bytes() {
        let encoded = encode_frame(b'Q', b"SELECT 1");
        for cut in 1..encoded.len() {
            let mut buf = BytesMut::from(&encoded[..cut]);
            assert!(
                decode_frame(&mut buf, MAX_MESSAGE_LENGTH)
                    .unwrap()
                    .is_none(),
                "prefix of length {cut} should be incomplete"
            );
        }
    }

    #[test]
    fn rejects_bogus_length() {
        let mut buf = BytesMut::from(&[b'Q', 0, 0, 0, 1][..]);
        assert!(decode_frame(&mut buf, MAX_MESSAGE_LENGTH).is_err());
    }

    #[test]
    fn reader_basics() {
        let mut w = Writer::new();
        w.u8(1).i16(2).i32(3).cstr("hi").bytes(b"xy");
        let raw = w.into_bytes();
        let mut r = Reader::new(&raw);
        assert_eq!(r.u8().unwrap(), 1);
        assert_eq!(r.i16().unwrap(), 2);
        assert_eq!(r.i32().unwrap(), 3);
        assert_eq!(r.cstr().unwrap(), "hi");
        assert_eq!(r.bytes(2).unwrap(), b"xy");
        assert!(r.is_empty());
    }

    #[test]
    fn reader_detects_truncation() {
        let mut r = Reader::new(b"ab");
        assert!(r.i32().is_err());
    }
}
