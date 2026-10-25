//! A pure-Rust implementation of the PostgreSQL v3.0 frontend/backend protocol.
//!
//! The module is deliberately close to the specification
//! (<https://www.postgresql.org/docs/16/protocol.html>): every message that the
//! proxy needs to understand has an explicit decoder, and everything else is
//! relayed verbatim as an opaque [`codec::Frame`].

pub mod codec;
pub mod message;
pub mod startup;

pub use codec::{
    decode_frame, decode_startup_packet, encode_frame, Frame, Reader, Writer, CANCEL_REQUEST_CODE,
    GSSENC_REQUEST_CODE, MAX_MESSAGE_LENGTH, MAX_STARTUP_PACKET_LENGTH, PROTOCOL_VERSION_3_0,
    SSL_REQUEST_CODE,
};
pub use message::*;
pub use startup::{StartupPacket, StartupParams};
