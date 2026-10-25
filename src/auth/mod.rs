//! Authentication primitives used by the proxy on both sides of the connection:
//! MD5 challenge/response and SCRAM-SHA-256 (RFC 5802 / RFC 7677).

pub mod md5;
pub mod scram;

pub use md5::{md5_hex, md5_password_response, verify_md5_response};
pub use scram::{normalize_password, ScramClient, ScramServer};
