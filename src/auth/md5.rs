//! PostgreSQL's MD5 password authentication.
//!
//! The on-the-wire response is
//!
//! ```text
//! "md5" || md5hex( md5hex(password || user) || salt )
//! ```
//!
//! Note that `md5()` in PostgreSQL is applied to the *hex string* produced by
//! the inner hash, not to the raw digest.

use md5::{Digest, Md5};

/// Lowercase hex encoding of `MD5(parts…)`.
pub fn md5_hex(parts: &[&[u8]]) -> String {
    let mut hasher = Md5::new();
    for part in parts {
        hasher.update(part);
    }
    hex::encode(hasher.finalize())
}

/// Compute the response a client must send for `user`/`password` given `salt`.
pub fn md5_password_response(user: &str, password: &str, salt: &[u8; 4]) -> String {
    let inner = md5_hex(&[password.as_bytes(), user.as_bytes()]);
    format!("md5{}", md5_hex(&[inner.as_bytes(), salt.as_slice()]))
}

/// Check a client-supplied MD5 response against the expected password.
///
/// The comparison is constant time with respect to the response contents.
pub fn verify_md5_response(user: &str, password: &str, salt: &[u8; 4], response: &str) -> bool {
    let expected = md5_password_response(user, password, salt);
    constant_time_eq(expected.as_bytes(), response.as_bytes())
}

/// Compare two byte strings without an early exit.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Cross-checked against PostgreSQL:
    /// `SELECT 'md5' || md5(md5('secret' || 'alice') || 'salt');`
    /// is not directly reproducible here because the salt is arbitrary, so we
    /// recompute the documented composition instead.
    #[test]
    fn composition_matches_documented_formula() {
        let salt = [0x01u8, 0x02, 0x03, 0x04];
        let inner = md5_hex(&[b"secret", b"alice"]);
        assert_eq!(
            md5_password_response("alice", "secret", &salt),
            format!(
                "md5{}",
                md5_hex(&[inner.as_bytes(), &[0x01, 0x02, 0x03, 0x04]])
            )
        );
    }

    #[test]
    fn md5_known_vector() {
        // RFC 1321 test vector.
        assert_eq!(md5_hex(&[b"abc"]), "900150983cd24fb0d6963f7d28e17f72");
    }

    #[test]
    fn verification() {
        let salt = [9u8, 8, 7, 6];
        let response = md5_password_response("bob", "hunter2", &salt);
        assert!(verify_md5_response("bob", "hunter2", &salt, &response));
        assert!(!verify_md5_response("bob", "hunter3", &salt, &response));
        assert!(!verify_md5_response("alice", "hunter2", &salt, &response));
    }
}
