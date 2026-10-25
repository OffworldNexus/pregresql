//! SCRAM-SHA-256 (RFC 5802 / RFC 7677) as used by PostgreSQL.
//!
//! Both directions are implemented:
//!
//! * [`ScramClient`] authenticates the proxy *to* an upstream PostgreSQL server.
//! * [`ScramServer`] authenticates an incoming client *to* the proxy. Because
//!   the proxy looks passwords up in plaintext it can build the SCRAM verifier
//!   on the fly, which lets it learn (and therefore hand to the auth hook) the
//!   identity the client proved.
//!
//! Channel binding is not advertised by this implementation, but the `y` and
//! `p=` handshake flags are parsed and validated so that a client which offers
//! channel binding gracefully falls back to `SCRAM-SHA-256`.

use std::borrow::Cow;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

type HmacSha256 = Hmac<Sha256>;

/// The mechanism name used on the wire.
pub const SCRAM_SHA_256: &str = "SCRAM-SHA-256";
/// The channel-binding variant name.
pub const SCRAM_SHA_256_PLUS: &str = "SCRAM-SHA-256-PLUS";
/// Default iteration count, matching PostgreSQL 16's `scram_iterations`.
pub const DEFAULT_ITERATIONS: u32 = 4096;

const CLIENT_KEY: &[u8] = b"Client Key";
const SERVER_KEY: &[u8] = b"Server Key";

/// Apply SASLprep to a password, falling back to the raw bytes when the
/// password is not valid UTF-8 or contains prohibited code points.
///
/// This mirrors PostgreSQL's `scram_build_secret`, which falls back to the raw
/// password instead of raising an error.
pub fn normalize_password(password: &str) -> Cow<'_, str> {
    match stringprep::saslprep(password) {
        Ok(p) => p,
        Err(_) => Cow::Borrowed(password),
    }
}

fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts keys of any length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

fn salted_password(password: &str, salt: &[u8], iterations: u32) -> [u8; 32] {
    let normalized = normalize_password(password);
    pbkdf2::pbkdf2_hmac_array::<Sha256, 32>(normalized.as_bytes(), salt, iterations)
}

fn xor(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = a[i] ^ b[i];
    }
    out
}

fn random_nonce() -> String {
    // 18 random bytes -> 24 base64 characters, comparable to libpq's nonce.
    let mut raw = [0u8; 18];
    rand::thread_rng().fill_bytes(&mut raw);
    B64.encode(raw)
}

/// Generate a fresh client nonce.
pub fn client_nonce() -> String {
    random_nonce()
}

/// Generate a fresh server nonce.
pub fn server_nonce() -> String {
    random_nonce()
}

/// The gs2 header used when no channel binding is offered.
const GS2_HEADER_NONE: &str = "n,,";

/// Split a SCRAM message into its gs2 header and the "bare" remainder.
fn split_gs2(message: &str) -> Result<(&str, &str)> {
    let first_comma = message
        .find(',')
        .ok_or_else(|| Error::auth("malformed SCRAM message: missing gs2 header"))?;
    let rest = &message[first_comma + 1..];
    let second_comma = rest
        .find(',')
        .ok_or_else(|| Error::auth("malformed SCRAM message: missing gs2 header terminator"))?;
    let split_at = first_comma + 1 + second_comma + 1;
    Ok((&message[..split_at], &message[split_at..]))
}

/// Extract a `key=value` attribute from a SCRAM message.
fn attribute(message: &str, key: char) -> Result<&str> {
    for part in message.split(',') {
        if let Some(value) = part.strip_prefix(key) {
            if let Some(value) = value.strip_prefix('=') {
                return Ok(value);
            }
        }
    }
    Err(Error::auth(format!(
        "malformed SCRAM message: missing '{key}=' attribute"
    )))
}

/// SASLprep + `saslname` escaping of a user name for the `n=` attribute.
fn encode_username(name: &str) -> String {
    let normalized = normalize_password(name);
    let mut out = String::with_capacity(normalized.len());
    for ch in normalized.chars() {
        match ch {
            ',' => out.push_str("=2C"),
            '=' => out.push_str("=3D"),
            other => out.push(other),
        }
    }
    out
}

/// A SCRAM-SHA-256 client (the proxy talking to an upstream server).
#[derive(Debug)]
pub struct ScramClient {
    client_nonce: String,
    gs2_header: String,
    client_first_bare: String,
    server_first: String,
    salted: [u8; 32],
    expected_server_signature: [u8; 32],
}

impl ScramClient {
    /// Start a non-channel-binding exchange with an empty user name, exactly
    /// like libpq (`n,,n=,r=<nonce>`): PostgreSQL ignores the SCRAM user name
    /// and uses the one from the startup packet.
    pub fn new() -> Self {
        Self::with_channel_binding(client_nonce(), None)
    }

    /// Start an exchange, optionally with `tls-server-end-point` channel binding.
    pub fn with_channel_binding(nonce: String, channel_binding: Option<&[u8]>) -> Self {
        let gs2_header = match channel_binding {
            None => GS2_HEADER_NONE.to_string(),
            Some(_) => "p=tls-server-end-point,,".to_string(),
        };
        Self::new_with_username(nonce, gs2_header, String::new())
    }

    /// Start an exchange with an explicit user name (used by the RFC test
    /// vectors; PostgreSQL itself ignores the value).
    pub fn with_username(nonce: String, username: &str) -> Self {
        Self::new_with_username(
            nonce,
            GS2_HEADER_NONE.to_string(),
            encode_username(username),
        )
    }

    fn new_with_username(nonce: String, gs2_header: String, username: String) -> Self {
        let client_first_bare = format!("n={username},r={nonce}");
        Self {
            client_nonce: nonce,
            gs2_header,
            client_first_bare,
            server_first: String::new(),
            salted: [0u8; 32],
            expected_server_signature: [0u8; 32],
        }
    }

    /// The mechanism to select from the server's list.
    pub fn mechanism(&self) -> &'static str {
        SCRAM_SHA_256
    }

    /// The full `client-first-message`.
    pub fn client_first_message(&self) -> String {
        format!("{}{}", self.gs2_header, self.client_first_bare)
    }

    /// Process the `server-first-message` and derive the keys.
    pub fn handle_server_first(&mut self, message: &str, password: &str) -> Result<()> {
        let combined_nonce = attribute(message, 'r')?;
        if !combined_nonce.starts_with(&self.client_nonce) {
            return Err(Error::auth(
                "server nonce does not extend the client nonce (possible attack)",
            ));
        }
        let salt = B64
            .decode(attribute(message, 's')?)
            .map_err(|e| Error::auth(format!("invalid SCRAM salt: {e}")))?;
        let iterations: u32 = attribute(message, 'i')?
            .parse()
            .map_err(|e| Error::auth(format!("invalid SCRAM iteration count: {e}")))?;

        self.server_first = message.to_string();
        self.salted = salted_password(password, &salt, iterations);
        Ok(())
    }

    fn auth_message(&self, without_proof: &str) -> String {
        format!(
            "{},{},{}",
            self.client_first_bare, self.server_first, without_proof
        )
    }

    /// Build the `client-final-message`, storing the expected server signature.
    ///
    /// `channel_binding` is the opaque binding data (the `tls-server-end-point`
    /// certificate digest) when channel binding was requested.
    pub fn client_final_message(&mut self, channel_binding: Option<&[u8]>) -> String {
        let mut cbind = self.gs2_header.as_bytes().to_vec();
        if let Some(data) = channel_binding {
            cbind.extend_from_slice(data);
        }
        let without_proof = format!(
            "c={},r={}",
            B64.encode(&cbind),
            attribute(&self.server_first, 'r').unwrap_or_default()
        );
        let auth_message = self.auth_message(&without_proof);

        let client_key = hmac(&self.salted, CLIENT_KEY);
        let stored_key: [u8; 32] = Sha256::digest(client_key).into();
        let client_signature = hmac(&stored_key, auth_message.as_bytes());
        let proof = xor(&client_key, &client_signature);

        let server_key = hmac(&self.salted, SERVER_KEY);
        self.expected_server_signature = hmac(&server_key, auth_message.as_bytes());

        format!("{without_proof},p={}", B64.encode(proof))
    }

    /// Verify the `server-final-message`.
    pub fn verify_server_final(&self, message: &str) -> Result<()> {
        let value = attribute(message, 'v')
            .map_err(|_| Error::auth("server sent an invalid SCRAM final message"))?;
        let signature = B64
            .decode(value)
            .map_err(|e| Error::auth(format!("invalid SCRAM server signature: {e}")))?;
        if crate::auth::md5::constant_time_eq(&signature, &self.expected_server_signature) {
            Ok(())
        } else {
            Err(Error::auth("SCRAM server signature mismatch"))
        }
    }
}

impl Default for ScramClient {
    fn default() -> Self {
        Self::new()
    }
}

/// A SCRAM-SHA-256 server (the proxy authenticating an incoming client).
#[derive(Debug, Clone)]
pub struct ScramServer {
    gs2_header: String,
    client_first_bare: String,
    client_nonce: String,
    server_nonce: String,
    salt: Vec<u8>,
    iterations: u32,
}

impl ScramServer {
    /// Begin a server-side exchange given the client's first message.
    pub fn start(
        client_first_message: &str,
        salt: Vec<u8>,
        iterations: u32,
        server_nonce: String,
    ) -> Result<Self> {
        let (gs2_header, client_first_bare) = split_gs2(client_first_message)?;
        let flag = gs2_header.as_bytes().first().copied().unwrap_or(b'x');
        if flag == b'p' {
            // The client wants channel binding, which we did not advertise.
            return Err(Error::auth(
                "SCRAM channel binding was requested but not offered by the proxy",
            ));
        }
        let client_nonce = attribute(client_first_bare, 'r')?.to_string();
        if client_nonce.is_empty() {
            return Err(Error::auth("SCRAM client nonce is empty"));
        }
        Ok(Self {
            gs2_header: gs2_header.to_string(),
            client_first_bare: client_first_bare.to_string(),
            client_nonce,
            server_nonce,
            salt,
            iterations,
        })
    }

    /// Generate a random salt for this exchange.
    pub fn random_salt() -> Vec<u8> {
        let mut salt = vec![0u8; 16];
        rand::thread_rng().fill_bytes(&mut salt);
        salt
    }

    /// The `server-first-message`.
    pub fn server_first_message(&self) -> String {
        format!(
            "r={}{},s={},i={}",
            self.client_nonce,
            self.server_nonce,
            B64.encode(&self.salt),
            self.iterations
        )
    }

    /// Verify a `client-final-message` against `password` and produce the
    /// `server-final-message`.
    pub fn verify_client_final(
        &self,
        client_final_message: &str,
        password: &str,
    ) -> Result<String> {
        let channel_binding = attribute(client_final_message, 'c')?;
        let decoded_binding = B64
            .decode(channel_binding)
            .map_err(|e| Error::auth(format!("invalid SCRAM channel binding: {e}")))?;
        if decoded_binding != self.gs2_header.as_bytes() {
            return Err(Error::auth(
                "SCRAM channel binding does not match the gs2 header",
            ));
        }

        let nonce = attribute(client_final_message, 'r')?;
        if nonce != format!("{}{}", self.client_nonce, self.server_nonce) {
            return Err(Error::auth("SCRAM nonce mismatch"));
        }

        let proof = B64
            .decode(attribute(client_final_message, 'p')?)
            .map_err(|e| Error::auth(format!("invalid SCRAM proof: {e}")))?;
        if proof.len() != 32 {
            return Err(Error::auth("SCRAM proof has the wrong length"));
        }

        // client-final-message-without-proof
        let without_proof = client_final_message
            .rfind(",p=")
            .map(|idx| &client_final_message[..idx])
            .ok_or_else(|| Error::auth("malformed SCRAM client-final-message"))?;

        let server_first = self.server_first_message();
        let auth_message = format!(
            "{},{},{}",
            self.client_first_bare, server_first, without_proof
        );

        let salted = salted_password(password, &self.salt, self.iterations);
        let client_key = hmac(&salted, CLIENT_KEY);
        let stored_key: [u8; 32] = Sha256::digest(client_key).into();
        let client_signature = hmac(&stored_key, auth_message.as_bytes());

        let mut proof_arr = [0u8; 32];
        proof_arr.copy_from_slice(&proof);
        let recovered_client_key = xor(&proof_arr, &client_signature);
        let recovered_stored_key: [u8; 32] = Sha256::digest(recovered_client_key).into();
        if !crate::auth::md5::constant_time_eq(&recovered_stored_key, &stored_key) {
            return Err(Error::auth("SCRAM authentication failed"));
        }

        let server_key = hmac(&salted, SERVER_KEY);
        let server_signature = hmac(&server_key, auth_message.as_bytes());
        Ok(format!("v={}", B64.encode(server_signature)))
    }

    /// The gs2 header the client used.
    pub fn gs2_header(&self) -> &str {
        &self.gs2_header
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_and_server_interoperate() {
        let password = "s3cret";
        let salt = ScramServer::random_salt();

        let mut client = ScramClient::new();
        let client_first = client.client_first_message();

        let server =
            ScramServer::start(&client_first, salt, DEFAULT_ITERATIONS, server_nonce()).unwrap();
        let server_first = server.server_first_message();

        client.handle_server_first(&server_first, password).unwrap();
        let client_final = client.client_final_message(None);

        let server_final = server.verify_client_final(&client_final, password).unwrap();
        client.verify_server_final(&server_final).unwrap();
    }

    #[test]
    fn wrong_password_is_rejected() {
        let salt = ScramServer::random_salt();
        let mut client = ScramClient::new();
        let client_first = client.client_first_message();
        let server =
            ScramServer::start(&client_first, salt, DEFAULT_ITERATIONS, server_nonce()).unwrap();
        let server_first = server.server_first_message();
        client
            .handle_server_first(&server_first, "correct")
            .unwrap();
        let client_final = client.client_final_message(None);
        assert!(server.verify_client_final(&client_final, "wrong").is_err());
    }

    #[test]
    fn channel_binding_request_is_rejected_when_not_offered() {
        let msg = format!("p=tls-server-end-point,,n=,r={}", client_nonce());
        assert!(ScramServer::start(&msg, vec![1, 2, 3, 4], 4096, server_nonce()).is_err());
    }

    #[test]
    fn tampered_nonce_is_rejected() {
        let salt = ScramServer::random_salt();
        let mut client = ScramClient::new();
        let client_first = client.client_first_message();
        let server =
            ScramServer::start(&client_first, salt, DEFAULT_ITERATIONS, server_nonce()).unwrap();
        let mut server_first = server.server_first_message();
        server_first.push('x');
        assert!(client.handle_server_first(&server_first, "pw").is_err());
    }

    /// RFC 7677 section 3 test vector. The user name is included explicitly so
    /// that the published `ClientProof` and `ServerSignature` can be checked.
    #[test]
    fn rfc7677_vector() {
        let client_nonce_str = "rOprNGfwEbeRWgbNEkqO";
        let server_nonce_str = "%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0";
        let salt_b64 = "W22ZaJ0SNY7soEsUEjb6gQ==";
        let iterations = 4096;
        let password = "pencil";
        let server_first =
            format!("r={client_nonce_str}{server_nonce_str},s={salt_b64},i={iterations}");
        let expected_client_final = format!(
            "c=biws,r={client_nonce_str}{server_nonce_str},p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="
        );
        let expected_server_final = "v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=";

        // Client side: reproduce the published proof and verify the signature.
        let mut client = ScramClient::with_username(client_nonce_str.to_string(), "user");
        assert_eq!(
            client.client_first_message(),
            format!("n,,n=user,r={client_nonce_str}")
        );
        client.handle_server_first(&server_first, password).unwrap();
        assert_eq!(client.client_final_message(None), expected_client_final);
        client.verify_server_final(expected_server_final).unwrap();

        // Server side: verify the published proof and reproduce the signature.
        let salt = B64.decode(salt_b64).unwrap();
        let server = ScramServer::start(
            &format!("n,,n=user,r={client_nonce_str}"),
            salt,
            iterations,
            server_nonce_str.to_string(),
        )
        .unwrap();
        assert_eq!(server.server_first_message(), server_first);
        assert_eq!(
            server
                .verify_client_final(&expected_client_final, password)
                .unwrap(),
            expected_server_final
        );
    }
}
