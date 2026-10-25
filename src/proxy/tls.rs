//! TLS support: serving TLS to clients and speaking TLS to the upstream server.

use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, ServerConfig, SignatureScheme};

use crate::error::{Error, Result};
use crate::proxy::config::{TlsClientOptions, VerifyMode};

fn crypto_provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Load a PEM certificate chain.
pub fn load_certificates(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let file =
        File::open(path).map_err(|e| Error::tls(format!("cannot open {}: {e}", path.display())))?;
    let mut reader = BufReader::new(file);
    let certs: std::result::Result<Vec<_>, _> = rustls_pemfile::certs(&mut reader).collect();
    let certs = certs.map_err(|e| Error::tls(format!("cannot parse {}: {e}", path.display())))?;
    if certs.is_empty() {
        return Err(Error::tls(format!(
            "{} does not contain any certificate",
            path.display()
        )));
    }
    Ok(certs)
}

/// Load a PEM private key (PKCS#8, PKCS#1 or SEC1).
pub fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let file =
        File::open(path).map_err(|e| Error::tls(format!("cannot open {}: {e}", path.display())))?;
    let mut reader = BufReader::new(file);
    rustls_pemfile::private_key(&mut reader)
        .map_err(|e| Error::tls(format!("cannot parse {}: {e}", path.display())))?
        .ok_or_else(|| Error::tls(format!("{} does not contain a private key", path.display())))
}

/// Build a server configuration, optionally requiring client certificates.
pub fn server_config(
    cert_file: &Path,
    key_file: &Path,
    client_ca_file: Option<&Path>,
) -> Result<Arc<ServerConfig>> {
    let certs = load_certificates(cert_file)?;
    let key = load_private_key(key_file)?;

    let builder = ServerConfig::builder_with_provider(crypto_provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| Error::tls(e.to_string()))?;

    let config = match client_ca_file {
        None => builder
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| Error::tls(e.to_string()))?,
        Some(ca) => {
            let mut roots = RootCertStore::empty();
            for cert in load_certificates(ca)? {
                roots
                    .add(cert)
                    .map_err(|e| Error::tls(format!("invalid CA certificate: {e}")))?;
            }
            let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
                .build()
                .map_err(|e| Error::tls(format!("cannot build client verifier: {e}")))?;
            builder
                .with_client_cert_verifier(verifier)
                .with_single_cert(certs, key)
                .map_err(|e| Error::tls(e.to_string()))?
        }
    };
    Ok(Arc::new(config))
}

/// Build a client configuration for the upstream connection.
pub fn client_config(options: &TlsClientOptions) -> Result<Arc<ClientConfig>> {
    let provider = crypto_provider();
    let builder = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| Error::tls(e.to_string()))?;

    let with_roots = match options.verify {
        VerifyMode::None => builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerification::new(provider))),
        VerifyMode::Full => {
            let ca = options.ca_file.as_deref().ok_or_else(|| {
                Error::tls(
                    "upstream TLS verification is enabled but no CA bundle was configured \
                     (set a CA file or disable verification explicitly)",
                )
            })?;
            let mut roots = RootCertStore::empty();
            for cert in load_certificates(ca)? {
                roots
                    .add(cert)
                    .map_err(|e| Error::tls(format!("invalid CA certificate: {e}")))?;
            }
            builder.with_root_certificates(roots)
        }
    };

    let config = match &options.client_cert {
        None => with_roots.with_no_client_auth(),
        Some((cert_file, key_file)) => {
            let certs = load_certificates(cert_file)?;
            let key = load_private_key(key_file)?;
            with_roots
                .with_client_auth_cert(certs, key)
                .map_err(|e| Error::tls(e.to_string()))?
        }
    };
    Ok(Arc::new(config))
}

/// A certificate verifier that accepts everything.
///
/// Only reachable through an explicit `VerifyMode::None`; the proxy logs a
/// warning when it is used because it defeats server authentication.
#[derive(Debug)]
struct NoVerification {
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl NoVerification {
    fn new(provider: Arc<rustls::crypto::CryptoProvider>) -> Self {
        Self { provider }
    }
}

impl ServerCertVerifier for NoVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Compute the `tls-server-end-point` channel-binding digest of a certificate.
///
/// PostgreSQL uses the certificate's signature hash, defaulting to SHA-256 for
/// hashes weaker than SHA-256 and for certificates without a hash.
pub fn tls_server_end_point(certificate: &CertificateDer<'_>) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    Sha256::digest(certificate.as_ref()).to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_ca_is_an_error() {
        let options = TlsClientOptions {
            verify: VerifyMode::Full,
            ca_file: None,
            client_cert: None,
        };
        assert!(client_config(&options).is_err());
    }

    #[test]
    fn no_verify_config_builds() {
        let options = TlsClientOptions {
            verify: VerifyMode::None,
            ca_file: None,
            client_cert: None,
        };
        assert!(client_config(&options).is_ok());
    }
}
