//! TLS for the replication stream.
//!
//! The stream carries every replicated table, including the web UI's
//! password hashes and API tokens, so it should not cross a network in
//! the clear. When the active has a certificate and key
//! (`ng_replication.tls_certificate` and `tls_key`) it only accepts TLS,
//! and a standby with `tls_ca` or `tls_pin` only connects with TLS and
//! checks the active's certificate. The shared-secret handshake runs
//! inside the TLS session unchanged, so TLS adds confidentiality and server
//! authentication on top of it and replaces nothing.
//!
//! Both ends are irrd-ng, so only TLS 1.3 is offered. rustls with the ring
//! provider keeps the static musl builds free of C dependencies.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, ServerConfig, SignatureScheme};
use sha2::{Digest, Sha256};

/// The first byte of a TLS handshake record. A plaintext replication frame
/// starts with the high byte of its length, which is never this value
/// (frames are far smaller than 0x16000000 bytes).
pub(crate) const TLS_HANDSHAKE_BYTE: u8 = 0x16;

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// The active's TLS settings, from a PEM certificate chain and a PEM
/// private key (PKCS#8, PKCS#1 or SEC1).
pub fn server_config(cert_path: &Path, key_path: &Path) -> Result<Arc<ServerConfig>, String> {
    let certs = read_certs(cert_path)?;
    let key = PrivateKeyDer::from_pem_file(key_path)
        .map_err(|e| format!("unable to read {}: {e}", key_path.display()))?;
    let config = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| e.to_string())?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| {
            format!(
                "unable to use {} with {}: {e}",
                cert_path.display(),
                key_path.display()
            )
        })?;
    Ok(Arc::new(config))
}

/// How a standby decides to trust the active's certificate.
#[derive(Debug, Clone)]
pub enum Trust {
    /// A PEM file of CA certificates; the active's certificate must chain
    /// to one of them and be valid for the server name.
    Ca(PathBuf),
    /// The SHA-256 fingerprint of the active's certificate (its DER
    /// encoding, as `openssl x509 -noout -fingerprint -sha256` prints it).
    /// Nothing else about the certificate is checked, so a self-signed
    /// certificate works and its expiry does not matter.
    Pin([u8; 32]),
}

/// What a standby needs to connect with TLS.
#[derive(Debug, Clone)]
pub struct ClientTls {
    pub(crate) config: Arc<ClientConfig>,
    pub(crate) server_name: ServerName<'static>,
}

/// The standby's TLS settings. `server_name` is the name the active's
/// certificate must be valid for with [`Trust::Ca`] (a DNS name or an IP
/// address); with [`Trust::Pin`] it is only sent as SNI.
pub fn client_config(trust: Trust, server_name: &str) -> Result<ClientTls, String> {
    let server_name = ServerName::try_from(server_name.to_owned())
        .map_err(|_| format!("invalid TLS server name {server_name}"))?;
    let provider = provider();
    let builder = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| e.to_string())?;
    let config = match trust {
        Trust::Ca(path) => {
            let mut roots = RootCertStore::empty();
            for cert in read_certs(&path)? {
                roots
                    .add(cert)
                    .map_err(|e| format!("unable to use {}: {e}", path.display()))?;
            }
            builder.with_root_certificates(roots).with_no_client_auth()
        }
        Trust::Pin(pin) => builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(Pinned {
                pin,
                algorithms: provider.signature_verification_algorithms,
            }))
            .with_no_client_auth(),
    };
    Ok(ClientTls {
        config: Arc::new(config),
        server_name,
    })
}

fn read_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, String> {
    let certs = CertificateDer::pem_file_iter(path)
        .and_then(|it| it.collect::<Result<Vec<_>, _>>())
        .map_err(|e| format!("unable to read {}: {e}", path.display()))?;
    if certs.is_empty() {
        return Err(format!("no certificates found in {}", path.display()));
    }
    Ok(certs)
}

/// Parse a SHA-256 fingerprint: 64 hexadecimal digits, optionally separated
/// by colons, in either case.
pub fn parse_pin(s: &str) -> Option<[u8; 32]> {
    let digits: Vec<u8> = s.bytes().filter(|b| *b != b':').collect();
    if digits.len() != 64 || s.starts_with(':') || s.ends_with(':') || s.contains("::") {
        return None;
    }
    let mut out = [0u8; 32];
    for (o, pair) in out.iter_mut().zip(digits.as_chunks::<2>().0) {
        let hi = char::from(pair[0]).to_digit(16)?;
        let lo = char::from(pair[1]).to_digit(16)?;
        *o = u8::try_from(hi * 16 + lo).ok()?;
    }
    Some(out)
}

/// The SHA-256 fingerprint of a DER certificate.
pub fn fingerprint(cert_der: &[u8]) -> [u8; 32] {
    Sha256::digest(cert_der).into()
}

/// Accepts exactly one certificate, by fingerprint, and checks that the
/// handshake was signed with its key.
struct Pinned {
    pin: [u8; 32],
    algorithms: WebPkiSupportedAlgorithms,
}

impl fmt::Debug for Pinned {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pinned").finish_non_exhaustive()
    }
}

impl ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if crate::protocol::constant_time_eq(&fingerprint(end_entity), &self.pin) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "the active's certificate does not match ng_replication.tls_pin".into(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pins_parse() {
        let hex = "AB".repeat(32);
        assert_eq!(parse_pin(&hex), Some([0xab; 32]));
        let colons = vec!["ab"; 32].join(":");
        assert_eq!(parse_pin(&colons), Some([0xab; 32]));
        assert_eq!(parse_pin(&"ab".repeat(31)), None);
        assert_eq!(parse_pin(&"zz".repeat(32)), None);
        assert_eq!(parse_pin(&format!(":{hex}")), None);
        assert_eq!(
            parse_pin(&format!("{}::{}", "ab".repeat(16), "ab".repeat(16))),
            None
        );
        assert_eq!(parse_pin(""), None);
        // Multi-byte characters are not hex digits, and do not panic.
        assert_eq!(parse_pin(&"é".repeat(32)), None);
    }
}
