//! Connection strings and TLS for the source database.
//!
//! Accepts what an operator already has: v4's own `database_url`
//! (SQLAlchemy style, `postgresql+psycopg2://...` included) or any libpq
//! URL or `key=value` string. `sslmode` follows libpq: `disable`, `allow`,
//! `prefer` (the default) and `require` encrypt without checking the
//! certificate, unless `sslrootcert` is given, in which case `require`
//! checks the chain like `verify-ca`; `verify-ca` checks the chain and
//! `verify-full` the chain and host name. Without `sslrootcert` the
//! verifying modes trust the Mozilla roots (webpki-roots).
//!
//! TLS is rustls with the ring provider, so the static musl build needs no
//! system OpenSSL or certificate store.

use std::sync::Arc;

use postgres::config::SslMode;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, DigitallySignedStruct, RootCertStore, SignatureScheme};

use crate::messages;
use crate::ImportError;

/// How the server certificate is checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verify {
    None,
    Chain,
    Full,
}

/// A connection string split into what tokio-postgres understands and the
/// TLS settings it does not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Dsn {
    pub(crate) config: String,
    pub(crate) mode: SslMode,
    pub(crate) verify: Verify,
    pub(crate) root_cert: Option<String>,
}

pub(crate) fn parse(dsn: &str) -> Result<Dsn, ImportError> {
    let dsn = dsn.trim();
    let mut sslmode = None;
    let mut root_cert = None;
    let config = if let Some((scheme, rest)) = dsn.split_once("://") {
        let base = scheme.split('+').next().unwrap_or(scheme);
        if base != "postgresql" && base != "postgres" {
            return Err(ImportError::Dsn(messages::dsn_scheme(scheme)));
        }
        let (head, query) = match rest.split_once('?') {
            Some((h, q)) => (h, Some(q)),
            None => (rest, None),
        };
        let mut kept = Vec::new();
        for pair in query.into_iter().flat_map(|q| q.split('&')) {
            match pair.split_once('=') {
                Some(("sslmode", v)) => sslmode = Some(v.to_owned()),
                Some(("sslrootcert", v)) => root_cert = Some(v.to_owned()),
                _ if pair.is_empty() => {}
                _ => kept.push(pair),
            }
        }
        let mut s = format!("postgresql://{head}");
        if !kept.is_empty() {
            s.push('?');
            s.push_str(&kept.join("&"));
        }
        s
    } else {
        let mut kept = Vec::new();
        for token in dsn.split_whitespace() {
            match token.split_once('=') {
                Some(("sslmode", v)) => sslmode = Some(unquote(v)),
                Some(("sslrootcert", v)) => root_cert = Some(unquote(v)),
                _ => kept.push(token),
            }
        }
        kept.join(" ")
    };

    let has_root = root_cert.is_some();
    let (mode, verify) = match sslmode.as_deref().unwrap_or("prefer") {
        "disable" => (SslMode::Disable, Verify::None),
        "allow" | "prefer" => (SslMode::Prefer, Verify::None),
        "require" if has_root => (SslMode::Require, Verify::Chain),
        "require" => (SslMode::Require, Verify::None),
        "verify-ca" => (SslMode::Require, Verify::Chain),
        "verify-full" => (SslMode::Require, Verify::Full),
        other => return Err(ImportError::Dsn(messages::dsn_sslmode(other))),
    };
    Ok(Dsn {
        config,
        mode,
        verify,
        root_cert,
    })
}

fn unquote(v: &str) -> String {
    v.trim_matches('\'').to_owned()
}

pub(crate) fn tls_config(dsn: &Dsn) -> Result<rustls::ClientConfig, ImportError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| ImportError::Tls(e.to_string()))?;
    let verifier: Arc<dyn ServerCertVerifier> = match dsn.verify {
        Verify::None => Arc::new(NoVerify(provider)),
        Verify::Chain | Verify::Full => {
            let mut roots = RootCertStore::empty();
            match &dsn.root_cert {
                Some(path) => {
                    let certs = CertificateDer::pem_file_iter(path)
                        .map_err(|e| ImportError::Tls(messages::root_cert(path, &e.to_string())))?;
                    for cert in certs {
                        let cert = cert.map_err(|e| {
                            ImportError::Tls(messages::root_cert(path, &e.to_string()))
                        })?;
                        roots.add(cert).map_err(|e| {
                            ImportError::Tls(messages::root_cert(path, &e.to_string()))
                        })?;
                    }
                }
                None => roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
            }
            let inner = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider)
                .build()
                .map_err(|e| ImportError::Tls(e.to_string()))?;
            if dsn.verify == Verify::Full {
                inner
            } else {
                Arc::new(ChainOnly(inner))
            }
        }
    };
    Ok(builder
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth())
}

/// libpq's `prefer`/`require`: encrypted, certificate not checked.
/// Handshake signatures are still verified.
#[derive(Debug)]
struct NoVerify(Arc<CryptoProvider>);

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// libpq's `verify-ca`: the chain must check out, the host name need not
/// match.
#[derive(Debug)]
struct ChainOnly(Arc<WebPkiServerVerifier>);

impl ServerCertVerifier for ChainOnly {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        match self
            .0
            .verify_server_cert(end_entity, intermediates, server_name, ocsp, now)
        {
            Err(rustls::Error::InvalidCertificate(
                CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. },
            )) => Ok(ServerCertVerified::assertion()),
            other => other,
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.0.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.0.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.supported_verify_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sqlalchemy_url_drops_driver() {
        let d = parse("postgresql+psycopg2://irrd:irrd@db/irrd").unwrap();
        assert_eq!(d.config, "postgresql://irrd:irrd@db/irrd");
        assert_eq!(d.mode, SslMode::Prefer);
        assert_eq!(d.verify, Verify::None);
    }

    #[test]
    fn url_tls_params_are_taken_out() {
        let d = parse(
            "postgres://u@h:5433/db?sslmode=verify-full&application_name=x&sslrootcert=/ca.pem",
        )
        .unwrap();
        assert_eq!(d.config, "postgresql://u@h:5433/db?application_name=x");
        assert_eq!(d.mode, SslMode::Require);
        assert_eq!(d.verify, Verify::Full);
        assert_eq!(d.root_cert.as_deref(), Some("/ca.pem"));
    }

    #[test]
    fn require_with_root_cert_checks_the_chain() {
        let d = parse("host=h dbname=irrd sslmode=require sslrootcert='/ca.pem'").unwrap();
        assert_eq!(d.config, "host=h dbname=irrd");
        assert_eq!(d.verify, Verify::Chain);
        assert_eq!(parse("host=h sslmode=require").unwrap().verify, Verify::None);
        assert_eq!(parse("host=h sslmode=disable").unwrap().mode, SslMode::Disable);
    }

    #[test]
    fn bad_scheme_and_sslmode_are_rejected() {
        assert!(parse("mysql://h/db").is_err());
        assert!(parse("host=h sslmode=bogus").is_err());
    }
}
