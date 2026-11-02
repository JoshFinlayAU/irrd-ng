//! Connection strings and TLS for the source database.
//!
//! Accepts what an operator already has: v4's own `database_url`
//! (SQLAlchemy style, `postgresql+psycopg2://...` included) or any libpq
//! URL or `key=value` string. `sslmode` and `sslrootcert` follow libpq
//! (16 and later): `disable` does not encrypt, `allow`, `prefer` (the
//! default) and `require` encrypt without checking the certificate,
//! `verify-ca` checks the chain and `verify-full` the chain and host name.
//! The root certificates come from `sslrootcert`, by default
//! `~/.postgresql/root.crt`; when that file exists, `require` checks the
//! chain like `verify-ca`, and when it does not the verifying modes fail
//! with libpq's error. `sslrootcert=system` trusts the Mozilla roots built
//! into the binary (webpki-roots, as the system roots of a static build)
//! and needs `verify-full`, which it makes the default.
//!
//! TLS is rustls with the ring provider, so the static musl build needs no
//! system OpenSSL or certificate store.

use std::sync::Arc;

use postgres::config::SslMode;
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, DigitallySignedStruct, RootCertStore, SignatureScheme};

use crate::ImportError;
use crate::messages;

/// How the server certificate is checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verify {
    None,
    Chain,
    Full,
}

/// libpq's `sslmode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    Disable,
    Allow,
    Prefer,
    Require,
    VerifyCa,
    VerifyFull,
}

impl Mode {
    fn name(self) -> &'static str {
        match self {
            Mode::Disable => "disable",
            Mode::Allow => "allow",
            Mode::Prefer => "prefer",
            Mode::Require => "require",
            Mode::VerifyCa => "verify-ca",
            Mode::VerifyFull => "verify-full",
        }
    }
}

/// A connection string split into what tokio-postgres understands and the
/// TLS settings it does not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Dsn {
    pub(crate) config: String,
    pub(crate) mode: SslMode,
    pub(crate) sslmode: Mode,
    /// `sslrootcert`, if given and not empty.
    pub(crate) root_cert: Option<String>,
}

/// libpq's `ROOT_CERT_FILE`, under the home directory.
const ROOT_CERT_FILE: &str = ".postgresql/root.crt";

/// Where the trusted roots come from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Roots {
    /// Not checked.
    None,
    /// A PEM file.
    File(String),
    /// `sslrootcert=system`.
    System,
}

/// What `initialize_SSL()` decides for a connection: how much of the
/// certificate to check, against which roots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TlsPlan {
    pub(crate) verify: Verify,
    pub(crate) roots: Roots,
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
    // An empty sslrootcert is libpq's unset one.
    let root_cert = root_cert.filter(|r| !r.is_empty());

    let system = root_cert.as_deref() == Some("system");
    let sslmode = match sslmode.as_deref() {
        // sslrootcert=system makes verify-full the default.
        None if system => Mode::VerifyFull,
        None | Some("prefer") => Mode::Prefer,
        Some("disable") => Mode::Disable,
        Some("allow") => Mode::Allow,
        Some("require") => Mode::Require,
        Some("verify-ca") => Mode::VerifyCa,
        Some("verify-full") => Mode::VerifyFull,
        Some(other) => return Err(ImportError::Dsn(messages::dsn_sslmode(other))),
    };
    if system && sslmode != Mode::VerifyFull {
        return Err(ImportError::Dsn(messages::weak_sslmode(sslmode.name())));
    }
    let mode = match sslmode {
        Mode::Disable => SslMode::Disable,
        Mode::Allow | Mode::Prefer => SslMode::Prefer,
        Mode::Require | Mode::VerifyCa | Mode::VerifyFull => SslMode::Require,
    };
    Ok(Dsn {
        config,
        mode,
        sslmode,
        root_cert,
    })
}

fn unquote(v: &str) -> String {
    v.trim_matches('\'').to_owned()
}

/// What a masked password is shown as.
pub const MASK: &str = "****";

/// `dsn` with any password replaced by [`MASK`], for showing to an
/// operator: the `user:password@` of a URL, a `password=` URL parameter,
/// and the `password` keyword of a `key=value` string (quoted or not).
/// Everything else is kept as written, so the result can be pasted back
/// once the password is filled in.
pub fn mask_password(dsn: &str) -> String {
    if let Some((scheme, rest)) = dsn.split_once("://") {
        let (head, query) = match rest.split_once('?') {
            Some((h, q)) => (h, Some(q)),
            None => (rest, None),
        };
        // The user info ends at the last `@` before the path: a password
        // may itself hold an unencoded `@`.
        let host_from = head.rfind('@').map_or(0, |at| at + 1);
        let path_start = head[host_from..]
            .find('/')
            .map_or(head.len(), |p| host_from + p);
        let authority = &head[..path_start];
        let path = &head[path_start..];
        let authority = match authority.rsplit_once('@') {
            Some((userinfo, host)) => match userinfo.split_once(':') {
                Some((user, _)) => format!("{user}:{MASK}@{host}"),
                None => format!("{userinfo}@{host}"),
            },
            None => authority.to_owned(),
        };
        let mut out = format!("{scheme}://{authority}{path}");
        if let Some(q) = query {
            let pairs: Vec<String> = q
                .split('&')
                .map(|pair| match pair.split_once('=') {
                    Some(("password", _)) => format!("password={MASK}"),
                    _ => pair.to_owned(),
                })
                .collect();
            out.push('?');
            out.push_str(&pairs.join("&"));
        }
        return out;
    }
    mask_keyword_password(dsn)
}

/// [`mask_password`] for libpq's `key = value` form, where values may be
/// single-quoted with backslash escapes and `=` may have spaces around it.
fn mask_keyword_password(dsn: &str) -> String {
    let b = dsn.as_bytes();
    let mut out = String::with_capacity(dsn.len());
    let mut i = 0;
    while i < b.len() {
        if b[i].is_ascii_whitespace() {
            out.push(char::from(b[i]));
            i += 1;
            continue;
        }
        // One `key = value` pair.
        let key_start = i;
        while i < b.len() && !b[i].is_ascii_whitespace() && b[i] != b'=' {
            i += 1;
        }
        let key = &dsn[key_start..i];
        while i < b.len() && b[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= b.len() || b[i] != b'=' {
            // Not a pair: keep it as written.
            out.push_str(&dsn[key_start..i]);
            continue;
        }
        i += 1;
        while i < b.len() && b[i].is_ascii_whitespace() {
            i += 1;
        }
        let value_start = i;
        if i < b.len() && b[i] == b'\'' {
            i += 1;
            while i < b.len() && b[i] != b'\'' {
                i += if b[i] == b'\\' { 2 } else { 1 };
            }
            i = (i + 1).min(b.len());
        } else {
            while i < b.len() && !b[i].is_ascii_whitespace() {
                i += 1;
            }
        }
        out.push_str(&dsn[key_start..value_start]);
        if key == "password" {
            out.push_str(MASK);
        } else {
            out.push_str(&dsn[value_start..i]);
        }
    }
    out
}

/// libpq's choice of root certificates and checks: `sslrootcert`, or
/// `root.crt` under `home`; a file that does not exist means no checks,
/// which the verifying modes refuse.
pub(crate) fn plan(dsn: &Dsn, home: Option<&std::path::Path>) -> Result<TlsPlan, ImportError> {
    let none = TlsPlan {
        verify: Verify::None,
        roots: Roots::None,
    };
    let verifying = matches!(dsn.sslmode, Mode::VerifyCa | Mode::VerifyFull);
    // Only libpq's verifying modes and require look at the roots;
    // allow and prefer encrypt without checks here.
    if !verifying && dsn.sslmode != Mode::Require {
        return Ok(none);
    }
    let verify = if dsn.sslmode == Mode::VerifyFull {
        Verify::Full
    } else {
        Verify::Chain
    };
    let path = match (&dsn.root_cert, home) {
        (Some(r), _) if r == "system" => {
            return Ok(TlsPlan {
                verify,
                roots: Roots::System,
            });
        }
        (Some(r), _) => r.clone(),
        (None, Some(h)) => h.join(ROOT_CERT_FILE).display().to_string(),
        (None, None) if verifying => {
            return Err(ImportError::Tls(messages::NO_HOME_FOR_ROOT_CERT.to_owned()));
        }
        (None, None) => return Ok(none),
    };
    if std::fs::metadata(&path).is_ok() {
        Ok(TlsPlan {
            verify,
            roots: Roots::File(path),
        })
    } else if verifying {
        Err(ImportError::Tls(messages::root_cert_missing(&path)))
    } else {
        Ok(none)
    }
}

/// The home directory libpq looks in: `$HOME`.
pub(crate) fn home_dir() -> Option<std::path::PathBuf> {
    std::env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .map(std::path::PathBuf::from)
}

pub(crate) fn tls_config(plan: &TlsPlan) -> Result<rustls::ClientConfig, ImportError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| ImportError::Tls(e.to_string()))?;
    let verifier: Arc<dyn ServerCertVerifier> = match plan.verify {
        Verify::None => Arc::new(NoVerify(provider)),
        Verify::Chain | Verify::Full => {
            let mut roots = RootCertStore::empty();
            match &plan.roots {
                Roots::File(path) => {
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
                Roots::System => roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
                Roots::None => {}
            }
            let inner = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider)
                .build()
                .map_err(|e| ImportError::Tls(e.to_string()))?;
            if plan.verify == Verify::Full {
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
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
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
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    struct Tmp(std::path::PathBuf);
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A home directory, with `~/.postgresql/root.crt` or without.
    fn home(tag: &str, with_root: bool) -> Tmp {
        let p = std::env::temp_dir().join(format!("irrd-ng-dsn-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(p.join(".postgresql")).unwrap();
        if with_root {
            std::fs::write(p.join(ROOT_CERT_FILE), "").unwrap();
        }
        Tmp(p)
    }

    fn plan_for(dsn: &str, home: Option<&Tmp>) -> Result<TlsPlan, String> {
        plan(&parse(dsn).unwrap(), home.map(|h| h.0.as_path())).map_err(|e| e.to_string())
    }

    #[test]
    fn sqlalchemy_url_drops_driver() {
        let d = parse("postgresql+psycopg2://irrd:irrd@db/irrd").unwrap();
        assert_eq!(d.config, "postgresql://irrd:irrd@db/irrd");
        assert_eq!(d.mode, SslMode::Prefer);
        assert_eq!(d.sslmode, Mode::Prefer);
    }

    #[test]
    fn url_tls_params_are_taken_out() {
        let d = parse(
            "postgres://u@h:5433/db?sslmode=verify-full&application_name=x&sslrootcert=/ca.pem",
        )
        .unwrap();
        assert_eq!(d.config, "postgresql://u@h:5433/db?application_name=x");
        assert_eq!(d.mode, SslMode::Require);
        assert_eq!(d.sslmode, Mode::VerifyFull);
        assert_eq!(d.root_cert.as_deref(), Some("/ca.pem"));
    }

    #[test]
    fn require_checks_the_chain_when_there_are_roots() {
        let d = parse("host=h dbname=irrd sslmode=require sslrootcert='/ca.pem'").unwrap();
        assert_eq!(d.config, "host=h dbname=irrd");
        assert_eq!(
            parse("host=h sslmode=disable").unwrap().mode,
            SslMode::Disable
        );
        let none = TlsPlan {
            verify: Verify::None,
            roots: Roots::None,
        };
        // A named file that does not exist: no checks, as in libpq.
        assert_eq!(
            plan_for(
                "host=h sslmode=require sslrootcert=/nonexistent/ca.pem",
                None
            ),
            Ok(none.clone())
        );
        // ~/.postgresql/root.crt, when it exists.
        let with = home("require-with", true);
        let root = with.0.join(ROOT_CERT_FILE).display().to_string();
        assert_eq!(
            plan_for("host=h sslmode=require", Some(&with)),
            Ok(TlsPlan {
                verify: Verify::Chain,
                roots: Roots::File(root),
            })
        );
        let without = home("require-without", false);
        assert_eq!(
            plan_for("host=h sslmode=require", Some(&without)),
            Ok(none.clone())
        );
        assert_eq!(plan_for("host=h sslmode=require", None), Ok(none.clone()));
        // prefer and allow encrypt without checks.
        assert_eq!(plan_for("host=h", Some(&with)), Ok(none.clone()));
        assert_eq!(plan_for("host=h sslmode=allow", Some(&with)), Ok(none));
    }

    /// verify-ca and verify-full never fall back to roots nobody named:
    /// without sslrootcert they use ~/.postgresql/root.crt, and fail with
    /// libpq's error when it is missing.
    #[test]
    fn verifying_modes_need_a_root_certificate_file() {
        let with = home("verify-with", true);
        let root = with.0.join(ROOT_CERT_FILE).display().to_string();
        assert_eq!(
            plan_for("postgresql://h/irrd?sslmode=verify-ca", Some(&with)),
            Ok(TlsPlan {
                verify: Verify::Chain,
                roots: Roots::File(root.clone()),
            })
        );
        assert_eq!(
            plan_for("host=h sslmode=verify-full", Some(&with)),
            Ok(TlsPlan {
                verify: Verify::Full,
                roots: Roots::File(root),
            })
        );
        let without = home("verify-without", false);
        let missing = without.0.join(ROOT_CERT_FILE).display().to_string();
        for mode in ["verify-ca", "verify-full"] {
            assert_eq!(
                plan_for(&format!("host=h sslmode={mode}"), Some(&without)),
                Err(format!(
                    "root certificate file \"{missing}\" does not exist\n\
                     Either provide the file, use the system's trusted roots with \
                     sslrootcert=system, or change sslmode to disable server certificate \
                     verification."
                ))
            );
            assert_eq!(
                plan_for(
                    &format!("host=h sslmode={mode} sslrootcert=/nonexistent/ca.pem"),
                    Some(&with)
                ),
                Err(
                    "root certificate file \"/nonexistent/ca.pem\" does not exist\n\
                     Either provide the file, use the system's trusted roots with \
                     sslrootcert=system, or change sslmode to disable server certificate \
                     verification."
                        .to_owned()
                )
            );
            assert_eq!(
                plan_for(&format!("host=h sslmode={mode}"), None),
                Err(
                    "could not get home directory to locate root certificate file\n\
                     Either provide the file, use the system's trusted roots with \
                     sslrootcert=system, or change sslmode to disable server certificate \
                     verification."
                        .to_owned()
                )
            );
        }
        // The Mozilla roots only when asked for, and only with the host
        // name checked.
        assert_eq!(
            plan_for("host=h sslrootcert=system", None),
            Ok(TlsPlan {
                verify: Verify::Full,
                roots: Roots::System,
            })
        );
        assert_eq!(
            plan_for("host=h sslmode=verify-full sslrootcert=system", None),
            Ok(TlsPlan {
                verify: Verify::Full,
                roots: Roots::System,
            })
        );
        assert_eq!(
            parse("host=h sslmode=verify-ca sslrootcert=system")
                .map_err(|e| e.to_string())
                .unwrap_err(),
            "weak sslmode \"verify-ca\" may not be used with sslrootcert=system (use \"verify-full\")"
        );
        assert!(parse("host=h sslmode=require sslrootcert=system").is_err());
    }

    #[test]
    fn bad_scheme_and_sslmode_are_rejected() {
        assert!(parse("mysql://h/db").is_err());
        assert!(parse("host=h sslmode=bogus").is_err());
    }

    #[test]
    fn passwords_are_masked_in_urls() {
        for (dsn, want) in [
            (
                "postgresql://irrd:s3cret@localhost/irrd",
                "postgresql://irrd:****@localhost/irrd",
            ),
            (
                "postgresql+psycopg2://irrd:p@ss:w/rd@db.example.net:5433/irrd?sslmode=require",
                "postgresql+psycopg2://irrd:****@db.example.net:5433/irrd?sslmode=require",
            ),
            (
                "postgresql://irrd@localhost/irrd?password=x&sslmode=disable",
                "postgresql://irrd@localhost/irrd?password=****&sslmode=disable",
            ),
            ("postgresql:///irrd", "postgresql:///irrd"),
            (
                "postgres://irrd:pw@[::1]:5432",
                "postgres://irrd:****@[::1]:5432",
            ),
        ] {
            assert_eq!(mask_password(dsn), want, "{dsn}");
        }
    }

    #[test]
    fn passwords_are_masked_in_keyword_strings() {
        for (dsn, want) in [
            (
                "host=localhost dbname=irrd user=irrd password=s3cret",
                "host=localhost dbname=irrd user=irrd password=****",
            ),
            (
                "host=h password = 'a b\\' c' dbname=irrd",
                "host=h password = **** dbname=irrd",
            ),
            ("host=h dbname=irrd", "host=h dbname=irrd"),
            ("passwordx=1 password=", "passwordx=1 password=****"),
        ] {
            assert_eq!(mask_password(dsn), want, "{dsn}");
        }
    }
}
