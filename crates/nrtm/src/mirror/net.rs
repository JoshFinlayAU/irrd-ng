//! Outbound connections for mirroring: DNS, TCP, the whois client for
//! NRTMv3 (`irrd/utils/whois_client.py`), HTTP(S) and FTP.
//!
//! Everything here is pure Rust so the static musl build behaves like the
//! others: names are resolved by hickory from `/etc/hosts` and
//! `/etc/resolv.conf` (falling back to the system resolver if those cannot
//! be read), TLS is rustls with the Mozilla root store built in, as v4's
//! `requests` uses certifi's bundle.

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use hickory_resolver::TokioResolver;
use hickory_resolver::config::LookupIpStrategy;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::messages;
use crate::mirror::pyerr::{PyErr, os_error_text};

/// v4's logger for the whois client.
pub const WHOIS_LOG_TARGET: &str = "irrd.utils.whois_client";

/// v4's `HTTP_USER_AGENT`: `irrd/<version>`.
pub const HTTP_USER_AGENT: &str = "irrd/4.5.4";

fn resolver() -> Option<&'static TokioResolver> {
    static RESOLVER: OnceLock<Option<TokioResolver>> = OnceLock::new();
    RESOLVER
        .get_or_init(|| {
            let mut builder = TokioResolver::builder_tokio().ok()?;
            builder.options_mut().ip_strategy = LookupIpStrategy::Ipv4AndIpv6;
            builder.build().ok()
        })
        .as_ref()
}

/// `socket.getaddrinfo(host, port)`: the addresses to try, in order.
/// Failure is `socket.gaierror`, an `OSError`.
pub async fn resolve(host: &str, port: u16) -> Result<Vec<SocketAddr>, PyErr> {
    let bare = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    if let Ok(ip) = bare.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    if let Some(r) = resolver() {
        return match r.lookup_ip(host).await {
            Ok(l) => {
                let addrs: Vec<SocketAddr> = l.iter().map(|ip| SocketAddr::new(ip, port)).collect();
                if addrs.is_empty() {
                    Err(PyErr::Os(messages::GAI_NONAME.to_owned()))
                } else {
                    Ok(addrs)
                }
            }
            Err(e) if e.is_no_records_found() => Err(PyErr::Os(messages::GAI_NONAME.to_owned())),
            Err(_) => Err(PyErr::Os(messages::GAI_AGAIN.to_owned())),
        };
    }
    match tokio::net::lookup_host((host, port)).await {
        Ok(a) => Ok(a.collect()),
        Err(_) => Err(PyErr::Os(messages::GAI_NONAME.to_owned())),
    }
}

/// `socket.create_connection((host, port), timeout)`: try each address in
/// turn, each within the timeout; the last error is raised.
pub async fn connect(host: &str, port: u16, timeout: Duration) -> Result<TcpStream, PyErr> {
    let addrs = resolve(host, port).await?;
    let mut last = PyErr::Os(messages::GAI_NONAME.to_owned());
    for addr in addrs {
        match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
            Ok(Ok(s)) => return Ok(s),
            Ok(Err(e)) => last = PyErr::Os(os_error_text(&e, None)),
            Err(_) => last = PyErr::Os(messages::TIMED_OUT.to_owned()),
        }
    }
    Err(last)
}

/// `whois_query(host, port, query, end_markings, socket_timeout)`.
///
/// Reads until an end marking appears, the server closes, or nothing
/// arrives for `timeout` (logged as a warning, and what was read so far is
/// returned). The response is decoded as UTF-8 with backslash escapes for
/// invalid bytes.
pub async fn whois_query(
    host: &str,
    port: u16,
    query: &str,
    end_markings: &[String],
    timeout: Duration,
) -> Result<String, PyErr> {
    let query = format!("{}\n", rpsl::text::py_strip(query));
    let q = rpsl::text::py_strip(&query).to_owned();
    tracing::debug!(target: WHOIS_LOG_TARGET, "{}", messages::running_whois_query(&q, host, port));
    let mut s = connect(host, port, timeout).await?;
    match tokio::time::timeout(timeout, s.write_all(query.as_bytes())).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(PyErr::Os(os_error_text(&e, None))),
        Err(_) => return Err(PyErr::Os(messages::TIMED_OUT.to_owned())),
    }
    let mut buffer: Vec<u8> = Vec::new();
    let mut chunk = vec![0u8; 1024 * 1024];
    while !end_markings.iter().any(|m| contains(&buffer, m.as_bytes())) {
        match tokio::time::timeout(timeout, s.read(&mut chunk)).await {
            Err(_) => {
                tracing::warn!(target: WHOIS_LOG_TARGET, "{}", messages::whois_query_timed_out(&q, host, port));
                break;
            }
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => buffer.extend_from_slice(&chunk[..n]),
            Ok(Err(e)) => return Err(PyErr::Os(os_error_text(&e, None))),
        }
    }
    Ok(decode_backslashreplace(&buffer))
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

/// `bytes.decode("utf-8", errors="backslashreplace")`.
pub fn decode_backslashreplace(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for chunk in bytes.utf8_chunks() {
        out.push_str(chunk.valid());
        for b in chunk.invalid() {
            out.push_str(&format!("\\x{b:02x}"));
        }
    }
    out
}

/// Resolves names for reqwest with [`resolve`].
struct DnsResolver;

impl reqwest::dns::Resolve for DnsResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_owned();
        Box::pin(async move {
            match resolve(&host, 0).await {
                Ok(addrs) => Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs),
                Err(e) => Err(Box::new(std::io::Error::other(e.message().to_owned()))
                    as Box<dyn std::error::Error + Send + Sync>),
            }
        })
    }
}

/// The trust anchors `requests` uses: the bundle named by
/// `REQUESTS_CA_BUNDLE` or `CURL_CA_BUNDLE` (a PEM file, or a directory of
/// them) when set, otherwise its built-in Mozilla bundle.
fn root_store() -> Result<rustls::RootCertStore, PyErr> {
    root_store_from(
        ["REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"]
            .iter()
            .filter_map(std::env::var_os)
            .find(|v| !v.is_empty()),
    )
}

fn root_store_from(bundle: Option<std::ffi::OsString>) -> Result<rustls::RootCertStore, PyErr> {
    use rustls::pki_types::CertificateDer;
    use rustls::pki_types::pem::PemObject as _;
    let Some(bundle) = bundle else {
        return Ok(rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        });
    };
    let path = std::path::PathBuf::from(&bundle);
    let invalid = || PyErr::Os(messages::invalid_ca_bundle(&path.to_string_lossy()));
    let files: Vec<std::path::PathBuf> = if path.is_dir() {
        std::fs::read_dir(&path)
            .map_err(|_| invalid())?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .collect()
    } else if path.is_file() {
        vec![path.clone()]
    } else {
        return Err(invalid());
    };
    let mut store = rustls::RootCertStore::empty();
    for f in files {
        let Ok(bytes) = std::fs::read(&f) else {
            continue;
        };
        for cert in CertificateDer::pem_slice_iter(&bytes).flatten() {
            let _ = store.add(cert);
        }
    }
    Ok(store)
}

/// The HTTP client: `requests.get(url, stream=True, timeout=t,
/// headers={"User-Agent": HTTP_USER_AGENT})`. The timeout applies to
/// connecting and to each read, as in `requests`.
pub fn http_client(timeout: Duration) -> Result<reqwest::Client, PyErr> {
    http_client_builder(timeout)?
        .build()
        .map_err(|e| PyErr::Other(e.to_string()))
}

/// [`http_client`]'s configuration, for callers that need to change
/// more (`irr_rpsl_submit` does not follow redirects, as urllib does not
/// for its POST and DELETE requests).
pub fn http_client_builder(timeout: Duration) -> Result<reqwest::ClientBuilder, PyErr> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let roots = root_store()?;
    let tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| PyErr::Other(e.to_string()))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(reqwest::Client::builder()
        .use_preconfigured_tls(tls)
        .dns_resolver(Arc::new(DnsResolver))
        .user_agent(HTTP_USER_AGENT)
        .connect_timeout(timeout)
        .read_timeout(timeout))
}

/// `str()` of the exception `requests` raises when a request fails before
/// a response arrives (all are `OSError` subclasses). The shape follows
/// urllib3's messages; the cause is irrd-ng's own wording.
pub fn requests_error_text(url: &reqwest::Url, e: &reqwest::Error, timeout_secs: u64) -> String {
    let host = url.host_str().unwrap_or_default();
    let port = url.port_or_known_default().unwrap_or(0);
    let pool = if url.scheme() == "https" {
        "HTTPSConnectionPool"
    } else {
        "HTTPConnectionPool"
    };
    let mut path = url.path().to_owned();
    if let Some(q) = url.query() {
        path.push('?');
        path.push_str(q);
    }
    let mut cause = e.to_string();
    let mut src: Option<&dyn std::error::Error> = std::error::Error::source(e);
    while let Some(s) = src {
        cause = s.to_string();
        src = s.source();
    }
    if e.is_timeout() {
        if e.is_connect() {
            return format!(
                "{pool}(host={}, port={port}): Max retries exceeded with url: {path} (Caused by ConnectTimeoutError({}))",
                config::str_repr(host),
                config::str_repr(&cause)
            );
        }
        return format!(
            "{pool}(host={}, port={port}): Read timed out. (read timeout={timeout_secs})",
            config::str_repr(host)
        );
    }
    format!(
        "{pool}(host={}, port={port}): Max retries exceeded with url: {path} (Caused by NewConnectionError({}))",
        config::str_repr(host),
        config::str_repr(&cause)
    )
}

/// `urllib.request.urlopen(ftp_url, timeout=t)` and `shutil.copyfileobj`
/// into `out`. Anonymous login unless the URL carries a user, binary
/// mode, passive mode with the control connection's address (Python's
/// `trust_server_pasv_ipv4_address = False`), one `CWD` per directory.
pub async fn ftp_download(
    url: &str,
    timeout: Duration,
    out: &mut (dyn std::io::Write + Send),
) -> Result<(), String> {
    use suppaftp::tokio::AsyncFtpStream;
    use suppaftp::types::FileType;

    let parsed = reqwest::Url::parse(url).map_err(|e| format!("<urlopen error {e}>"))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| "<urlopen error ftp error: no host given>".to_owned())?
        .to_owned();
    let port = parsed.port().unwrap_or(21);
    let user = percent_decode(parsed.username());
    let (user, password) = if user.is_empty() {
        ("anonymous".to_owned(), "anonymous@".to_owned())
    } else {
        (
            user,
            parsed.password().map(percent_decode).unwrap_or_default(),
        )
    };
    // urllib: dirs = path.split("/"), unquoted; the last is the file; a
    // leading empty part is dropped; then one CWD to the joined dirs
    // (ftplib turns '' into '.').
    let raw_path = parsed.path();
    let mut dirs: Vec<String> = raw_path.split('/').map(percent_decode).collect();
    let file = dirs.pop().unwrap_or_default();
    if dirs.first().is_some_and(String::is_empty) {
        dirs.remove(0);
    }
    let target = match dirs.join("/") {
        t if t.is_empty() => ".".to_owned(),
        t => t,
    };

    let urlopen = |e: String| format!("<urlopen error {e}>");
    let ftp_err = |e: suppaftp::FtpError| -> String {
        match e {
            suppaftp::FtpError::ConnectionError(io) => urlopen(os_error_text(&io, None)),
            suppaftp::FtpError::UnexpectedResponse(r) => {
                let body = String::from_utf8_lossy(&r.body).trim_end().to_owned();
                let kind = if body.starts_with('5') {
                    "error_perm"
                } else if body.starts_with('4') {
                    "error_temp"
                } else {
                    "error_reply"
                };
                urlopen(format!("ftp error: {kind}({})", config::str_repr(&body)))
            }
            other => urlopen(format!("ftp error: {other}")),
        }
    };
    let step = |r: Result<Result<(), String>, tokio::time::error::Elapsed>| -> Result<(), String> {
        match r {
            Ok(v) => v,
            Err(_) => Err(urlopen(messages::TIMED_OUT.to_owned())),
        }
    };

    let stream = connect(&host, port, timeout)
        .await
        .map_err(|e| urlopen(e.message().to_owned()))?;
    let mut ftp =
        match tokio::time::timeout(timeout, AsyncFtpStream::connect_with_stream(stream)).await {
            Ok(Ok(f)) => f,
            Ok(Err(e)) => return Err(ftp_err(e)),
            Err(_) => return Err(urlopen(messages::TIMED_OUT.to_owned())),
        };
    ftp.set_passive_nat_workaround(true);
    step(
        tokio::time::timeout(timeout, async {
            ftp.login(user.as_str(), password.as_str())
                .await
                .map_err(ftp_err)
        })
        .await,
    )?;
    step(tokio::time::timeout(timeout, async { ftp.cwd(&target).await.map_err(ftp_err) }).await)?;
    step(
        tokio::time::timeout(timeout, async {
            ftp.transfer_type(FileType::Binary).await.map_err(ftp_err)
        })
        .await,
    )?;
    let mut data = match tokio::time::timeout(timeout, ftp.retr_as_stream(&file)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(ftp_err(e)),
        Err(_) => return Err(urlopen(messages::TIMED_OUT.to_owned())),
    };
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        match tokio::time::timeout(timeout, data.read(&mut buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => out
                .write_all(&buf[..n])
                .map_err(|e| os_error_text(&e, None))?,
            Ok(Err(e)) => return Err(os_error_text(&e, None)),
            Err(_) => return Err(messages::TIMED_OUT.to_owned()),
        }
    }
    let _ = tokio::time::timeout(timeout, data.finish()).await;
    let _ = tokio::time::timeout(timeout, ftp.quit()).await;
    Ok(())
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && i + 2 < b.len()
            && let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2]))
        {
            out.push(h * 16 + l);
            i += 3;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backslashreplace() {
        assert_eq!(decode_backslashreplace(b"a\xffb\xc3\xa9"), "a\\xffb\u{e9}");
    }

    #[test]
    fn percent() {
        assert_eq!(percent_decode("/a%20b/c%2"), "/a b/c%2");
    }

    #[test]
    fn ca_bundle_from_the_environment() {
        let dir = tempfile::tempdir().expect("dir");
        let missing = dir.path().join("none.pem");
        assert_eq!(
            root_store_from(Some(missing.clone().into_os_string())).err(),
            Some(PyErr::Os(format!(
                "Could not find a suitable TLS CA certificate bundle, invalid path: {}",
                missing.display()
            )))
        );
        let builtin = root_store_from(None).expect("built in");
        assert_eq!(builtin.len(), webpki_roots::TLS_SERVER_ROOTS.len());
    }

    #[tokio::test]
    async fn resolves_literals_without_dns() {
        let a = resolve("127.0.0.1", 43).await.expect("literal");
        assert_eq!(a, vec!["127.0.0.1:43".parse().expect("addr")]);
        let a = resolve("[::1]", 43).await.expect("literal");
        assert_eq!(a, vec!["[::1]:43".parse().expect("addr")]);
    }
}
