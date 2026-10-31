//! `irrd/mirroring/retrieval.py`: fetch a file over HTTP(S) or FTP, or
//! from local disk, gunzip it if the name ends in `.gz`, and check its
//! SHA-256 hash.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use sha2::{Digest, Sha256};

use crate::messages;
use crate::mirror::net;
use crate::mirror::pyerr::{PyErr, os_error};

/// v4's logger name.
pub const LOG_TARGET: &str = "irrd.mirroring.retrieval";

/// A retrieved file: a temporary copy (deleted when dropped, as v4
/// unlinks it), or a local file used in place.
#[derive(Debug)]
pub enum LocalFile {
    /// A temporary file.
    Temp(tempfile::TempPath),
    /// A local file, read where it is.
    Existing(PathBuf),
}

impl LocalFile {
    /// The path to read.
    pub fn path(&self) -> &Path {
        match self {
            LocalFile::Temp(t) => t,
            LocalFile::Existing(p) => p,
        }
    }

    /// The name v4 logs and uses in errors (`NamedTemporaryFile().name`).
    pub fn name(&self) -> String {
        self.path().to_string_lossy().into_owned()
    }
}

/// `urlparse(url)`: scheme (lower case), netloc and path, as Python 3.13
/// splits them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UrlParts {
    /// `scheme`, lower-cased; empty if there is none.
    pub scheme: String,
    /// `netloc`
    pub netloc: String,
    /// `path`
    pub path: String,
}

/// `urllib.parse.urlparse`, enough of it for the scheme, netloc and path.
pub fn urlparse(url: &str) -> UrlParts {
    let url: String = url
        .trim_matches(|c: char| c <= ' ')
        .chars()
        .filter(|c| !matches!(c, '\t' | '\r' | '\n'))
        .collect();
    let mut rest: &str = &url;
    let mut scheme = String::new();
    if let Some(i) = url.find(':')
        && i > 0
        && url.as_bytes()[0].is_ascii_alphabetic()
        && url[..i]
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'+' | b'-' | b'.'))
    {
        scheme = url[..i].to_ascii_lowercase();
        rest = &url[i + 1..];
    }
    let mut netloc = String::new();
    if let Some(r) = rest.strip_prefix("//") {
        let end = r.find(['/', '?', '#']).unwrap_or(r.len());
        netloc = r[..end].to_owned();
        rest = &r[end..];
    }
    let end = rest.find(['?', '#']).unwrap_or(rest.len());
    let mut path = rest[..end].to_owned();
    // urlparse splits ";params" off the last path segment for these
    // schemes; the path v4 uses excludes them.
    if matches!(
        scheme.as_str(),
        "" | "ftp"
            | "http"
            | "https"
            | "file"
            | "hdl"
            | "rtsp"
            | "rtspu"
            | "sip"
            | "sips"
            | "mms"
            | "sftp"
            | "tel"
    ) && let Some(slash) = path.rfind('/').map(|s| s + 1).or(Some(0))
        && let Some(semi) = path[slash..].find(';')
    {
        path.truncate(slash + semi);
    }
    UrlParts {
        scheme,
        netloc,
        path,
    }
}

/// Downloads and local reads, as v4's `retrieve_file`.
#[derive(Debug, Clone)]
pub struct Retriever {
    http: reqwest::Client,
    timeout: Duration,
}

impl Retriever {
    /// `download_timeout` seconds for connecting and each read.
    pub fn new(download_timeout: u64) -> Result<Retriever, PyErr> {
        let timeout = Duration::from_secs(download_timeout);
        Ok(Retriever {
            http: net::http_client(timeout)?,
            timeout,
        })
    }

    /// `retrieve_file(url, return_contents=True)`: the contents, decoded
    /// as UTF-8 and stripped.
    pub async fn contents(&self, url: &str) -> Result<String, PyErr> {
        let parts = urlparse(url);
        match parts.scheme.as_str() {
            "ftp" | "http" | "https" => {
                let mut buf: Vec<u8> = Vec::new();
                self.download(url, &parts, &mut buf).await?;
                let text = decode_utf8(&buf)?;
                tracing::info!(target: LOG_TARGET, "{}", messages::downloaded(url));
                Ok(rpsl::text::py_strip(&text).to_owned())
            }
            "file" => {
                let path = parts.path.clone();
                let bytes = std::fs::read(&path).map_err(|e| os_error(&e, Some(&path)))?;
                let text = decode_utf8(&bytes)?;
                let text = text.replace("\r\n", "\n").replace('\r', "\n");
                Ok(rpsl::text::py_strip(&text).to_owned())
            }
            other => Err(PyErr::Value(messages::invalid_url_scheme(url, other))),
        }
    }

    /// `retrieve_file(url, return_contents=False, expected_hash=...)`: a
    /// local file with the (gunzipped) contents.
    pub async fn file(&self, url: &str, expected_hash: Option<&str>) -> Result<LocalFile, PyErr> {
        let parts = urlparse(url);
        match parts.scheme.as_str() {
            "ftp" | "http" | "https" => {
                let mut tmp = new_temp()?;
                self.download(url, &parts, tmp.as_file_mut()).await?;
                tmp.as_file_mut().flush().map_err(|e| os_error(&e, None))?;
                let tmp = tmp.into_temp_path();
                let name = tmp.to_string_lossy().into_owned();
                let downloaded = LocalFile::Temp(tmp);
                check_file_hash_sha256(downloaded.path(), &name, expected_hash)?;
                let result = if url.ends_with(".gz") {
                    let unzipped = gunzip(downloaded.path())?;
                    drop(downloaded);
                    unzipped
                } else {
                    downloaded
                };
                tracing::info!(target: LOG_TARGET, "{}", messages::downloaded_to(url, &result.name()));
                Ok(result)
            }
            "file" => {
                let path = parts.path.clone();
                check_file_hash_sha256(Path::new(&path), &path, expected_hash)?;
                if path.ends_with(".gz") {
                    tracing::debug!(target: LOG_TARGET, "{}", messages::local_gunzip(&path));
                    gunzip(Path::new(&path))
                } else {
                    Ok(LocalFile::Existing(PathBuf::from(path)))
                }
            }
            other => Err(PyErr::Value(messages::invalid_url_scheme(url, other))),
        }
    }

    async fn download(
        &self,
        url: &str,
        parts: &UrlParts,
        out: &mut (dyn std::io::Write + Send),
    ) -> Result<(), PyErr> {
        if parts.scheme == "ftp" {
            return net::ftp_download(url, self.timeout, out)
                .await
                .map_err(|e| PyErr::Os(messages::failed_to_download(url, &e)));
        }
        let parsed = reqwest::Url::parse(url).map_err(|e| PyErr::Value(e.to_string()))?;
        let secs = self.timeout.as_secs();
        let mut resp = self
            .http
            .get(parsed.clone())
            .send()
            .await
            .map_err(|e| PyErr::Os(net::requests_error_text(&parsed, &e, secs)))?;
        let status = resp.status().as_u16();
        if status != 200 {
            let body = resp.bytes().await.unwrap_or_default();
            return Err(PyErr::Os(messages::failed_to_download(
                url,
                &format!("{status}: {}", config::bytes_repr(&body)),
            )));
        }
        loop {
            match resp.chunk().await {
                Ok(Some(c)) => out.write_all(&c).map_err(|e| os_error(&e, None))?,
                Ok(None) => break,
                Err(e) => return Err(PyErr::Os(net::requests_error_text(&parsed, &e, secs))),
            }
        }
        Ok(())
    }
}

fn new_temp() -> Result<tempfile::NamedTempFile, PyErr> {
    tempfile::NamedTempFile::new().map_err(|e| os_error(&e, None))
}

/// `gzip.open(path)` copied into a new temporary file.
fn gunzip(path: &Path) -> Result<LocalFile, PyErr> {
    let name = path.to_string_lossy().into_owned();
    let f = std::fs::File::open(path).map_err(|e| os_error(&e, Some(&name)))?;
    let mut dec = flate2::read::MultiGzDecoder::new(std::io::BufReader::new(f));
    let mut tmp = new_temp()?;
    match std::io::copy(&mut dec, tmp.as_file_mut()) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Err(PyErr::Other(messages::GZIP_EOF.to_owned()));
        }
        Err(e) if e.kind() == std::io::ErrorKind::InvalidInput || e.raw_os_error().is_none() => {
            let head = std::fs::read(path)
                .map(|b| b.into_iter().take(2).collect::<Vec<u8>>())
                .unwrap_or_default();
            return Err(PyErr::Os(messages::not_gzipped(&config::bytes_repr(&head))));
        }
        Err(e) => return Err(os_error(&e, None)),
    }
    Ok(LocalFile::Temp(tmp.into_temp_path()))
}

/// `check_file_hash_sha256(filename, expected_hash)`.
pub fn check_file_hash_sha256(
    path: &Path,
    filename: &str,
    expected_hash: Option<&str>,
) -> Result<(), PyErr> {
    let Some(expected) = expected_hash.filter(|h| !h.is_empty()) else {
        return Ok(());
    };
    let digest = file_hash_sha256(path).map_err(|e| os_error(&e, Some(filename)))?;
    let wanted = bytes_fromhex(expected)?;
    if digest.as_slice() != wanted.as_slice() {
        return Err(PyErr::Value(messages::invalid_hash(
            filename,
            expected,
            &hex(&digest),
        )));
    }
    Ok(())
}

/// The SHA-256 digest of a file.
pub fn file_hash_sha256(path: &Path) -> std::io::Result<Vec<u8>> {
    use std::io::Read as _;
    let mut f = std::fs::File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(h.finalize().to_vec())
}

/// Lower-case hex.
pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// `bytes.fromhex(s)`: pairs of hex digits, ASCII whitespace allowed
/// between them.
pub fn bytes_fromhex(s: &str) -> Result<Vec<u8>, PyErr> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    let digit = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
    while i < b.len() {
        if b[i].is_ascii_whitespace() {
            i += 1;
            continue;
        }
        let hi = digit(b[i]).ok_or_else(|| PyErr::Value(messages::fromhex_error(i)))?;
        let lo = b
            .get(i + 1)
            .and_then(|c| digit(*c))
            .ok_or_else(|| PyErr::Value(messages::fromhex_error(i + 1)))?;
        out.push(hi * 16 + lo);
        i += 2;
    }
    Ok(out)
}

/// `bytes.decode("utf-8")`, strict.
pub fn decode_utf8(bytes: &[u8]) -> Result<String, PyErr> {
    match std::str::from_utf8(bytes) {
        Ok(s) => Ok(s.to_owned()),
        Err(e) => {
            let pos = e.valid_up_to();
            let byte = bytes[pos];
            let reason = match e.error_len() {
                None => "unexpected end of data",
                Some(_) if (0xc2..=0xf4).contains(&byte) => "invalid continuation byte",
                Some(_) => "invalid start byte",
            };
            Err(PyErr::Value(messages::utf8_decode_error(byte, pos, reason)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urlparse_like_python() {
        let p = urlparse("FTP://host/a/b.gz");
        assert_eq!(p.scheme, "ftp");
        assert_eq!(p.netloc, "host");
        assert_eq!(p.path, "/a/b.gz");
        assert_eq!(urlparse("file:///tmp/x").path, "/tmp/x");
        assert_eq!(urlparse("file://host/tmp/x").path, "/tmp/x");
        assert_eq!(urlparse("/tmp/x").scheme, "");
        assert_eq!(urlparse("gopher://x").scheme, "gopher");
        assert_eq!(urlparse("1http://x").scheme, "");
    }

    #[test]
    fn fromhex() {
        assert_eq!(bytes_fromhex("ab cd").expect("hex"), vec![0xab, 0xcd]);
        assert_eq!(
            bytes_fromhex("abx"),
            Err(PyErr::Value(
                "non-hexadecimal number found in fromhex() arg at position 2".into()
            ))
        );
        assert!(bytes_fromhex("abc").is_err());
    }

    // From v4's test_retrieval.py and TestRPSLMirrorFullImportRunner:
    // unsupported schemes are a ValueError naming the scheme.
    #[tokio::test]
    async fn unsupported_scheme() {
        let r = Retriever::new(10).expect("client");
        let e = r.contents("gopher://host/x").await.expect_err("gopher");
        assert_eq!(
            e,
            PyErr::Value("Invalid URL: gopher://host/x - scheme gopher is not supported".into())
        );
    }

    #[tokio::test]
    async fn local_files_and_gzip() {
        let dir = tempfile::tempdir().expect("dir");
        let plain = dir.path().join("serial");
        std::fs::write(&plain, "424242\n").expect("write");
        let r = Retriever::new(10).expect("client");
        let url = format!("file://{}", plain.display());
        assert_eq!(r.contents(&url).await.expect("contents"), "424242");
        // gzipped data, contains 'source1' (v4's test data).
        let gz = dir.path().join("source1.rpsl.gz");
        let data = [
            0x1f, 0x8b, 0x08, 0x00, 0x4e, 0x02, 0x7c, 0x5b, 0x00, 0x03, 0x2b, 0xce, 0x2f, 0x2d,
            0x4a, 0x4e, 0x35, 0x04, 0x00, 0x4e, 0x45, 0x8f, 0x4a, 0x07, 0x00, 0x00, 0x00,
        ];
        std::fs::write(&gz, data).expect("write");
        let f = r
            .file(&format!("file://{}", gz.display()), None)
            .await
            .expect("gunzip");
        assert_eq!(std::fs::read(f.path()).expect("read"), b"source1");
        let tmp = f.path().to_owned();
        drop(f);
        assert!(!tmp.exists(), "temporary file removed");
        let f = r
            .file(&url, Some(&hex(&file_hash_sha256(&plain).expect("hash"))))
            .await
            .expect("hash ok");
        assert_eq!(f.path(), plain);
        let e = r.file(&url, Some("00")).await.expect_err("bad hash");
        assert!(e.message().starts_with("Invalid hash in "), "{e}");
    }
}
