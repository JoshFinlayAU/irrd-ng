//! The file handling v4's serving code gets from Python's standard
//! library: `gzip.open()`, `NamedTemporaryFile`, `shutil.move`,
//! `secrets.token_hex` and `pathlib.Path` joins.
//!
//! The gzip streams are byte-identical to CPython's for the same header
//! fields: level 9 through the same zlib (1.3.1), `XFL` 2, `OS` 255, and
//! the `FNAME` and `MTIME` fields `gzip.open()` writes.

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

/// `secrets.token_hex(n)`: `n` random bytes, lower-case hex.
pub fn token_hex(n: usize) -> std::io::Result<String> {
    let mut buf = vec![0u8; n];
    getrandom::fill(&mut buf).map_err(|e| std::io::Error::other(e.to_string()))?;
    Ok(buf.iter().map(|b| format!("{b:02x}")).collect())
}

/// A name from `tempfile`'s `_RandomNameSequence`: `tmp` and eight
/// characters from `[a-z0-9_]`.
pub fn tmp_name() -> std::io::Result<String> {
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789_";
    let mut buf = [0u8; 8];
    getrandom::fill(&mut buf).map_err(|e| std::io::Error::other(e.to_string()))?;
    let mut out = String::from("tmp");
    for b in buf {
        // 37 characters; the slight bias does not matter for a file name.
        out.push(CHARS[usize::from(b) % CHARS.len()] as char);
    }
    Ok(out)
}

/// `str(Path(dir) / name)`: repeated and trailing slashes and `.`
/// components go, as `pathlib` normalises them.
pub fn py_path_join(dir: &str, name: &str) -> String {
    let mut out = String::new();
    if dir.starts_with('/') {
        out.push('/');
        // POSIX keeps exactly two leading slashes, pathlib too.
        if dir.starts_with("//") && !dir.starts_with("///") {
            out.push('/');
        }
    }
    let mut first = true;
    for part in dir.split('/').chain(std::iter::once(name)) {
        if part.is_empty() || part == "." {
            continue;
        }
        if !first {
            out.push('/');
        }
        out.push_str(part);
        first = false;
    }
    out
}

/// `str(Path(p))`.
pub fn py_path(p: &str) -> String {
    let joined = py_path_join(p, "");
    if joined.is_empty() {
        ".".to_owned()
    } else {
        joined
    }
}

/// Seconds since the epoch, as `int(time.time())`.
fn unix_now() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0)
}

/// A file opened with `gzip.open(path, "wb")`.
pub struct PyGzipWriter {
    inner: flate2::write::GzEncoder<BufWriter<File>>,
}

impl std::fmt::Debug for PyGzipWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PyGzipWriter")
    }
}

impl PyGzipWriter {
    /// Create (or truncate) `path`. Like CPython, the header carries the
    /// base name of `path` without a `.gz` suffix and the current time.
    pub fn create(path: &Path) -> std::io::Result<PyGzipWriter> {
        let file = File::create(path)?;
        let mut name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        if let Some(stripped) = name.strip_suffix(".gz") {
            name = stripped.to_owned();
        }
        let mut builder = flate2::GzBuilder::new().mtime(unix_now());
        if !name.is_empty() {
            builder = builder.filename(name.into_bytes());
        }
        Ok(PyGzipWriter {
            inner: builder.write(
                BufWriter::with_capacity(128 * 1024, file),
                flate2::Compression::best(),
            ),
        })
    }

    /// Write the trailer and flush everything to the file.
    pub fn finish(self) -> std::io::Result<()> {
        let mut w = self.inner.finish()?;
        w.flush()?;
        w.into_inner().map_err(|e| e.into_error())?.sync_all()
    }
}

impl Write for PyGzipWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// `NamedTemporaryFile(delete=False).name`: a new, empty file in the
/// temporary directory (`TMPDIR`, else `/tmp`), mode 0600.
pub fn named_temporary_file() -> std::io::Result<PathBuf> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let dir = std::env::temp_dir();
    loop {
        let path = dir.join(tmp_name()?);
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
        {
            Ok(_) => return Ok(path),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
}

/// `shutil.move(src, dst)` for a file: rename, or copy with permissions
/// and modification time and remove the source when the rename crosses
/// file systems.
pub fn shutil_move(src: &Path, dst: &Path) -> std::io::Result<()> {
    match std::fs::rename(src, dst) {
        Ok(()) => Ok(()),
        Err(e) if e.raw_os_error() == Some(18) => {
            std::fs::copy(src, dst)?;
            let modified = std::fs::metadata(src)?.modified()?;
            File::options()
                .write(true)
                .open(dst)?
                .set_modified(modified)?;
            std::fs::remove_file(src)
        }
        Err(e) => Err(e),
    }
}

/// `chmod(path, mode)`.
pub fn chmod(path: &Path, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

/// `file_hash_sha256(path).hexdigest()`.
pub fn sha256_hex(path: &Path) -> std::io::Result<String> {
    use sha2::Digest as _;
    let mut f = File::open(path)?;
    let mut h = sha2::Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = std::io::Read::read(&mut f, &mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::io::Read as _;

    #[test]
    fn pathlib_joins() {
        assert_eq!(
            py_path_join("/srv/exports/", "a.db.gz"),
            "/srv/exports/a.db.gz"
        );
        assert_eq!(py_path_join("/srv//./x", "a"), "/srv/x/a");
        assert_eq!(py_path_join("rel", "a"), "rel/a");
        assert_eq!(py_path("/srv/nrtm4/"), "/srv/nrtm4");
        assert_eq!(py_path("//x"), "//x");
    }

    #[test]
    fn tokens() {
        let t = token_hex(16).unwrap();
        assert_eq!(t.len(), 32);
        assert!(t.bytes().all(|b| b.is_ascii_hexdigit()));
        let n = tmp_name().unwrap();
        assert_eq!(n.len(), 11);
        assert!(n.starts_with("tmp"));
    }

    /// The header and stream `gzip.open(path, "wb")` writes in CPython 3.13
    /// with zlib 1.3.1 for `b"hello\n" * 3`, apart from the MTIME bytes.
    #[test]
    fn gzip_like_cpython() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x.json.gz");
        let mut w = PyGzipWriter::create(&path).unwrap();
        w.write_all(b"hello\n").unwrap();
        w.write_all(b"hello\nhello\n").unwrap();
        w.finish().unwrap();
        let mut bytes = Vec::new();
        File::open(&path).unwrap().read_to_end(&mut bytes).unwrap();
        assert_eq!(&bytes[..4], b"\x1f\x8b\x08\x08");
        assert_eq!(&bytes[8..17], b"\x02\xffx.json\x00");
        assert_eq!(&bytes[17..26], b"\xcbH\xcd\xc9\xc9\xe7\xca@\"");
    }
}
