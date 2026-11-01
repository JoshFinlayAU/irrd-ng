//! The PID file: v4 holds `irrd.pid` in `piddir` with the `pid` library
//! (3.0.4), `PidFile(pidname="irrd", piddir=piddir)`. This is that
//! library's posix implementation: create the directory if needed, open
//! the file for appending, take an exclusive non-blocking `flock`, refuse
//! if the PID in the file is still running, then write `<pid>\n` with mode
//! 0644, and remove the file on exit.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use nix::errno::Errno;
use nix::fcntl::{AtFlags, Flock, FlockArg};
use nix::unistd::{AccessFlags, Pid};

/// Why the PID file could not be secured.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PidError {
    /// A `PidFileError`: v4 logs `Failed to start IRRd, unable to lock PID
    /// file irrd.pid in {piddir}: {this}` and stops.
    Locked(String),
    /// Any other exception (an `OSError`): v4's generic handler logs it.
    Other(String),
}

/// The held PID file. Dropping it removes the file, as the library's
/// `close()` does on exit.
#[derive(Debug)]
pub(crate) struct PidFile {
    path: PathBuf,
    _lock: Flock<File>,
}

impl Drop for PidFile {
    fn drop(&mut self) {
        if self.path.is_file() {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

fn effective_access(path: &Path, mode: AccessFlags) -> bool {
    nix::unistd::faccessat(nix::fcntl::AT_FDCWD, path, mode, AtFlags::AT_EACCESS).is_ok()
}

/// `str(OSError)`: `[Errno N] text`, with the file name when there is one.
fn os_error(e: &std::io::Error, path: Option<&Path>) -> String {
    let text = e.to_string();
    let text = text.split(" (os error").next().unwrap_or(&text).to_owned();
    match (e.raw_os_error(), path) {
        (Some(n), Some(p)) => format!(
            "[Errno {n}] {text}: {}",
            config::str_repr(&p.to_string_lossy())
        ),
        (Some(n), None) => format!("[Errno {n}] {text}"),
        _ => text,
    }
}

fn errno_text(e: Errno) -> String {
    os_error(&std::io::Error::from_raw_os_error(e as i32), None)
}

/// `PidFile(pidname="irrd", piddir=piddir).__enter__()`.
pub(crate) fn create(piddir: &str) -> Result<PidFile, PidError> {
    let dir = Path::new(piddir);
    if dir.exists() && !dir.is_dir() {
        return Err(PidError::Other(format!(
            "Pid file directory '{piddir}' exists but is not a directory"
        )));
    }
    if !dir.is_dir() {
        std::fs::create_dir_all(dir).map_err(|e| PidError::Other(os_error(&e, Some(dir))))?;
    }
    if !effective_access(dir, AccessFlags::R_OK) {
        return Err(PidError::Other(format!(
            "Pid file directory '{piddir}' cannot be read"
        )));
    }
    if !effective_access(dir, AccessFlags::W_OK | AccessFlags::X_OK) {
        return Err(PidError::Other(format!(
            "Pid file directory '{piddir}' cannot be written to"
        )));
    }
    let path = std::path::absolute(dir.join("irrd.pid")).unwrap_or_else(|_| dir.join("irrd.pid"));

    // open(filename, "a+")
    let file = std::fs::OpenOptions::new()
        .read(true)
        .append(true)
        .create(true)
        .open(&path)
        .map_err(|e| PidError::Other(os_error(&e, Some(&path))))?;
    let mut lock = Flock::lock(file, FlockArg::LockExclusiveNonblock)
        .map_err(|(_, e)| PidError::Locked(errno_text(e)))?;

    // _inner_check()
    let mut head = [0u8; 16];
    let _ = lock.seek(SeekFrom::Start(0));
    let n = lock.read(&mut head).unwrap_or(0);
    let text = String::from_utf8_lossy(&head[..n]);
    let pid_str = text.split('\n').next().unwrap_or_default().trim();
    if !pid_str.is_empty() {
        let pid = crate::argparse::py_int(pid_str).ok_or_else(|| {
            PidError::Locked(format!(
                "invalid literal for int() with base 10: {}",
                config::str_repr(pid_str)
            ))
        })?;
        match nix::sys::signal::kill(Pid::from_raw(pid as i32), None) {
            Ok(()) => {
                return Err(PidError::Locked(format!(
                    "Program already running with pid: {pid}"
                )));
            }
            Err(Errno::ESRCH) => {}
            Err(e) => return Err(PidError::Locked(errno_text(e))),
        }
    }

    let write = |f: &mut File| -> std::io::Result<()> {
        f.set_permissions(std::fs::Permissions::from_mode(0o644))?;
        f.set_len(0)?;
        f.write_all(format!("{}\n", std::process::id()).as_bytes())?;
        f.flush()
    };
    write(&mut lock).map_err(|e| PidError::Other(os_error(&e, Some(&path))))?;
    Ok(PidFile { path, _lock: lock })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn behaves_like_the_pid_library() {
        let dir = std::env::temp_dir().join(format!("irrd-ng-pidfile-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let piddir = dir.join("run");
        let p = piddir.to_string_lossy().into_owned();
        let pidfile = piddir.join("irrd.pid");

        // The directory is created, the file holds our PID with mode 0644.
        let held = create(&p).expect("create");
        assert_eq!(
            std::fs::read_to_string(&pidfile).expect("read"),
            format!("{}\n", std::process::id())
        );
        assert_eq!(
            std::fs::metadata(&pidfile)
                .expect("meta")
                .permissions()
                .mode()
                & 0o777,
            0o644
        );
        // A second instance cannot lock it.
        assert_eq!(
            create(&p).expect_err("locked"),
            PidError::Locked("[Errno 11] Resource temporarily unavailable".into())
        );
        // Released and removed on drop.
        drop(held);
        assert!(!pidfile.exists());

        // A stale file of a process that is not running is taken over; a
        // running one, or garbage, is refused.
        std::fs::write(&pidfile, "999999999\n").expect("write");
        drop(create(&p).expect("stale"));
        std::fs::write(&pidfile, "1\n").expect("write");
        assert!(matches!(
            create(&p).expect_err("running"),
            PidError::Locked(m) if m == "Program already running with pid: 1" || m.starts_with("[Errno 1]")
        ));
        std::fs::write(&pidfile, "abc\n").expect("write");
        assert_eq!(
            create(&p).expect_err("garbage"),
            PidError::Locked("invalid literal for int() with base 10: 'abc'".into())
        );

        std::fs::write(dir.join("file"), "").expect("write");
        assert_eq!(
            create(&dir.join("file").to_string_lossy()).expect_err("not a dir"),
            PidError::Other(format!(
                "Pid file directory '{}' exists but is not a directory",
                dir.join("file").display()
            ))
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
