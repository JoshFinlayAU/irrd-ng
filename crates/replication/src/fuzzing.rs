//! Entry points for the fuzz targets in `fuzz/`. Not a stable API.

use std::io::Cursor;
use std::pin::pin;
use std::task::{Context, Poll, Waker};

use crate::protocol::{self, Conn, Kind};

/// Run a future that never waits: every stream here is in memory.
fn now<F: Future>(f: F) -> Option<F::Output> {
    let mut cx = Context::from_waker(Waker::noop());
    match pin!(f).poll(&mut cx) {
        Poll::Ready(v) => Some(v),
        Poll::Pending => None,
    }
}

/// Decode a byte stream the way each end does: frames first, then each
/// frame's payload by its kind, and the log entries and snapshot rows
/// inside them.
///
/// The first byte picks the mode. Odd: `data` is raw bytes from an
/// unauthenticated peer, read before the handshake. Even: the rest is a
/// list of frames (kind byte, 2-byte length, payload) that this function
/// tags with a session key first, so the fuzzer reaches the payload parsers
/// behind the authentication check.
pub fn decode(data: &[u8]) {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    let key = [7u8; 32];
    let input = if mode & 1 == 1 {
        rest.to_vec()
    } else {
        let mut writer = Conn::new(Cursor::new(Vec::new()));
        writer.set_key(key);
        let mut r = rest;
        while let [kind, a, b, tail @ ..] = r {
            let n = usize::from(u16::from_be_bytes([*a, *b])).min(tail.len());
            let (payload, tail) = tail.split_at(n);
            let kind = match *kind % 10 {
                0 => Kind::Hello,
                1 => Kind::Challenge,
                2 => Kind::Auth,
                3 => Kind::Error,
                4 => Kind::SnapshotBegin,
                5 => Kind::SnapshotRows,
                6 => Kind::SnapshotEnd,
                7 => Kind::Entries,
                8 => Kind::Accept,
                _ => Kind::Heartbeat,
            };
            if now(writer.send(kind, payload)).is_none() {
                return;
            }
            r = tail;
        }
        writer.into_inner().into_inner()
    };
    let mut conn = Conn::new(Cursor::new(input));
    if mode & 1 == 0 {
        conn.set_key(key);
    }
    while let Some(Ok((kind, p))) = now(conn.recv()) {
        match kind {
            Kind::Hello => {
                let _ = protocol::parse_hello(&p);
            }
            Kind::Challenge => {
                let _ = protocol::parse_challenge_version(&p);
                let _ = protocol::parse_challenge(&p);
            }
            Kind::Auth => {
                if let Ok((body, _)) = protocol::split_auth(&p) {
                    let _ = protocol::parse_auth_position(body);
                }
            }
            Kind::Accept => {
                let _ = protocol::parse_accept(&p);
            }
            Kind::Error => {
                let _ = crate::messages::remote_text(&p);
            }
            Kind::SnapshotBegin | Kind::Heartbeat => {
                let _ = protocol::parse_position(&p);
            }
            Kind::SnapshotEnd => {
                let _ = protocol::parse_snapshot_end(&p);
            }
            Kind::SnapshotRows => {
                let mut c = Cursor::new(&p[..]);
                while let Ok(Some(_)) = store::replog::read_spool_row(&mut c) {}
            }
            Kind::Entries => {
                if let Ok((_, entries)) = protocol::parse_entries(&p) {
                    for (_, bytes) in entries {
                        let _ = store::replog::Entry::is_resync(&bytes);
                        let _ = store::replog::Entry::decode(&bytes);
                    }
                }
            }
        }
    }
}
