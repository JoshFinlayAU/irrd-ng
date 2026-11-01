//! The wire protocol between an active and a standby.
//!
//! One TCP connection, opened by the standby. Every message is a frame:
//! a 4-byte big-endian length, a kind byte and the payload. The length
//! counts the kind byte, the payload and, once the session is
//! authenticated, a 32-byte HMAC-SHA256 tag over a per-direction frame
//! counter, the kind and the payload, keyed with the session key.
//!
//! The handshake proves both ends know the shared secret without sending
//! it, and derives the session key from both ends' random nonces:
//!
//! 1. standby: `HELLO` (magic, protocol version, store schema version,
//!    nonce)
//! 2. active: `CHALLENGE` (protocol version, schema version, nonce, the
//!    active's proof), or `ERROR`
//! 3. standby: `AUTH` (the standby's proof, the log id and sequence it has
//!    applied)
//!
//! After that the active only sends: `SNAPSHOT_BEGIN`, `SNAPSHOT_ROWS`,
//! `SNAPSHOT_END`, `ENTRIES` and `HEARTBEAT`, or `ERROR` before closing.
//! The data is authenticated, not encrypted.

use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::Error;

/// Bumped on any incompatible change.
pub const PROTOCOL_VERSION: u32 = 1;
const MAGIC: &[u8] = b"IRRDNG-REPL";
const TAG_LEN: usize = 32;
/// The largest frame either side accepts.
pub const MAX_FRAME: usize = store::replog::MAX_ENTRY_BYTES + (1 << 20);

/// Frame kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    Hello = 1,
    Challenge = 2,
    Auth = 3,
    Error = 4,
    SnapshotBegin = 10,
    SnapshotRows = 11,
    SnapshotEnd = 12,
    Entries = 20,
    Heartbeat = 30,
}

impl Kind {
    fn from_u8(b: u8) -> Option<Kind> {
        Some(match b {
            1 => Kind::Hello,
            2 => Kind::Challenge,
            3 => Kind::Auth,
            4 => Kind::Error,
            10 => Kind::SnapshotBegin,
            11 => Kind::SnapshotRows,
            12 => Kind::SnapshotEnd,
            20 => Kind::Entries,
            30 => Kind::Heartbeat,
            _ => return None,
        })
    }
}

/// HMAC-SHA256 (RFC 2104) over the concatenation of `parts`.
pub fn hmac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        k[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha256::new();
    inner.update(k.map(|b| b ^ 0x36));
    for p in parts {
        inner.update(p);
    }
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(k.map(|b| b ^ 0x5c));
    outer.update(inner);
    outer.finalize().into()
}

/// Compare without an early exit.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

pub(crate) fn nonce() -> Result<[u8; 32], Error> {
    let mut n = [0u8; 32];
    getrandom::fill(&mut n).map_err(|e| Error::Io(std::io::Error::other(e.to_string())))?;
    Ok(n)
}

pub(crate) fn server_proof(secret: &[u8], cn: &[u8; 32], sn: &[u8; 32]) -> [u8; 32] {
    hmac(secret, &[b"irrd-ng server", cn, sn])
}

pub(crate) fn client_proof(secret: &[u8], cn: &[u8; 32], sn: &[u8; 32]) -> [u8; 32] {
    hmac(secret, &[b"irrd-ng client", cn, sn])
}

pub(crate) fn session_key(secret: &[u8], cn: &[u8; 32], sn: &[u8; 32]) -> [u8; 32] {
    hmac(secret, &[b"irrd-ng session", cn, sn])
}

/// One end of a connection: frames in and out, tagged once a session key
/// is set.
pub(crate) struct Conn<S> {
    stream: S,
    key: Option<[u8; 32]>,
    sent: u64,
    received: u64,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Conn<S> {
    pub(crate) fn new(stream: S) -> Self {
        Conn {
            stream,
            key: None,
            sent: 0,
            received: 0,
        }
    }

    pub(crate) fn set_key(&mut self, key: [u8; 32]) {
        self.key = Some(key);
    }

    fn tag(&self, counter: u64, kind: u8, payload: &[u8]) -> Option<[u8; 32]> {
        self.key
            .map(|k| hmac(&k, &[&counter.to_be_bytes(), &[kind], payload]))
    }

    pub(crate) async fn send(&mut self, kind: Kind, payload: &[u8]) -> Result<(), Error> {
        let tag = self.tag(self.sent, kind as u8, payload);
        let len = 1 + payload.len() + tag.map_or(0, |_| TAG_LEN);
        if len > MAX_FRAME {
            return Err(Error::Protocol(format!(
                "frame of {len} bytes is too large"
            )));
        }
        let mut head = [0u8; 5];
        head[..4].copy_from_slice(&(len as u32).to_be_bytes());
        head[4] = kind as u8;
        self.stream.write_all(&head).await?;
        self.stream.write_all(payload).await?;
        if let Some(t) = tag {
            self.stream.write_all(&t).await?;
        }
        self.stream.flush().await?;
        self.sent += 1;
        Ok(())
    }

    /// Wait until the other end closes the connection (or sends anything,
    /// which a standby never does after the handshake). Cancel-safe.
    pub(crate) async fn closed(&mut self) {
        let mut b = [0u8; 1];
        let _ = self.stream.read(&mut b).await;
    }

    pub(crate) async fn recv(&mut self) -> Result<(Kind, Vec<u8>), Error> {
        let mut len = [0u8; 4];
        self.stream.read_exact(&mut len).await?;
        let len = u32::from_be_bytes(len) as usize;
        let min = 1 + self.key.map_or(0, |_| TAG_LEN);
        if !(min..=MAX_FRAME).contains(&len) {
            return Err(Error::Protocol(format!("bad frame length {len}")));
        }
        let mut buf = vec![0u8; len];
        self.stream.read_exact(&mut buf).await?;
        let kind = buf[0];
        let body_end = len - (min - 1);
        if self.key.is_some() {
            let expect = self.tag(self.received, kind, &buf[1..body_end]);
            let ok = expect.is_some_and(|e| constant_time_eq(&e, &buf[body_end..]));
            if !ok {
                return Err(Error::Protocol("frame failed authentication".into()));
            }
        }
        self.received += 1;
        let kind = Kind::from_u8(kind)
            .ok_or_else(|| Error::Protocol(format!("unknown frame kind {kind}")))?;
        buf.truncate(body_end);
        buf.remove(0);
        Ok((kind, buf))
    }
}

/// Payload building and parsing.
#[derive(Debug, Default)]
pub(crate) struct Writer(pub(crate) Vec<u8>);

impl Writer {
    pub(crate) fn u32(mut self, v: u32) -> Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }
    pub(crate) fn u64(mut self, v: u64) -> Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }
    pub(crate) fn bytes(mut self, v: &[u8]) -> Self {
        self.0.extend_from_slice(v);
        self
    }
    pub(crate) fn str(mut self, v: &str) -> Self {
        let len = u16::try_from(v.len()).unwrap_or(u16::MAX);
        self.0.extend_from_slice(&len.to_be_bytes());
        self.0.extend_from_slice(&v.as_bytes()[..usize::from(len)]);
        self
    }
    pub(crate) fn blob(mut self, v: &[u8]) -> Self {
        self.0.extend_from_slice(&(v.len() as u32).to_be_bytes());
        self.0.extend_from_slice(v);
        self
    }
}

#[derive(Debug)]
pub(crate) struct Reader<'a>(pub(crate) &'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if self.0.len() < n {
            return Err(Error::Protocol("truncated frame".into()));
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }
    pub(crate) fn u16(&mut self) -> Result<u16, Error> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
    pub(crate) fn u32(&mut self) -> Result<u32, Error> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
    pub(crate) fn u64(&mut self) -> Result<u64, Error> {
        let mut a = [0u8; 8];
        a.copy_from_slice(self.take(8)?);
        Ok(u64::from_be_bytes(a))
    }
    pub(crate) fn array32(&mut self) -> Result<[u8; 32], Error> {
        let mut a = [0u8; 32];
        a.copy_from_slice(self.take(32)?);
        Ok(a)
    }
    pub(crate) fn str(&mut self) -> Result<String, Error> {
        let n = usize::from(self.u16()?);
        Ok(String::from_utf8_lossy(self.take(n)?).into_owned())
    }
    pub(crate) fn blob(&mut self) -> Result<&'a [u8], Error> {
        let n = self.u32()? as usize;
        self.take(n)
    }
    pub(crate) fn magic(&mut self) -> Result<(), Error> {
        if self.take(MAGIC.len())? != MAGIC {
            return Err(Error::Protocol("not an irrd-ng replication client".into()));
        }
        Ok(())
    }
}

pub(crate) fn hello(schema: u32, cn: &[u8; 32]) -> Vec<u8> {
    Writer::default()
        .bytes(MAGIC)
        .u32(PROTOCOL_VERSION)
        .u32(schema)
        .bytes(cn)
        .0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_rfc4231() {
        // RFC 4231 test case 2.
        let tag = hmac(b"Jefe", &[b"what do ya want ", b"for nothing?"]);
        let hex: String = tag.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        // Test case 6: a key longer than the block size.
        let tag = hmac(
            &[0xaa; 131],
            &[b"Test Using Larger Than Block-Size Key - Hash Key First"],
        );
        let hex: String = tag.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    #[tokio::test]
    async fn frames_are_tagged_and_checked() {
        let (a, b) = tokio::io::duplex(1 << 16);
        let (mut a, mut b) = (Conn::new(a), Conn::new(b));
        a.send(Kind::Hello, b"plain").await.expect("send");
        assert_eq!(
            b.recv().await.expect("recv"),
            (Kind::Hello, b"plain".to_vec())
        );
        a.set_key([7; 32]);
        b.set_key([7; 32]);
        a.send(Kind::Entries, b"one").await.expect("send");
        a.send(Kind::Heartbeat, b"").await.expect("send");
        assert_eq!(
            b.recv().await.expect("recv"),
            (Kind::Entries, b"one".to_vec())
        );
        assert_eq!(b.recv().await.expect("recv"), (Kind::Heartbeat, Vec::new()));
        // A different key fails the tag.
        b.set_key([8; 32]);
        a.send(Kind::Entries, b"two").await.expect("send");
        assert!(b.recv().await.is_err());
    }
}
