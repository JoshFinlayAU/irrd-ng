//! The wire protocol between an active and a standby.
//!
//! One TCP connection, opened by the standby. Every message is a frame:
//! a 4-byte big-endian length, a kind byte and the payload. The length
//! counts the kind byte, the payload and, once the session is
//! authenticated, a 32-byte HMAC-SHA256 tag over a per-direction frame
//! counter, the kind and the payload, keyed with the session key.
//!
//! The handshake proves both ends know the shared secret without sending
//! it, and derives the session key from both ends' random nonces. The
//! secret itself is never used as a key: both ends stretch it once at
//! startup with Argon2id ([`SharedKey`]), so a guess at it costs an
//! Argon2id run, not one HMAC.
//!
//! 1. standby: `HELLO` (magic, protocol version, store schema version,
//!    nonce)
//! 2. active: `CHALLENGE` (protocol version, schema version, nonce), or
//!    `ERROR`. The active proves nothing yet, so a peer that does not know
//!    the secret learns nothing it could test guesses against.
//! 3. standby: `AUTH` (the log id and sequence it has applied, then its
//!    proof)
//! 4. active: `ACCEPT` (its own proof), or `ERROR`
//!
//! Each proof is an HMAC under the stretched key over a hash of the whole
//! handshake so far ([`Transcript`]): every frame's kind and payload,
//! versions and log position included. The session key covers the whole
//! handshake, both proofs included. Changing any byte of any handshake
//! frame on the way therefore fails authentication.
//!
//! After `ACCEPT` the active only sends: `SNAPSHOT_BEGIN`, `SNAPSHOT_ROWS`,
//! `SNAPSHOT_END`, `ENTRIES` and `HEARTBEAT`, or `ERROR` before closing.
//!
//! The frames are authenticated, and encrypted only when the connection
//! runs over TLS ([`crate::tls`]), which wraps this whole exchange.

use sha2::{Digest, Sha256};
use std::fmt;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::Error;

/// Bumped on any incompatible change. Version 2: the standby proves the
/// secret first, the proofs cover the whole handshake, and the secret is
/// stretched with Argon2id. `HELLO` keeps its layout across versions, so
/// either end can always tell the other which version it speaks.
pub const PROTOCOL_VERSION: u32 = 2;
/// The shortest shared secret either end accepts, in characters (the same
/// limit the configuration check applies to `ng_replication.secret`).
pub const MIN_SECRET_CHARS: usize = 16;
const MAGIC: &[u8] = b"IRRDNG-REPL";
const TAG_LEN: usize = 32;
/// The largest frame either side accepts.
pub const MAX_FRAME: usize = store::replog::MAX_ENTRY_BYTES + (1 << 20);
/// The largest frame either side accepts before the handshake has proved
/// the shared secret. Handshake frames are well under 1 KiB, so an
/// unauthenticated peer cannot make the other end buffer up to
/// [`MAX_FRAME`] bytes per connection.
pub const MAX_HANDSHAKE_FRAME: usize = 4096;

/// A byte stream a connection runs over: plain TCP, or TLS over TCP.
pub(crate) trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}
/// A boxed [`Io`].
pub(crate) type Stream = Box<dyn Io>;

/// Frame kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    Hello = 1,
    Challenge = 2,
    Auth = 3,
    Error = 4,
    Accept = 5,
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
            5 => Kind::Accept,
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

/// The shared secret, stretched with Argon2id. Derived once at startup:
/// each end needs only this, never the secret itself.
#[derive(Clone)]
pub struct SharedKey([u8; 32]);

impl fmt::Debug for SharedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SharedKey(..)")
    }
}

/// Argon2id parameters: 19 MiB, two passes, one lane (the OWASP minimum
/// for password storage). Part of the protocol: both ends must use the
/// same ones.
const KDF_MEMORY_KIB: u32 = 19 * 1024;
const KDF_PASSES: u32 = 2;
/// Both ends hold the same secret, so the salt only has to keep these keys
/// apart from any other use of it.
const KDF_SALT: &[u8] = b"irrd-ng replication v2";

impl SharedKey {
    /// Stretch `secret`. Takes a few tens of milliseconds on purpose; call
    /// it once, at startup.
    pub fn derive(secret: &[u8]) -> Result<SharedKey, Error> {
        let params = argon2::Params::new(KDF_MEMORY_KIB, KDF_PASSES, 1, Some(32))
            .map_err(|e| Error::Protocol(e.to_string()))?;
        let argon =
            argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
        let mut out = [0u8; 32];
        argon
            .hash_password_into(secret, KDF_SALT, &mut out)
            .map_err(|e| Error::Protocol(e.to_string()))?;
        Ok(SharedKey(out))
    }
}

/// A running hash of the handshake frames, in the order they were sent.
#[derive(Clone)]
pub(crate) struct Transcript(Sha256);

impl Transcript {
    pub(crate) fn new() -> Self {
        let mut h = Sha256::new();
        h.update(MAGIC);
        h.update(b" handshake v2");
        Transcript(h)
    }

    /// Add one frame: its kind and its length-prefixed payload.
    pub(crate) fn add(&mut self, kind: Kind, payload: &[u8]) {
        self.0.update([kind as u8]);
        self.0.update((payload.len() as u64).to_be_bytes());
        self.0.update(payload);
    }

    /// Add the standby's proof, once it has been sent or checked.
    pub(crate) fn add_proof(&mut self, proof: &[u8; 32]) {
        self.0.update(b"standby proof");
        self.0.update(proof);
    }

    fn hash(&self) -> [u8; 32] {
        self.0.clone().finalize().into()
    }

    /// The standby's proof: over `HELLO`, `CHALLENGE` and the part of
    /// `AUTH` before the proof, which the caller has added.
    pub(crate) fn standby_proof(&self, key: &SharedKey) -> [u8; 32] {
        hmac(&key.0, &[b"irrd-ng standby proof", &self.hash()])
    }

    /// The active's proof: over everything up to and including the
    /// standby's proof.
    pub(crate) fn active_proof(&self, key: &SharedKey) -> [u8; 32] {
        hmac(&key.0, &[b"irrd-ng active proof", &self.hash()])
    }

    /// The session key: over the whole handshake, `ACCEPT` included.
    pub(crate) fn session_key(&self, key: &SharedKey) -> [u8; 32] {
        hmac(&key.0, &[b"irrd-ng session", &self.hash()])
    }
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

    /// The underlying stream.
    pub(crate) fn into_inner(self) -> S {
        self.stream
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
        let max = if self.key.is_some() {
            MAX_FRAME
        } else {
            MAX_HANDSHAKE_FRAME
        };
        if !(min..=max).contains(&len) {
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

/// `HELLO`: protocol version, schema version and the standby's nonce.
pub(crate) fn parse_hello(p: &[u8]) -> Result<(u32, u32, [u8; 32]), Error> {
    let mut r = Reader(p);
    r.magic()?;
    Ok((r.u32()?, r.u32()?, r.array32()?))
}

/// `CHALLENGE`: the protocol version alone, which the standby checks
/// before it reads anything else, so a version mismatch is reported as
/// one whatever the rest looks like.
pub(crate) fn parse_challenge_version(p: &[u8]) -> Result<u32, Error> {
    Reader(p).u32()
}

/// `CHALLENGE`: protocol version, schema version and the active's nonce.
pub(crate) fn parse_challenge(p: &[u8]) -> Result<(u32, u32, [u8; 32]), Error> {
    let mut r = Reader(p);
    Ok((r.u32()?, r.u32()?, r.array32()?))
}

/// `AUTH`: the log id and sequence the standby has applied, then its
/// proof. Split into the part the proof covers and the proof, so the proof
/// is checked before anything else is looked at.
pub(crate) fn split_auth(p: &[u8]) -> Result<(&[u8], [u8; 32]), Error> {
    let Some(cut) = p.len().checked_sub(TAG_LEN) else {
        return Err(Error::Protocol("truncated frame".into()));
    };
    let mut proof = [0u8; 32];
    proof.copy_from_slice(&p[cut..]);
    Ok((&p[..cut], proof))
}

/// The part of `AUTH` before the proof.
pub(crate) fn parse_auth_position(p: &[u8]) -> Result<(String, u64), Error> {
    let mut r = Reader(p);
    Ok((r.str()?, r.u64()?))
}

/// `ACCEPT`: the active's proof.
pub(crate) fn parse_accept(p: &[u8]) -> Result<[u8; 32], Error> {
    Reader(p).array32()
}

/// `SNAPSHOT_BEGIN` and `HEARTBEAT`: a log id and a sequence.
pub(crate) fn parse_position(p: &[u8]) -> Result<(String, u64), Error> {
    let mut r = Reader(p);
    Ok((r.str()?, r.u64()?))
}

/// `SNAPSHOT_END`: the number of rows sent.
pub(crate) fn parse_snapshot_end(p: &[u8]) -> Result<u64, Error> {
    Reader(p).u64()
}

/// Log entries: (sequence, encoded entry).
pub(crate) type Entries = Vec<(u64, Vec<u8>)>;

/// `ENTRIES`: a log id and a counted list of (sequence, entry blob).
pub(crate) fn parse_entries(p: &[u8]) -> Result<(String, Entries), Error> {
    let mut r = Reader(p);
    let id = r.str()?;
    let n = r.u32()? as usize;
    // Each entry takes at least 12 bytes, so the count cannot make this
    // reserve more than the frame could hold.
    let mut entries = Vec::with_capacity(n.min(r.0.len() / 12));
    for _ in 0..n {
        let seq = r.u64()?;
        entries.push((seq, r.blob()?.to_vec()));
    }
    Ok((id, entries))
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

    #[test]
    fn shared_key_is_stretched_and_redacted() {
        let a = SharedKey::derive(b"a shared secret of some length").expect("derive");
        let b = SharedKey::derive(b"a shared secret of some length").expect("derive");
        let c = SharedKey::derive(b"a shared secret of some lengtH").expect("derive");
        assert_eq!(a.0, b.0);
        assert_ne!(a.0, c.0);
        // Not a plain hash or HMAC of the secret.
        assert_ne!(a.0, hmac(b"a shared secret of some length", &[KDF_SALT]));
        let shown = format!("{a:?}");
        assert_eq!(shown, "SharedKey(..)");
    }

    /// Every handshake byte is covered, each proof is bound to its role,
    /// and the active's proof and the session key cover the standby's
    /// proof.
    #[test]
    fn proofs_cover_the_whole_transcript() {
        let key = SharedKey::derive(b"a shared secret of some length").expect("derive");
        let other = SharedKey::derive(b"another secret of some length!").expect("derive");
        let hello = hello(7, &[1; 32]);
        let challenge = Writer::default()
            .u32(PROTOCOL_VERSION)
            .u32(7)
            .bytes(&[2; 32])
            .0;
        let auth = Writer::default().str("log").u64(42).0;
        let run = |hello: &[u8], challenge: &[u8], auth: &[u8]| {
            let mut t = Transcript::new();
            t.add(Kind::Hello, hello);
            t.add(Kind::Challenge, challenge);
            t.add(Kind::Auth, auth);
            t
        };
        let base = run(&hello, &challenge, &auth);
        let proof = base.standby_proof(&key);
        assert_ne!(proof, base.standby_proof(&other));
        assert_ne!(proof, base.active_proof(&key), "roles differ");
        let mut tampered = Vec::new();
        for i in 0..hello.len() {
            let mut h = hello.clone();
            h[i] ^= 1;
            tampered.push(run(&h, &challenge, &auth));
        }
        for i in 0..challenge.len() {
            let mut c = challenge.clone();
            c[i] ^= 1;
            tampered.push(run(&hello, &c, &auth));
        }
        for i in 0..auth.len() {
            let mut a = auth.clone();
            a[i] ^= 1;
            tampered.push(run(&hello, &challenge, &a));
        }
        let mut longer = hello.clone();
        longer.push(0);
        tampered.push(run(&longer, &challenge, &auth));
        // Moving a byte from one frame to the next changes the proof too.
        tampered.push(run(
            &hello[..hello.len() - 1],
            &[&hello[hello.len() - 1..], &challenge[..]].concat(),
            &auth,
        ));
        for t in &tampered {
            assert_ne!(t.standby_proof(&key), proof);
        }
        let mut after = base.clone();
        after.add_proof(&proof);
        let mut wrong = base;
        wrong.add_proof(&[0; 32]);
        assert_ne!(after.active_proof(&key), wrong.active_proof(&key));
        let accept = after.active_proof(&key);
        let mut done = after.clone();
        done.add(Kind::Accept, &accept);
        assert_ne!(done.session_key(&key), after.session_key(&key));
        assert_ne!(done.session_key(&key), accept);
    }

    #[test]
    fn auth_splits_off_the_proof() {
        let p = Writer::default().str("id").u64(9).bytes(&[5; 32]).0;
        let (body, proof) = split_auth(&p).expect("split");
        assert_eq!(proof, [5; 32]);
        assert_eq!(
            parse_auth_position(body).expect("position"),
            ("id".into(), 9)
        );
        assert!(split_auth(&[0; 31]).is_err());
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
