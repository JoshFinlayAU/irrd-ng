//! PGP key handling for key-cert objects.
//!
//! v4 validates a key-cert by handing the `certif` text to GnuPG 2.4 through
//! python-gnupg (`gpg.import_keys`, then `gpg.list_keys`), and derives the
//! `fingerpr`, `owner` and `method` attributes from what gpg reports. This
//! module reproduces that pipeline without gpg:
//!
//! 1. python-gnupg encodes the text as Latin-1 ([`Keyring::import_keys`]).
//! 2. gpg's armor reader, including its tolerance of a missing blank line
//!    after the armor headers, which RPSL normalisation usually removes
//!    ([`dearmor`]). Errors gpg logs make it end with a `FAILURE` status.
//! 3. gpg's import: v3 keys are skipped, user IDs without a valid
//!    self-signature are dropped, keys without a valid user ID are refused,
//!    and the primary user ID is moved to the front.
//! 4. python-gnupg's status handling (`ImportResult`) and its parsing of
//!    `gpg --list-keys --with-colons`, which decodes gpg's output as Latin-1.
//!
//! Packet parsing and signature verification use sequoia-openpgp with its
//! pure Rust crypto backend.

use std::collections::HashSet;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use sequoia_openpgp as openpgp;

use openpgp::packet::{Key, Signature, UserID, key};
use openpgp::parse::{PacketParser, PacketParserResult, Parse};
use openpgp::serialize::MarshalInto;
use openpgp::types::{HashAlgorithm, SignatureType};
use openpgp::{KeyHandle, Packet};

use crate::fields::Uncaught;
use crate::messages;
use crate::py;

/// An in-memory PGP keyring, the counterpart of v4's `auth.gnupg_keyring`.
///
/// Like gpg's keyring it keeps every key imported through it, so importing
/// the same key again merges user IDs, and `owner` reflects all of them.
#[derive(Debug, Default)]
pub struct Keyring {
    keys: Mutex<Vec<StoredKey>>,
}

#[derive(Debug, Clone)]
struct StoredKey {
    fingerprint: String,
    uids: Vec<StoredUid>,
    subkeys: HashSet<String>,
    sigs: HashSet<Vec<u8>>,
}

#[derive(Debug, Clone)]
struct StoredUid {
    value: Vec<u8>,
    /// Creation time of the latest valid self-signature.
    created: u64,
    /// That self-signature carries the primary user ID flag.
    primary: bool,
}

/// What python-gnupg's `ImportResult` holds after an import.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ImportResult {
    /// `result.fingerprints`: one per `IMPORT_OK` status.
    pub(crate) fingerprints: Vec<String>,
    /// `result.results[*]["text"]`, in status order.
    pub(crate) results: Vec<String>,
}

impl Keyring {
    /// An empty keyring.
    pub fn new() -> Self {
        Keyring::default()
    }

    /// `gpg.import_keys(text)`.
    pub(crate) fn import_keys(&self, text: &str) -> Result<ImportResult, Uncaught> {
        let bytes = latin1_encode(text)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let mut keys = self.keys.lock().unwrap_or_else(|e| e.into_inner());
        Ok(import(&bytes, &mut keys, now))
    }

    /// The `uids` python-gnupg reports for a key from
    /// `gpg --list-keys --with-colons`.
    pub(crate) fn uids(&self, fingerprint: &str) -> Vec<String> {
        let keys = self.keys.lock().unwrap_or_else(|e| e.into_inner());
        let Some(key) = keys.iter().find(|k| k.fingerprint == fingerprint) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for uid in &key.uids {
            match python_gnupg_uid(&uid.value) {
                ListedUid::Uid(s) => out.push(s),
                ListedUid::UidThenStop(s) => {
                    out.push(s);
                    break;
                }
            }
        }
        out
    }

    /// Fingerprints of every key in the keyring, in import order.
    pub fn fingerprints(&self) -> Vec<String> {
        let keys = self.keys.lock().unwrap_or_else(|e| e.into_inner());
        keys.iter().map(|k| k.fingerprint.clone()).collect()
    }
}

/// `str.encode("latin-1")`, raising Python's `UnicodeEncodeError` text.
fn latin1_encode(text: &str) -> Result<Vec<u8>, Uncaught> {
    let mut out = Vec::with_capacity(text.len());
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if (c as u32) < 256 {
            out.push(c as u32 as u8);
            i += 1;
            continue;
        }
        let start = i;
        while i < chars.len() && chars[i] as u32 >= 256 {
            i += 1;
        }
        let msg = if i - start == 1 {
            let cp = c as u32;
            let esc = if cp <= 0xffff {
                format!("\\u{cp:04x}")
            } else {
                format!("\\U{cp:08x}")
            };
            format!(
                "'latin-1' codec can't encode character '{esc}' in position {start}: ordinal not in range(256)"
            )
        } else {
            format!(
                "'latin-1' codec can't encode characters in position {start}-{}: ordinal not in range(256)",
                i - 1
            )
        };
        return Err(Uncaught(msg));
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Armor, as GnuPG 2.4's armor filter reads it
// ---------------------------------------------------------------------------

/// The result of reading armored input.
#[derive(Debug, Default)]
struct Dearmored {
    /// Decoded bytes of every armor block, concatenated.
    data: Vec<u8>,
    /// At least one armor header line was found.
    found: bool,
    /// gpg logged an error but carried on (it will end with `FAILURE`).
    error: bool,
    /// gpg aborted reading (CRC error, malformed CRC, truncated armor).
    fatal: bool,
    /// An armor ended at an END line without a CRC. gpg then looks for
    /// more data, finds none and reports NODATA, after importing.
    nodata_after: bool,
}

const ARMOR_TYPES_IMPORTABLE: [&str; 3] = [
    "BEGIN PGP PUBLIC KEY BLOCK",
    "BEGIN PGP PRIVATE KEY BLOCK",
    "BEGIN PGP SECRET KEY BLOCK",
];

fn trim_trailing_ws(line: &[u8]) -> &[u8] {
    let end = line
        .iter()
        .rposition(|b| !matches!(b, b' ' | b'\t' | b'\r'))
        .map_or(0, |p| p + 1);
    &line[..end]
}

const ARMOR_HEAD_STRINGS: [&str; 7] = [
    "PGP MESSAGE",
    "PGP PUBLIC KEY BLOCK",
    "PGP SIGNATURE",
    "PGP SIGNED MESSAGE",
    "PGP ARMORED FILE",
    "PGP PRIVATE KEY BLOCK",
    "PGP SECRET KEY BLOCK",
];

/// A BEGIN or END armor line of a known type, which ends the data of an
/// armor block that has no CRC.
fn is_armor_line(line: &[u8]) -> bool {
    let line = trim_trailing_ws(line);
    let Some(body) = line
        .strip_prefix(b"-----")
        .and_then(|r| r.strip_suffix(b"-----"))
    else {
        return false;
    };
    let Some(rest) = body
        .strip_prefix(b"BEGIN ")
        .or_else(|| body.strip_prefix(b"END "))
    else {
        return false;
    };
    ARMOR_HEAD_STRINGS.iter().any(|t| rest == t.as_bytes())
}

/// `is_armor_header` for the types `--import` accepts.
fn is_begin_line(line: &[u8]) -> bool {
    let line = trim_trailing_ws(line);
    let Some(rest) = line.strip_prefix(b"-----") else {
        return false;
    };
    let Some(body) = rest.strip_suffix(b"-----") else {
        return false;
    };
    ARMOR_TYPES_IMPORTABLE
        .iter()
        .any(|t| body == t.as_bytes())
}

fn radix64_value(b: u8) -> Option<u32> {
    Some(match b {
        b'A'..=b'Z' => u32::from(b - b'A'),
        b'a'..=b'z' => u32::from(b - b'a') + 26,
        b'0'..=b'9' => u32::from(b - b'0') + 52,
        b'+' => 62,
        b'/' => 63,
        _ => return None,
    })
}

fn crc24(data: &[u8]) -> u32 {
    let mut crc: u32 = 0x00B7_04CE;
    for &b in data {
        crc ^= u32::from(b) << 16;
        for _ in 0..8 {
            crc <<= 1;
            if crc & 0x0100_0000 != 0 {
                crc ^= 0x0186_4CFB;
            }
        }
    }
    crc & 0x00FF_FFFF
}

/// Read every armor block in `input` the way gpg's armor filter does.
fn dearmor(input: &[u8]) -> Dearmored {
    let lines: Vec<&[u8]> = input.split(|&b| b == b'\n').collect();
    let mut out = Dearmored::default();
    let mut i = 0;
    while i < lines.len() {
        if !is_begin_line(lines[i]) {
            i += 1;
            continue;
        }
        out.found = true;
        i += 1;
        // Header lines, up to an empty line. A line that is not a valid
        // "Key: value" header is logged as an error and read as data.
        let mut first_data_from_header = false;
        while i < lines.len() {
            let line = trim_trailing_ws(lines[i]);
            if line.is_empty() {
                i += 1;
                break;
            }
            let valid = line
                .iter()
                .position(|&b| b == b':')
                .is_some_and(|p| p + 1 == line.len() || line[p + 1] == b' ');
            if valid {
                i += 1;
                continue;
            }
            out.error = true;
            first_data_from_header = true;
            break;
        }

        let mut block: Vec<u8> = Vec::new();
        let mut acc: u32 = 0;
        let mut nbits = 0;
        let mut padded = false;
        let mut ended = false;
        // Data lines.
        'data: while i < lines.len() {
            let line = lines[i];
            // Without a CRC, a BEGIN/END armor line ends the data. Any other
            // line, including the invalid header line data started with, is
            // radix64 (with its dashes skipped as invalid characters).
            if !first_data_from_header && is_armor_line(line) {
                ended = true;
                out.error = true;
                out.nodata_after = true;
                break;
            }
            first_data_from_header = false;
            for (pos, &b) in line.iter().enumerate() {
                match b {
                    b' ' | b'\t' | b'\r' => {}
                    b'=' => {
                        padded = true;
                        // Continue with the CRC phase from just after '='.
                        let rest = &line[pos + 1..];
                        i += 1;
                        let crc_result = read_crc(rest, &lines, &mut i);
                        match crc_result {
                            CrcRead::Eof => out.error = true,
                            CrcRead::Absent => {}
                            CrcRead::Malformed => {
                                out.fatal = true;
                                return out;
                            }
                            CrcRead::Value(v) => {
                                if v != crc24(&block) {
                                    out.fatal = true;
                                    return out;
                                }
                                // A trailer line must follow.
                                if !lines[i.min(lines.len())..]
                                    .iter()
                                    .any(|l| l.starts_with(b"-----"))
                                {
                                    out.fatal = true;
                                    return out;
                                }
                            }
                        }
                        break 'data;
                    }
                    _ => match radix64_value(b) {
                        Some(v) => {
                            acc = (acc << 6) | v;
                            nbits += 6;
                            if nbits >= 8 {
                                nbits -= 8;
                                block.push((acc >> nbits) as u8);
                                acc &= (1 << nbits) - 1;
                            }
                        }
                        None => out.error = true,
                    },
                }
            }
            i += 1;
        }
        if !padded && !ended {
            // End of input inside the data: "premature eof (no CRC)".
            out.error = true;
        }
        out.data.extend_from_slice(&block);
        // Skip to the line after the END line, if any.
        while i < lines.len() && !lines[i].starts_with(b"-----") {
            i += 1;
        }
        i += 1;
        let _ = ended;
    }
    out
}

enum CrcRead {
    /// Input ended before a CRC.
    Eof,
    /// No CRC; the next thing is the END line.
    Absent,
    /// The CRC is not four radix64 characters.
    Malformed,
    /// The CRC value.
    Value(u32),
}

/// After the first `=`: skip whitespace and `=` (also across lines), then
/// read the four character CRC. `i` is left at the line after the CRC.
fn read_crc(rest_of_line: &[u8], lines: &[&[u8]], i: &mut usize) -> CrcRead {
    let skip = |b: u8| matches!(b, b' ' | b'\t' | b'\r' | b'=');
    let mut current: Vec<u8> = rest_of_line.to_vec();
    loop {
        if let Some(p) = current.iter().position(|&b| !skip(b)) {
            current.drain(..p);
            break;
        }
        if *i >= lines.len() {
            return CrcRead::Eof;
        }
        current = lines[*i].to_vec();
        *i += 1;
        if current.starts_with(b"-----") {
            *i -= 1;
            return CrcRead::Absent;
        }
    }
    if current.len() < 4 {
        return CrcRead::Malformed;
    }
    let mut v: u32 = 0;
    for &b in &current[..4] {
        match radix64_value(b) {
            Some(x) => v = (v << 6) | x,
            None => return CrcRead::Malformed,
        }
    }
    CrcRead::Value(v)
}

// ---------------------------------------------------------------------------
// Import, as GnuPG 2.4 does it
// ---------------------------------------------------------------------------

fn import(input: &[u8], keys: &mut Vec<StoredKey>, now: u64) -> ImportResult {
    let mut result = ImportResult::default();
    let armor = dearmor(input);
    if armor.fatal {
        result.results.push(messages::GPG_OTHER_FAILURE.to_owned());
        return result;
    }
    if !armor.found || armor.data.is_empty() {
        result.results.push(messages::GPG_NO_VALID_DATA.to_owned());
        result.results.push(messages::GPG_OTHER_FAILURE.to_owned());
        return result;
    }
    let Some(packets) = parse_packets(&armor.data) else {
        result.results.push(messages::GPG_OTHER_FAILURE.to_owned());
        return result;
    };

    let mut error = armor.error;
    let blocks = split_keyblocks(packets);
    let count = blocks.len();
    if count == 0 && armor.nodata_after {
        result.results.push(messages::GPG_NO_VALID_DATA.to_owned());
    }
    for (n, block) in blocks.into_iter().enumerate() {
        // gpg reads ahead to the end of the input before it imports the
        // last keyblock, so a NODATA seen there comes first.
        if n + 1 == count && armor.nodata_after {
            result.results.push(messages::GPG_NO_VALID_DATA.to_owned());
        }
        match import_keyblock(block, now) {
            BlockOutcome::Skipped => {}
            BlockOutcome::Rejected => error = true,
            BlockOutcome::Import(new, expired) => {
                if expired {
                    result.results.push(messages::GPG_KEY_EXPIRED.to_owned());
                }
                let reason = merge(keys, *new);
                let fpr = keys_last_fpr(keys, reason.0);
                result.results.push(import_ok_text(reason.1));
                result.fingerprints.push(fpr);
            }
        }
    }
    if error {
        result.results.push(messages::GPG_OTHER_FAILURE.to_owned());
    }
    result
}

fn keys_last_fpr(keys: &[StoredKey], idx: usize) -> String {
    keys.get(idx).map(|k| k.fingerprint.clone()).unwrap_or_default()
}

/// python-gnupg's `IMPORT_OK` text: every `ok_reason` whose bits are set,
/// where reason `0` ("Not actually changed") always matches.
fn import_ok_text(reason: u32) -> String {
    const OK_REASONS: [(u32, &str); 6] = [
        (0, "Not actually changed"),
        (1, "Entirely new key"),
        (2, "New user IDs"),
        (4, "New signatures"),
        (8, "New subkeys"),
        (16, "Contains private key"),
    ];
    let mut out = String::new();
    for (code, text) in OK_REASONS {
        if reason | code == reason {
            if !out.is_empty() {
                out.push('\n');
            }
            out.push_str(text);
        }
    }
    out.push('\n');
    out
}

fn parse_packets(data: &[u8]) -> Option<Vec<Packet>> {
    let mut packets = Vec::new();
    let mut ppr = PacketParser::from_bytes(data).ok()?;
    while let PacketParserResult::Some(pp) = ppr {
        let (packet, next) = pp.next().ok()?;
        packets.push(packet);
        ppr = next;
    }
    Some(packets)
}

/// gpg's `read_block`: a keyblock starts at each primary key packet;
/// packets before the first one are skipped.
fn split_keyblocks(packets: Vec<Packet>) -> Vec<Vec<Packet>> {
    let mut blocks: Vec<Vec<Packet>> = Vec::new();
    for p in packets {
        let starts = match &p {
            Packet::PublicKey(_) | Packet::SecretKey(_) => true,
            Packet::Unknown(u) => matches!(
                u.tag(),
                openpgp::packet::Tag::PublicKey | openpgp::packet::Tag::SecretKey
            ),
            _ => false,
        };
        if starts {
            blocks.push(vec![p]);
        } else if let Some(b) = blocks.last_mut() {
            b.push(p);
        }
    }
    blocks
}

enum BlockOutcome {
    /// Silently skipped (v3 keys, unsupported versions).
    Skipped,
    /// Refused with a logged error (no user ID, no valid user ID).
    Rejected,
    /// Imported; whether the key has expired.
    Import(Box<StoredKey>, bool),
}

struct PendingUid {
    value: Vec<u8>,
    is_attribute: bool,
    sigs: Vec<Signature>,
}

fn import_keyblock(block: Vec<Packet>, now: u64) -> BlockOutcome {
    let mut iter = block.into_iter();
    let primary: Key<key::PublicParts, key::PrimaryRole> = match iter.next() {
        Some(Packet::PublicKey(k)) => k,
        Some(Packet::SecretKey(k)) => k.take_secret().0,
        _ => return BlockOutcome::Skipped,
    };
    if primary.version() != 4 {
        return BlockOutcome::Skipped;
    }
    let primary_handle = KeyHandle::from(primary.fingerprint());
    let primary_keyid = primary.keyid();
    let key_created = to_unix(primary.creation_time());

    let mut uids: Vec<PendingUid> = Vec::new();
    let mut subkeys: HashSet<String> = HashSet::new();
    let mut sigs: HashSet<Vec<u8>> = HashSet::new();
    let mut in_subkey = false;
    for p in iter {
        match p {
            Packet::UserID(u) => {
                in_subkey = false;
                uids.push(PendingUid {
                    value: u.value().to_vec(),
                    is_attribute: false,
                    sigs: Vec::new(),
                });
            }
            Packet::UserAttribute(a) => {
                in_subkey = false;
                uids.push(PendingUid {
                    value: a.value().to_vec(),
                    is_attribute: true,
                    sigs: Vec::new(),
                });
            }
            Packet::PublicSubkey(k) => {
                in_subkey = true;
                subkeys.insert(k.fingerprint().to_hex());
            }
            Packet::SecretSubkey(k) => {
                in_subkey = true;
                subkeys.insert(k.fingerprint().to_hex());
            }
            Packet::Signature(s) => {
                if let Ok(bytes) = s.to_vec() {
                    sigs.insert(bytes);
                }
                if in_subkey {
                    continue;
                }
                if let Some(u) = uids.last_mut() {
                    u.sigs.push(s);
                }
            }
            _ => {}
        }
    }

    if uids.iter().all(|u| u.is_attribute) {
        // "key %s: no user ID"
        return BlockOutcome::Rejected;
    }

    let is_self = |s: &Signature| {
        s.get_issuers().iter().any(|h| match h {
            KeyHandle::Fingerprint(_) => h.aliases(&primary_handle),
            KeyHandle::KeyID(id) => *id == primary_keyid,
        })
    };
    let valid_binding = |s: &Signature, uid: &PendingUid| -> bool {
        if !matches!(
            s.typ(),
            SignatureType::GenericCertification
                | SignatureType::PersonaCertification
                | SignatureType::CasualCertification
                | SignatureType::PositiveCertification
        ) {
            return false;
        }
        if !is_self(s) || s.hash_algo() == HashAlgorithm::MD5 || key_created > now {
            return false;
        }
        let userid = UserID::from(uid.value.clone());
        s.verify_userid_binding(&primary, &primary, &userid).is_ok()
            || verify_large_rsa(s, &primary, &userid)
    };

    // collapse_uids: identical user IDs are merged into the first.
    let mut collapsed: Vec<PendingUid> = Vec::new();
    for u in uids {
        match collapsed
            .iter_mut()
            .find(|c| c.is_attribute == u.is_attribute && c.value == u.value)
        {
            Some(c) => c.sigs.extend(u.sigs),
            None => collapsed.push(u),
        }
    }

    let mut kept: Vec<StoredUid> = Vec::new();
    let mut expiry: Option<(u64, Option<u64>)> = None;
    let mut any_valid_uid = false;
    for u in collapsed.iter().filter(|u| !u.is_attribute) {
        let mut latest: Option<&Signature> = None;
        for s in &u.sigs {
            if valid_binding(s, u) {
                let t = sig_time(s);
                if latest.is_none_or(|l| sig_time(l) <= t) {
                    latest = Some(s);
                }
            }
        }
        let Some(latest) = latest else { continue };
        any_valid_uid = true;
        let created = sig_time(latest);
        if expiry.is_none_or(|(t, _)| created >= t) {
            expiry = Some((
                created,
                latest.key_validity_period().map(|d| d.as_secs()),
            ));
        }
        kept.push(StoredUid {
            value: u.value.clone(),
            created,
            primary: latest.primary_userid().unwrap_or(false),
        });
    }
    if !any_valid_uid {
        // "key %s: no valid user IDs"
        return BlockOutcome::Rejected;
    }
    let expired = expiry
        .and_then(|(_, period)| period)
        .is_some_and(|p| p > 0 && key_created.saturating_add(p) < now);

    reorder_primary(&mut kept);
    BlockOutcome::Import(
        Box::new(StoredKey {
            fingerprint: primary.fingerprint().to_hex(),
            uids: kept,
            subkeys,
            sigs,
        }),
        expired,
    )
}

/// RSA PKCS#1 v1.5 verification for moduli above 4096 bits, which the
/// RustCrypto `rsa` crate behind sequoia refuses but gpg accepts.
fn verify_large_rsa(
    sig: &Signature,
    primary: &Key<key::PublicParts, key::PrimaryRole>,
    userid: &UserID,
) -> bool {
    use num_bigint::BigUint;
    use openpgp::crypto::mpi;
    let (mpi::PublicKey::RSA { e, n }, mpi::Signature::RSA { s }) = (primary.mpis(), sig.mpis())
    else {
        return false;
    };
    if n.bits() <= 4096 {
        return false;
    }
    if sig
        .signature_creation_time()
        .is_none_or(|t| t < primary.creation_time())
    {
        return false;
    }
    let Ok(builder) = sig.hash_algo().context() else {
        return false;
    };
    let mut ctx = builder.for_signature(sig.version());
    if sig.hash_userid_binding(&mut ctx, primary, userid).is_err() {
        return false;
    }
    let (Ok(digest), Ok(oid)) = (ctx.into_digest(), sig.hash_algo().oid()) else {
        return false;
    };
    let k = n.value().len();
    let t_len = oid.len() + digest.len();
    if k < t_len + 11 {
        return false;
    }
    let mut em = vec![0x00, 0x01];
    em.extend(std::iter::repeat_n(0xff, k - t_len - 3));
    em.push(0x00);
    em.extend_from_slice(oid);
    em.extend_from_slice(&digest);
    let n_big = BigUint::from_bytes_be(n.value());
    let m = BigUint::from_bytes_be(s.value()).modpow(&BigUint::from_bytes_be(e.value()), &n_big);
    let mut m_bytes = m.to_bytes_be();
    if m_bytes.len() > k {
        return false;
    }
    let mut padded = vec![0u8; k - m_bytes.len()];
    padded.append(&mut m_bytes);
    padded == em
}

fn to_unix(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

fn sig_time(s: &Signature) -> u64 {
    s.signature_creation_time().map_or(0, to_unix)
}

/// gpg's `cmp_user_ids`: longer wins, then byte comparison.
fn cmp_user_ids(a: &[u8], b: &[u8]) -> std::cmp::Ordering {
    a.len().cmp(&b.len()).then_with(|| a.cmp(b))
}

/// Move the primary user ID to the front, as gpg does on import: the
/// latest self-signed user ID flagged primary, or failing that the user ID
/// with the latest self-signature. Ties go to `cmp_user_ids`.
fn reorder_primary(uids: &mut Vec<StoredUid>) {
    let pick = |flagged: bool| -> Option<usize> {
        let mut best: Option<usize> = None;
        for (i, u) in uids.iter().enumerate() {
            if u.primary != flagged {
                continue;
            }
            best = match best {
                None if u.created > 0 || flagged => Some(i),
                None => Some(i),
                Some(b) => {
                    let bu = &uids[b];
                    if u.created > bu.created
                        || (u.created == bu.created
                            && cmp_user_ids(&u.value, &bu.value).is_gt())
                    {
                        Some(i)
                    } else {
                        Some(b)
                    }
                }
            };
        }
        best
    };
    if let Some(idx) = pick(true).or_else(|| pick(false)) {
        let u = uids.remove(idx);
        uids.insert(0, u);
    }
}

/// Merge a newly read key into the keyring. Returns the key's index and
/// the `IMPORT_OK` reason bits.
fn merge(keys: &mut Vec<StoredKey>, new: StoredKey) -> (usize, u32) {
    let Some(idx) = keys.iter().position(|k| k.fingerprint == new.fingerprint) else {
        keys.push(new);
        return (keys.len() - 1, 1);
    };
    let existing = &mut keys[idx];
    let mut reason = 0;
    for u in new.uids {
        match existing.uids.iter_mut().find(|e| e.value == u.value) {
            Some(e) => {
                if u.created > e.created {
                    e.created = u.created;
                    e.primary = u.primary;
                }
            }
            None => {
                reason |= 2;
                existing.uids.push(u);
            }
        }
    }
    for s in new.subkeys {
        if existing.subkeys.insert(s) {
            reason |= 8;
        }
    }
    for s in new.sigs {
        if existing.sigs.insert(s) && reason & 2 == 0 {
            reason |= 4;
        }
    }
    reorder_primary(&mut existing.uids);
    (idx, reason)
}

// ---------------------------------------------------------------------------
// python-gnupg's view of `gpg --list-keys --with-colons`
// ---------------------------------------------------------------------------

enum ListedUid {
    /// The uid as python-gnupg reports it.
    Uid(String),
    /// The uid, after which python-gnupg stops reading the listing (it
    /// treats an empty line as the end of output).
    UidThenStop(String),
}

/// gpg prints a user ID in colon listings with `es_write_sanitized(..., ":")`,
/// python-gnupg decodes the output as Latin-1, splits it with
/// `str.splitlines()` (which also splits on U+0085), strips each line, and
/// unescapes `\xNN` and then the C escapes.
fn python_gnupg_uid(raw: &[u8]) -> ListedUid {
    let mut escaped: Vec<u8> = Vec::with_capacity(raw.len());
    for &b in raw {
        if b < 0x20 || b == 0x7f || b == b':' || b == b'\\' {
            escaped.push(b'\\');
            match b {
                b'\n' => escaped.push(b'n'),
                b'\r' => escaped.push(b'r'),
                0x0c => escaped.push(b'f'),
                0x0b => escaped.push(b'v'),
                0x08 => escaped.push(b'b'),
                0 => escaped.push(b'0'),
                _ => escaped.extend_from_slice(format!("x{b:02x}").as_bytes()),
            }
        } else {
            escaped.push(b);
        }
    }
    let line: String = escaped.iter().map(|&b| char::from(b)).collect();
    // The record is "uid:<validity>::::<created>::<hash>::<uid>::::::::::0:".
    // Only a U+0085 inside the uid can split it; the first piece holds the
    // uid field, any empty piece after it ends python-gnupg's parsing.
    let mut stop = false;
    let field: String = match line.split_once('\u{85}') {
        None => line,
        Some((head, tail)) => {
            // The last piece carries the record's remaining fields and is
            // never empty; an empty piece before it is an empty line.
            let pieces: Vec<&str> = tail.split('\u{85}').collect();
            if pieces[..pieces.len() - 1].iter().any(|p| p.is_empty()) {
                stop = true;
            }
            py::rstrip(head).to_owned()
        }
    };
    let mut s = unescape_hex(&field);
    for (k, v) in [
        ("\\n", "\n"),
        ("\\r", "\r"),
        ("\\f", "\u{c}"),
        ("\\v", "\u{b}"),
        ("\\b", "\u{8}"),
        ("\\0", "\0"),
    ] {
        s = s.replace(k, v);
    }
    if stop {
        ListedUid::UidThenStop(s)
    } else {
        ListedUid::Uid(s)
    }
}

/// `re.sub(r'\\x([0-9a-f][0-9a-f])', lambda m: chr(int(m.group(1), 16)), s, flags=re.I)`
fn unescape_hex(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '\\'
            && i + 3 < chars.len()
            && (chars[i + 1] == 'x' || chars[i + 1] == 'X')
            && chars[i + 2].is_ascii_hexdigit()
            && chars[i + 3].is_ascii_hexdigit()
        {
            let hex: String = chars[i + 2..i + 4].iter().collect();
            if let Ok(v) = u8::from_str_radix(&hex, 16) {
                out.push(char::from(v));
                i += 4;
                continue;
            }
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn import_ok_texts_match_python_gnupg() {
        assert_eq!(import_ok_text(1), "Not actually changed\nEntirely new key\n");
        assert_eq!(import_ok_text(0), "Not actually changed\n");
    }

    #[test]
    fn uid_escapes_round_trip_like_python_gnupg() {
        let ListedUid::Uid(s) = python_gnupg_uid("a: b \\n".as_bytes()) else {
            panic!()
        };
        assert_eq!(s, "a: b \n");
        let ListedUid::Uid(s) = python_gnupg_uid("Bö".as_bytes()) else {
            panic!()
        };
        assert_eq!(s, "BÃ¶");
    }

    #[test]
    fn garbage_is_no_data() {
        let mut keys = Vec::new();
        let r = import(b"not a key", &mut keys, 0);
        assert!(r.fingerprints.is_empty());
        assert_eq!(r.results, vec!["No valid data found", "Other failure"]);
    }

    #[test]
    fn latin1_errors_match_python() {
        assert_eq!(
            latin1_encode("ab\u{20ac}c").unwrap_err().0,
            "'latin-1' codec can't encode character '\\u20ac' in position 2: ordinal not in range(256)"
        );
        assert_eq!(
            latin1_encode("\u{20ac}\u{20ac}").unwrap_err().0,
            "'latin-1' codec can't encode characters in position 0-1: ordinal not in range(256)"
        );
    }
}
