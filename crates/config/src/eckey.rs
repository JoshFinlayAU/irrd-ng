//! v4's `eckey_from_str` (`irrd/utils/crypto.py`), which hands the setting
//! to joserfc's `ECKey.import_key` and so to pyca/cryptography's loaders.
//!
//! The NRTMv4 key settings are validated by that call and its `ValueError`
//! text ends up in the configuration error, so the dispatch on the input
//! (OpenSSH, PEM by keyword, DER fallback) and the common error strings of
//! cryptography 50 (its PEM framing errors, base64 errors from the `pem`
//! crate, and `rust-asn1` parse errors on the outer structure) are
//! reproduced here. P-256, the curve NRTMv4 uses, is validated fully with
//! the pure-Rust `p256` crate; other named curves cryptography accepts are
//! checked for structure and point size only.

use crate::messages;
use crate::python::{PyException, Value, bytes_repr};

/// Why `eckey_from_str` failed.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum KeyError {
    /// A `ValueError`, which v4 reports; the text is `str(exc)`.
    Value(String),
    /// Anything else, which v4 does not catch.
    Crash(PyException),
}

type Result<T> = std::result::Result<T, KeyError>;

fn value_error(msg: impl Into<String>) -> KeyError {
    KeyError::Value(msg.into())
}

const PEM_LOAD_PREFIX: &str = "Unable to load PEM file. See https://cryptography.io/en/latest/faq/#why-can-t-i-import-my-pem-file for more details. ";
const DESERIALIZE_PREFIX: &str = "Could not deserialize key data. The data may be in an incorrect format, it may be encrypted with an unsupported algorithm, or it may be an unsupported key type (e.g. EC curves with explicit parameters). Details: ";
const INVALID_KEY: &str = "Invalid key";

fn not_ec() -> KeyError {
    KeyError::Crash(PyException::new(
        "InvalidKeyTypeError",
        "invalid_key_type: Not a key of: 'EC'",
    ))
}

/// `eckey_from_str(value, require_private)`.
pub(crate) fn eckey_from_str(value: &Value, require_private: bool) -> Result<()> {
    let raw = to_bytes(value)?;
    let private = import_from_bytes(&raw)?;
    if require_private && !private {
        return Err(value_error(messages::ECKEY_PUBLIC_NOT_PRIVATE));
    }
    Ok(())
}

/// joserfc's `to_bytes`: strings are encoded, numbers formatted, and
/// anything else goes through Python's `bytes()`. A DottedDict is not a
/// `dict` to joserfc, so it gets the `bytes()` treatment too.
fn to_bytes(value: &Value) -> Result<Vec<u8>> {
    let items = match value {
        Value::Str(s) => return Ok(s.as_bytes().to_vec()),
        Value::Bytes(b) => return Ok(b.clone()),
        Value::Int(_) | Value::Float(_) | Value::Bool(_) => return Ok(value.py_str().into_bytes()),
        Value::List(items) | Value::Tuple(items) | Value::Set(items) => items.clone(),
        Value::Dict(d) => d.keys().cloned().collect(),
        other => {
            return Err(KeyError::Crash(PyException::type_error(format!(
                "cannot convert '{}' object to bytes",
                other.type_name()
            ))));
        }
    };
    let mut out = Vec::with_capacity(items.len());
    for item in &items {
        let n = match item {
            Value::Int(i) => i.clone(),
            Value::Bool(b) => num_bigint::BigInt::from(u8::from(*b)),
            other => {
                return Err(KeyError::Crash(PyException::type_error(format!(
                    "'{}' object cannot be interpreted as an integer",
                    other.type_name()
                ))));
            }
        };
        match u8::try_from(&n) {
            Ok(b) => out.push(b),
            Err(_) => return Err(value_error("bytes must be in range(0, 256)")),
        }
    }
    Ok(out)
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// `CryptographyBinding.import_from_bytes` for `ECBinding`, returning
/// whether the key is private.
fn import_from_bytes(raw: &[u8]) -> Result<bool> {
    if raw.starts_with(b"ecdsa-sha2-") {
        load_ssh_public_key(raw)?;
        return Ok(false);
    }
    if contains(raw, b"OPENSSH PRIVATE") {
        load_ssh_private_key(raw)?;
        return Ok(true);
    }
    if contains(raw, b"PUBLIC") {
        load_pem_public_key(raw)?;
        return Ok(false);
    }
    if contains(raw, b"PRIVATE") {
        load_pem_private_key(raw)?;
        return Ok(true);
    }
    if contains(raw, b"CERTIFICATE") {
        load_pem_certificate(raw)?;
        return Ok(false);
    }
    match load_der_private_key(raw) {
        Ok(()) => Ok(true),
        Err(KeyError::Value(_)) => {
            load_der_public_key(raw)?;
            Ok(false)
        }
        Err(e) => Err(e),
    }
}

// ---------------------------------------------------------------------------
// base64, as the `base64` 0.22 STANDARD engine decodes PEM bodies.

fn b64_value(b: u8) -> Option<u8> {
    match b {
        b'A'..=b'Z' => Some(b - b'A'),
        b'a'..=b'z' => Some(b - b'a' + 26),
        b'0'..=b'9' => Some(b - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Decode with the `base64` crate's STANDARD engine; the error is its
/// `Display` text.
fn base64_standard(input: &[u8]) -> std::result::Result<Vec<u8>, String> {
    let invalid_byte = |i: usize, b: u8| format!("Invalid symbol {b}, offset {i}.");
    let rem = input.len() % 4;
    if rem == 1 {
        let last = input[input.len() - 1];
        if last != b'=' && b64_value(last).is_none() {
            return Err(invalid_byte(input.len() - 1, last));
        }
    }
    let nonterminal = input
        .len()
        .saturating_sub(rem)
        .saturating_sub(if rem == 0 { 4 } else { 0 });
    let mut out = Vec::with_capacity(input.len() / 4 * 3);
    for (q, chunk) in input[..nonterminal].as_chunks::<4>().0.iter().enumerate() {
        let mut acc = 0u32;
        for (i, &b) in chunk.iter().enumerate() {
            let v = b64_value(b).ok_or_else(|| invalid_byte(q * 4 + i, b))?;
            acc = (acc << 6) | u32::from(v);
        }
        out.extend_from_slice(&acc.to_be_bytes()[1..]);
    }
    // decode_suffix
    let mut morsels = Vec::new();
    let mut padding = 0;
    let mut first_padding = 0;
    let mut last_symbol = 0u8;
    for (li, &b) in input[nonterminal..].iter().enumerate() {
        if b == b'=' {
            if li < 2 {
                return Err(invalid_byte(nonterminal + li, b));
            }
            if padding == 0 {
                first_padding = li;
            }
            padding += 1;
            continue;
        }
        if padding > 0 {
            return Err(invalid_byte(nonterminal + first_padding, b'='));
        }
        last_symbol = b;
        let v = b64_value(b).ok_or_else(|| invalid_byte(nonterminal + li, b))?;
        morsels.push(v);
    }
    if !input.is_empty() && morsels.len() < 2 {
        return Err(format!(
            "Invalid input length: {}",
            nonterminal + morsels.len()
        ));
    }
    if (padding + morsels.len()) % 4 != 0 && !input.is_empty() {
        return Err("Invalid padding".to_owned());
    }
    let nbytes = morsels.len() * 6 / 8;
    let mut acc = 0u32;
    for (i, m) in morsels.iter().enumerate() {
        acc |= u32::from(*m) << (26 - 6 * i);
    }
    let mask = if nbytes == 0 {
        u32::MAX
    } else {
        u32::MAX >> (nbytes * 8)
    };
    if !morsels.is_empty() && acc & mask != 0 {
        return Err(format!(
            "Invalid last symbol {last_symbol}, offset {}.",
            nonterminal + morsels.len() - 1
        ));
    }
    out.extend_from_slice(&acc.to_be_bytes()[..nbytes]);
    Ok(out)
}

/// Python's `binascii.a2b_base64` in its default, non-strict mode.
fn a2b_base64(input: &[u8]) -> std::result::Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut acc = 0u32;
    let mut bits = 0;
    let mut quad = 0usize;
    let mut data_chars = 0usize;
    let mut pads = 0usize;
    for &b in input {
        if b == b'=' {
            if quad >= 2 {
                pads += 1;
                if quad + pads >= 4 {
                    return Ok(out);
                }
            }
            continue;
        }
        let Some(v) = b64_value(b) else { continue };
        pads = 0;
        data_chars += 1;
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        quad = (quad + 1) % 4;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    match quad {
        0 => Ok(out),
        1 => Err(format!(
            "Invalid base64-encoded string: number of data characters ({data_chars}) cannot be 1 more than a multiple of 4"
        )),
        _ => Err("Incorrect padding".to_owned()),
    }
}

// ---------------------------------------------------------------------------
// PEM, as the `pem` 3.0 crate frames it.

struct Pem {
    tag: String,
    contents: Vec<u8>,
}

fn read_until<'a>(input: &'a [u8], marker: &[u8]) -> Option<(&'a [u8], &'a [u8])> {
    let mut index = 0;
    let mut found = 0;
    while input.len() - index >= marker.len() - found {
        if input[index] == marker[found] {
            found += 1;
        } else {
            found = 0;
        }
        index += 1;
        if found == marker.len() {
            return Some((&input[index..], &input[..index - found]));
        }
    }
    None
}

fn skip_whitespace(mut input: &[u8]) -> &[u8] {
    while let Some(b) = input.first() {
        if matches!(b, b' ' | b'\t' | b'\n' | b'\r') {
            input = &input[1..];
        } else {
            break;
        }
    }
    input
}

fn pem_error(debug: &str) -> KeyError {
    value_error(format!("{PEM_LOAD_PREFIX}{debug}"))
}

/// `pem::parse`: the first block only.
fn pem_parse(input: &[u8]) -> Result<Pem> {
    let malformed = || pem_error("MalformedFraming");
    let (rest, _) = read_until(input, b"-----BEGIN ").ok_or_else(malformed)?;
    let (rest, begin) = read_until(rest, b"-----").ok_or_else(malformed)?;
    let rest = skip_whitespace(rest);
    let (rest, payload) = read_until(rest, b"-----END ").ok_or_else(malformed)?;
    let (headers, data) = if let Some((data, headers)) = read_until(payload, b"\n\n") {
        (headers, data)
    } else if let Some((data, headers)) = read_until(payload, b"\r\n\r\n") {
        (headers, data)
    } else {
        (&b""[..], payload)
    };
    let (_, end) = read_until(rest, b"-----").ok_or_else(malformed)?;
    let utf8 = |b: &[u8]| {
        std::str::from_utf8(b)
            .map(str::to_owned)
            .map_err(|e| pem_error(&format!("NotUtf8({e:?})")))
    };
    let tag = utf8(begin)?;
    if tag.is_empty() {
        return Err(pem_error("MissingBeginTag"));
    }
    let tag_end = utf8(end)?;
    if tag_end.is_empty() {
        return Err(pem_error("MissingEndTag"));
    }
    if tag != tag_end {
        return Err(pem_error(&format!("MismatchedTags({tag:?}, {tag_end:?})")));
    }
    let raw_data = utf8(data)?;
    let cleaned: String = raw_data.chars().filter(|c| !c.is_whitespace()).collect();
    let contents =
        base64_standard(cleaned.as_bytes()).map_err(|e| pem_error(&format!("InvalidData({e})")))?;
    let headers = utf8(headers)?;
    for line in headers.lines() {
        if !line.contains(':') {
            return Err(pem_error(&format!("InvalidHeader({line:?})")));
        }
    }
    Ok(Pem { tag, contents })
}

// ---------------------------------------------------------------------------
// DER, with `rust-asn1`'s error texts.

#[derive(Clone, Copy, PartialEq, Eq)]
struct Tag {
    value: u32,
    constructed: bool,
    class: u8,
}

impl Tag {
    const fn universal(value: u32, constructed: bool) -> Self {
        Tag {
            value,
            constructed,
            class: 0,
        }
    }

    fn debug(&self) -> String {
        let class = match self.class {
            0 => "Universal",
            1 => "Application",
            2 => "ContextSpecific",
            _ => "Private",
        };
        format!(
            "Tag {{ value: {}, constructed: {}, class: {class} }}",
            self.value, self.constructed
        )
    }
}

const SEQUENCE: Tag = Tag::universal(0x10, true);
const INTEGER: Tag = Tag::universal(0x02, false);
const BIT_STRING: Tag = Tag::universal(0x03, false);
const OCTET_STRING: Tag = Tag::universal(0x04, false);
const OID: Tag = Tag::universal(0x06, false);

#[derive(Debug)]
enum Asn1Error {
    ShortData(usize),
    InvalidTag,
    InvalidLength,
    UnexpectedTag(String),
    ExtraData,
    InvalidValue,
}

impl Asn1Error {
    fn text(&self) -> String {
        let kind = match self {
            Asn1Error::ShortData(n) => format!("short data (needed at least {n} additional bytes)"),
            Asn1Error::InvalidTag => "invalid tag".to_owned(),
            Asn1Error::InvalidLength => "invalid length".to_owned(),
            Asn1Error::UnexpectedTag(t) => format!("unexpected tag (got {t})"),
            Asn1Error::ExtraData => "extra data".to_owned(),
            Asn1Error::InvalidValue => "invalid value".to_owned(),
        };
        format!("ASN.1 parsing error: {kind}")
    }
}

impl Asn1Error {
    /// `Debug` of a `rust-asn1` `ParseError` raised at the outer level
    /// (no field locations), as cryptography's X.509 loader prints it.
    fn debug(&self) -> String {
        let kind = match self {
            Asn1Error::ShortData(n) => format!("ShortData {{ needed: {n} }}"),
            Asn1Error::InvalidTag => "InvalidTag".to_owned(),
            Asn1Error::InvalidLength => "InvalidLength".to_owned(),
            Asn1Error::UnexpectedTag(t) => format!("UnexpectedTag {{ actual: {t} }}"),
            Asn1Error::ExtraData => "ExtraData".to_owned(),
            Asn1Error::InvalidValue => "InvalidValue".to_owned(),
        };
        format!("ParseError {{ kind: {kind} }}")
    }
}

fn deserialize_error(e: &Asn1Error) -> KeyError {
    value_error(format!("{DESERIALIZE_PREFIX}{}", e.text()))
}

struct Der<'a> {
    data: &'a [u8],
}

impl<'a> Der<'a> {
    fn new(data: &'a [u8]) -> Self {
        Der { data }
    }

    fn read_bytes(&mut self, n: usize) -> std::result::Result<&'a [u8], Asn1Error> {
        if n > self.data.len() {
            return Err(Asn1Error::ShortData(n - self.data.len()));
        }
        let (head, tail) = self.data.split_at(n);
        self.data = tail;
        Ok(head)
    }

    fn read_tag(&mut self) -> std::result::Result<Tag, Asn1Error> {
        let first = self.read_bytes(1)?[0];
        let mut value = u32::from(first & 0x1f);
        let constructed = first & 0x20 != 0;
        let class = first >> 6;
        if value == 0x1f {
            let mut v: u64 = 0;
            let mut started = false;
            loop {
                let b = self.read_bytes(1)?[0];
                if !started && b == 0x80 {
                    return Err(Asn1Error::InvalidTag);
                }
                started = true;
                v = (v << 7) | u64::from(b & 0x7f);
                if v > u64::from(u32::MAX) {
                    return Err(Asn1Error::InvalidTag);
                }
                if b & 0x80 == 0 {
                    break;
                }
            }
            value = u32::try_from(v).map_err(|_| Asn1Error::InvalidTag)?;
            if value < 0x1f {
                return Err(Asn1Error::InvalidTag);
            }
        }
        Ok(Tag {
            value,
            constructed,
            class,
        })
    }

    fn read_length(&mut self) -> std::result::Result<usize, Asn1Error> {
        let b = self.read_bytes(1)?[0];
        if b & 0x80 == 0 {
            return Ok(usize::from(b));
        }
        let n = usize::from(b & 0x7f);
        if !(1..=4).contains(&n) {
            return Err(Asn1Error::InvalidLength);
        }
        let bytes = self.read_bytes(n)?;
        let length = bytes
            .iter()
            .fold(0usize, |acc, x| (acc << 8) | usize::from(*x));
        let minimum = 1usize << (8 * (n - 1));
        if length < minimum.max(0x80) {
            return Err(Asn1Error::InvalidLength);
        }
        Ok(length)
    }

    fn read_tlv(&mut self) -> std::result::Result<(Tag, &'a [u8]), Asn1Error> {
        let tag = self.read_tag()?;
        let length = self.read_length()?;
        let data = self.read_bytes(length)?;
        Ok((tag, data))
    }

    fn peek_tag(&self) -> Option<Tag> {
        Der { data: self.data }.read_tag().ok()
    }

    fn expect(&mut self, tag: Tag) -> std::result::Result<&'a [u8], Asn1Error> {
        let (t, data) = self.read_tlv()?;
        if t != tag {
            return Err(Asn1Error::UnexpectedTag(t.debug()));
        }
        Ok(data)
    }

    fn finish(&self) -> std::result::Result<(), Asn1Error> {
        if self.data.is_empty() {
            Ok(())
        } else {
            Err(Asn1Error::ExtraData)
        }
    }
}

/// `asn1::parse_single` of a SEQUENCE: parse the body with `f`, then
/// reject trailing data, in that order.
fn with_sequence<'a, T>(
    data: &'a [u8],
    f: impl FnOnce(&'a [u8]) -> std::result::Result<T, Asn1Error>,
) -> std::result::Result<T, Asn1Error> {
    let mut outer = Der::new(data);
    let body = outer.expect(SEQUENCE)?;
    let value = f(body)?;
    outer.finish()?;
    Ok(value)
}

const OID_EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const OID_P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];

/// Named curves OpenSSL knows, with their field size in bytes.
fn curve_field_bytes(oid: &[u8]) -> Option<usize> {
    const CURVES: &[(&[u8], usize)] = &[
        (&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x01], 24), // secp192r1
        (&[0x2b, 0x81, 0x04, 0x00, 0x21], 28),                   // secp224r1
        (OID_P256, 32),                                          // secp256r1
        (&[0x2b, 0x81, 0x04, 0x00, 0x22], 48),                   // secp384r1
        (&[0x2b, 0x81, 0x04, 0x00, 0x23], 66),                   // secp521r1
        (&[0x2b, 0x81, 0x04, 0x00, 0x0a], 32),                   // secp256k1
        (&[0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07], 32), // brainpoolP256r1
        (&[0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0b], 48), // brainpoolP384r1
        (&[0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0d], 64), // brainpoolP512r1
    ];
    CURVES.iter().find(|(o, _)| *o == oid).map(|(_, n)| *n)
}

/// Algorithms cryptography loads as a non-EC key type.
fn is_other_key_type(oid: &[u8]) -> bool {
    const OTHERS: &[&[u8]] = &[
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01], // rsaEncryption
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a], // RSASSA-PSS
        &[0x2a, 0x86, 0x48, 0xce, 0x38, 0x04, 0x01],             // DSA
        &[0x2b, 0x65, 0x70],                                     // Ed25519
        &[0x2b, 0x65, 0x71],                                     // Ed448
        &[0x2b, 0x65, 0x6e],                                     // X25519
        &[0x2b, 0x65, 0x6f],                                     // X448
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x03, 0x01], // dhKeyAgreement
        &[0x2a, 0x86, 0x48, 0xce, 0x3e, 0x02, 0x01],             // dhpublicnumber
    ];
    OTHERS.contains(&oid)
}

/// Check an encoded point for a named curve, the way OpenSSL's
/// `EcPoint::from_bytes` would accept or reject it.
fn check_point(curve: &[u8], point: &[u8]) -> Result<()> {
    if curve == OID_P256 {
        return p256::PublicKey::from_sec1_bytes(point)
            .map(|_| ())
            .map_err(|_| value_error(INVALID_KEY));
    }
    let Some(n) = curve_field_bytes(curve) else {
        return Ok(());
    };
    let ok = match point.first() {
        Some(4 | 6 | 7) => point.len() == 1 + 2 * n,
        Some(2 | 3) => point.len() == 1 + n,
        _ => false,
    };
    if ok {
        Ok(())
    } else {
        Err(value_error(INVALID_KEY))
    }
}

enum KeyAlg<'a> {
    Ec(Option<&'a [u8]>),
    Other,
    Unknown(&'a [u8]),
}

/// Parse an AlgorithmIdentifier body.
fn algorithm(body: &[u8]) -> std::result::Result<KeyAlg<'_>, Asn1Error> {
    let mut p = Der::new(body);
    let oid = p.expect(OID)?;
    if oid == OID_EC_PUBLIC_KEY {
        // ECParameters: namedCurve OID, implicitCurve NULL or a
        // specifiedCurve SEQUENCE (unsupported by cryptography).
        let params = match p.peek_tag() {
            Some(t) if t == OID => Some(p.expect(OID)?),
            Some(_) => {
                p.read_tlv()?;
                None
            }
            None => return Err(Asn1Error::ShortData(1)),
        };
        p.finish()?;
        return Ok(KeyAlg::Ec(params));
    }
    if !p.data.is_empty() {
        p.read_tlv()?;
    }
    p.finish()?;
    if is_other_key_type(oid) {
        Ok(KeyAlg::Other)
    } else {
        Ok(KeyAlg::Unknown(oid))
    }
}

fn oid_dotted(oid: &[u8]) -> String {
    let mut parts = Vec::new();
    let mut value: u64 = 0;
    for b in oid {
        value = (value << 7) | u64::from(b & 0x7f);
        if b & 0x80 == 0 {
            if parts.is_empty() {
                let (first, second) = if value < 80 {
                    (value / 40, value % 40)
                } else {
                    (2, value - 80)
                };
                parts.push(first.to_string());
                parts.push(second.to_string());
            } else {
                parts.push(value.to_string());
            }
            value = 0;
        }
    }
    parts.join(".")
}

fn unsupported_curve(oid: &[u8]) -> KeyError {
    value_error(format!("Curve {} is not supported", oid_dotted(oid)))
}

fn unknown_key_type(oid: &[u8]) -> KeyError {
    value_error(format!("Unknown key type: {}", oid_dotted(oid)))
}

/// `cryptography_key_parsing::spki::parse_public_key`.
fn parse_spki(data: &[u8]) -> Result<()> {
    let parsed = with_sequence(data, |body| {
        let mut p = Der::new(body);
        let alg = p.expect(SEQUENCE)?;
        let alg = algorithm(alg)?;
        let key = p.expect(BIT_STRING)?;
        p.finish()?;
        Ok((alg, key))
    });
    let (alg, key) = parsed.map_err(|e: Asn1Error| deserialize_error(&e))?;
    match alg {
        KeyAlg::Ec(Some(curve)) => {
            if curve_field_bytes(curve).is_none() {
                return Err(unsupported_curve(curve));
            }
            // BIT STRING: first byte is the unused-bit count.
            let point = key.get(1..).unwrap_or_default();
            if key.first().copied().unwrap_or(1) != 0 {
                return Err(deserialize_error(&Asn1Error::InvalidValue));
            }
            check_point(curve, point)
        }
        KeyAlg::Ec(None) => Err(value_error(
            "ECDSA keys with explicit parameters are unsupported at this time",
        )),
        KeyAlg::Other => Err(not_ec()),
        KeyAlg::Unknown(oid) => Err(unknown_key_type(oid)),
    }
}

/// An ECPrivateKey (SEC 1) body, with the curve from the algorithm
/// identifier when wrapped in PKCS#8.
fn parse_ec_private_key(data: &[u8], curve_from_alg: Option<&[u8]>) -> Result<()> {
    let parsed = with_sequence(data, |body| {
        let mut p = Der::new(body);
        let version = p.expect(INTEGER)?;
        let d = p.expect(OCTET_STRING)?;
        let mut curve = None;
        let mut public = None;
        if p.peek_tag().is_some_and(|t| t.class == 2 && t.value == 0) {
            let (_, params) = p.read_tlv()?;
            let mut q = Der::new(params);
            curve = Some(q.expect(OID)?);
        }
        if p.peek_tag().is_some_and(|t| t.class == 2 && t.value == 1) {
            let (_, bits) = p.read_tlv()?;
            let mut q = Der::new(bits);
            public = Some(q.expect(BIT_STRING)?);
        }
        p.finish()?;
        Ok((version, d, curve, public))
    });
    let (version, d, curve, public) = parsed.map_err(|e: Asn1Error| deserialize_error(&e))?;
    if version != [1] {
        return Err(value_error(INVALID_KEY));
    }
    let Some(curve) = curve_from_alg.or(curve) else {
        return Err(value_error(INVALID_KEY));
    };
    if curve_field_bytes(curve).is_none() {
        return Err(unsupported_curve(curve));
    }
    if curve == OID_P256 {
        let secret = p256::SecretKey::from_slice(d).map_err(|_| value_error(INVALID_KEY))?;
        if let Some(bits) = public {
            let point = bits.get(1..).unwrap_or_default();
            let embedded =
                p256::PublicKey::from_sec1_bytes(point).map_err(|_| value_error(INVALID_KEY))?;
            if embedded != secret.public_key() {
                return Err(value_error(INVALID_KEY));
            }
        }
        return Ok(());
    }
    if d.is_empty() || d.iter().all(|b| *b == 0) {
        return Err(value_error(INVALID_KEY));
    }
    if let Some(bits) = public {
        check_point(curve, bits.get(1..).unwrap_or_default())?;
    }
    Ok(())
}

/// `cryptography_key_parsing::pkcs8::parse_private_key`.
fn parse_pkcs8(data: &[u8]) -> Result<()> {
    let parsed = with_sequence(data, |body| {
        let mut p = Der::new(body);
        p.expect(INTEGER)?;
        let alg = p.expect(SEQUENCE)?;
        let alg = algorithm(alg)?;
        let key = p.expect(OCTET_STRING)?;
        while !p.data.is_empty() {
            p.read_tlv()?;
        }
        Ok((alg, key))
    });
    let (alg, key) = parsed.map_err(|e: Asn1Error| deserialize_error(&e))?;
    match alg {
        KeyAlg::Ec(Some(curve)) => parse_ec_private_key(key, Some(curve)),
        KeyAlg::Ec(None) => Err(value_error(
            "ECDSA keys with explicit parameters are unsupported at this time",
        )),
        KeyAlg::Other => Err(not_ec()),
        KeyAlg::Unknown(oid) => Err(unknown_key_type(oid)),
    }
}

fn load_pem_public_key(raw: &[u8]) -> Result<()> {
    let pem = pem_parse(raw)?;
    match pem.tag.as_str() {
        "PUBLIC KEY" => parse_spki(&pem.contents),
        // An RSA key in any form is not an EC key.
        "RSA PUBLIC KEY" => Err(not_ec()),
        _ => Err(pem_error("MalformedFraming")),
    }
}

fn load_pem_private_key(raw: &[u8]) -> Result<()> {
    let pem = pem_parse(raw)?;
    match pem.tag.as_str() {
        "PRIVATE KEY" => parse_pkcs8(&pem.contents),
        "EC PRIVATE KEY" => parse_ec_private_key(&pem.contents, None),
        "ENCRYPTED PRIVATE KEY" => Err(KeyError::Crash(PyException::type_error(
            "Password was not given but private key is encrypted",
        ))),
        "RSA PRIVATE KEY" | "DSA PRIVATE KEY" => Err(not_ec()),
        _ => Err(pem_error("MalformedFraming")),
    }
}

fn load_pem_certificate(raw: &[u8]) -> Result<()> {
    let pem = pem_parse(raw)?;
    if pem.tag != "CERTIFICATE" && pem.tag != "X509 CERTIFICATE" {
        return Err(value_error(
            "Valid PEM but no BEGIN CERTIFICATE/END CERTIFICATE delimiters. Are you sure this is a certificate?",
        ));
    }
    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature }
    // TBSCertificate ::= SEQUENCE { [0] version OPTIONAL, serial, signature,
    //   issuer, validity, subject, subjectPublicKeyInfo, ... }
    let spki = with_sequence(&pem.contents, |body| {
        let mut p = Der::new(body);
        let tbs = p.expect(SEQUENCE)?;
        let mut t = Der::new(tbs);
        if t.peek_tag().is_some_and(|x| x.class == 2 && x.value == 0) {
            t.read_tlv()?;
        }
        for _ in 0..5 {
            t.read_tlv()?;
        }
        let start = t.data;
        let (tag, _) = t.read_tlv()?;
        if tag != SEQUENCE {
            return Err(Asn1Error::UnexpectedTag(tag.debug()));
        }
        Ok(&start[..start.len() - t.data.len()])
    })
    .map_err(|e| value_error(format!("error parsing asn1 value: {}", e.debug())))?;
    parse_spki(spki)
}

fn load_der_private_key(raw: &[u8]) -> Result<()> {
    match parse_pkcs8(raw) {
        Err(KeyError::Value(_)) => parse_ec_private_key(raw, None),
        other => other,
    }
}

fn load_der_public_key(raw: &[u8]) -> Result<()> {
    parse_spki(raw)
}

// ---------------------------------------------------------------------------
// OpenSSH formats (`cryptography/hazmat/primitives/serialization/ssh.py`).

fn ssh_u32(data: &mut &[u8]) -> Result<u32> {
    if data.len() < 4 {
        return Err(value_error("Invalid data"));
    }
    let v = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    *data = &data[4..];
    Ok(v)
}

fn ssh_str<'a>(data: &mut &'a [u8]) -> Result<&'a [u8]> {
    let n = usize::try_from(ssh_u32(data)?).unwrap_or(usize::MAX);
    if n > data.len() {
        return Err(value_error("Invalid data"));
    }
    let (head, tail) = data.split_at(n);
    *data = tail;
    Ok(head)
}

fn ssh_curve(key_type: &[u8]) -> Option<(&'static [u8], &'static [u8])> {
    match key_type {
        b"ecdsa-sha2-nistp256" => Some((b"nistp256", OID_P256)),
        b"ecdsa-sha2-nistp384" => Some((b"nistp384", &[0x2b, 0x81, 0x04, 0x00, 0x22])),
        b"ecdsa-sha2-nistp521" => Some((b"nistp521", &[0x2b, 0x81, 0x04, 0x00, 0x23])),
        _ => None,
    }
}

const SSH_OTHER_KEY_TYPES: &[&[u8]] = &[
    b"ssh-rsa",
    b"ssh-dss",
    b"ssh-ed25519",
    b"sk-ssh-ed25519@openssh.com",
    b"sk-ecdsa-sha2-nistp256@openssh.com",
];

fn unsupported_ssh_key_type(key_type: &[u8]) -> KeyError {
    value_error(format!("Unsupported key type: {}", bytes_repr(key_type)))
}

/// `_SSHFormatECDSA.get_public`, returning (curve OID, point).
fn ssh_ecdsa_public<'a>(data: &mut &'a [u8], ssh_curve_name: &[u8]) -> Result<&'a [u8]> {
    let curve = ssh_str(data)?;
    let point = ssh_str(data)?;
    if curve != ssh_curve_name {
        return Err(value_error("Curve name mismatch"));
    }
    if point.is_empty() {
        return Err(value_error("Invalid EC point: empty data"));
    }
    if point[0] != 4 {
        return Err(KeyError::Crash(PyException::new(
            "NotImplementedError",
            "Need uncompressed point",
        )));
    }
    Ok(point)
}

fn load_ssh_public_key(raw: &[u8]) -> Result<()> {
    let is_space = |b: &u8| matches!(b, b' ' | b'\t' | b'\n' | b'\r' | b'\x0b' | b'\x0c');
    let type_end = raw.iter().position(is_space).unwrap_or(raw.len());
    let key_type = &raw[..type_end];
    let rest = &raw[type_end..];
    let sep = rest
        .iter()
        .take_while(|b| matches!(b, b' ' | b'\t'))
        .count();
    let body_start = &rest[sep..];
    let body_end = body_start
        .iter()
        .position(is_space)
        .unwrap_or(body_start.len());
    if key_type.is_empty() || sep == 0 || body_end == 0 {
        return Err(value_error("Invalid line format"));
    }
    let key_body = &body_start[..body_end];
    if key_type.ends_with(b"-cert-v01@openssh.com") {
        // Certificates carry a public key too; irrd-ng does not parse them.
        return Err(value_error("Invalid key format"));
    }
    let Some((curve_name, curve_oid)) = ssh_curve(key_type) else {
        if SSH_OTHER_KEY_TYPES.contains(&key_type) {
            return Err(not_ec());
        }
        return Err(unsupported_ssh_key_type(key_type));
    };
    let decoded = a2b_base64(key_body).map_err(|_| value_error("Invalid format"))?;
    let mut data = decoded.as_slice();
    let inner = ssh_str(&mut data)?;
    if inner != key_type {
        return Err(value_error("Invalid key format"));
    }
    let point = ssh_ecdsa_public(&mut data, curve_name)?;
    check_point(curve_oid, point).map_err(|_| value_error(INVALID_KEY))?;
    if !data.is_empty() {
        return Err(value_error("Corrupt data: unparsed data"));
    }
    Ok(())
}

fn load_ssh_private_key(raw: &[u8]) -> Result<()> {
    const START: &[u8] = b"-----BEGIN OPENSSH PRIVATE KEY-----";
    const END: &[u8] = b"-----END OPENSSH PRIVATE KEY-----";
    let not_format = || value_error("Not OpenSSH private key format");
    let start = raw
        .windows(START.len())
        .position(|w| w == START)
        .ok_or_else(not_format)?
        + START.len();
    let end = raw[start..]
        .windows(END.len())
        .position(|w| w == END)
        .ok_or_else(not_format)?
        + start;
    let decoded = a2b_base64(&raw[start..end]).map_err(value_error)?;
    let mut data = decoded
        .strip_prefix(b"openssh-key-v1\0")
        .ok_or_else(not_format)?;
    let ciphername = ssh_str(&mut data)?;
    let kdfname = ssh_str(&mut data)?;
    let kdfoptions = ssh_str(&mut data)?;
    if ssh_u32(&mut data)? != 1 {
        return Err(value_error("Only one key supported"));
    }
    let mut pubdata = ssh_str(&mut data)?;
    let pub_key_type = ssh_str(&mut pubdata)?;
    let Some((curve_name, curve_oid)) = ssh_curve(pub_key_type) else {
        if SSH_OTHER_KEY_TYPES.contains(&pub_key_type) {
            return Err(not_ec());
        }
        return Err(unsupported_ssh_key_type(pub_key_type));
    };
    let pub_point = ssh_ecdsa_public(&mut pubdata, curve_name)?;
    if !pubdata.is_empty() {
        return Err(value_error("Corrupt data: unparsed data"));
    }
    if ciphername != b"none" || kdfname != b"none" {
        // (block length, AEAD tag length) of the ciphers cryptography knows.
        let (block_len, tag_len) = match ciphername {
            b"aes256-ctr" | b"aes256-cbc" => (16, None),
            b"aes256-gcm@openssh.com" => (16, Some(16)),
            other => {
                return Err(value_error(format!(
                    "Unsupported cipher: {}",
                    bytes_repr(other)
                )));
            }
        };
        if kdfname != b"bcrypt" {
            // Python shows the kdf name as a memoryview repr here.
            return Err(value_error("Unsupported KDF"));
        }
        let edata = ssh_str(&mut data)?;
        match tag_len {
            Some(n) if data.len() != n => {
                return Err(value_error("Corrupt data: invalid tag length for cipher"));
            }
            Some(_) => {}
            None if !data.is_empty() => {
                return Err(value_error("Corrupt data: unparsed data"));
            }
            None => {}
        }
        if edata.is_empty() || edata.len() % block_len != 0 {
            return Err(value_error("Corrupt data: missing padding"));
        }
        let mut kbuf = kdfoptions;
        ssh_str(&mut kbuf)?;
        ssh_u32(&mut kbuf)?;
        if !kbuf.is_empty() {
            return Err(value_error("Corrupt data: unparsed data"));
        }
        return Err(KeyError::Crash(PyException::type_error(
            "Key is password-protected, but password was not provided.",
        )));
    }
    let mut edata = ssh_str(&mut data)?;
    if !data.is_empty() {
        return Err(value_error("Corrupt data: unparsed data"));
    }
    if edata.is_empty() || edata.len() % 8 != 0 {
        return Err(value_error("Corrupt data: missing padding"));
    }
    let ck1 = ssh_u32(&mut edata)?;
    let ck2 = ssh_u32(&mut edata)?;
    if ck1 != ck2 {
        return Err(value_error("Corrupt data: broken checksum"));
    }
    let key_type = ssh_str(&mut edata)?;
    if key_type != pub_key_type {
        return Err(value_error("Corrupt data: key type mismatch"));
    }
    let point = ssh_ecdsa_public(&mut edata, curve_name)?;
    let secret = ssh_str(&mut edata)?;
    if secret.first().is_some_and(|b| *b > 0x7f) {
        return Err(value_error("Invalid data"));
    }
    if point != pub_point {
        return Err(value_error("Corrupt data: ecdsa field mismatch"));
    }
    if curve_oid == OID_P256 {
        let trimmed: Vec<u8> = secret.iter().copied().skip_while(|b| *b == 0).collect();
        let mut padded = vec![0u8; 32usize.saturating_sub(trimmed.len())];
        padded.extend_from_slice(&trimmed);
        p256::SecretKey::from_slice(&padded).map_err(|_| value_error("Invalid EC key."))?;
    }
    let _comment = ssh_str(&mut edata)?;
    let padding_ok = edata
        .iter()
        .enumerate()
        .all(|(i, b)| usize::from(*b) == i + 1);
    if !padding_ok {
        return Err(value_error("Corrupt data: invalid padding"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const P256_PUB: &str = "-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAELKaMQb8oBd3nQ3ESLPkwfJmSAIc2
DDbfu0ofoocKgnihO3oOQjuFGu9yikyE1rlaufo2Up0p04/7T+kXs+T5sQ==
-----END PUBLIC KEY-----
";

    fn check(s: &str, private: bool) -> std::result::Result<(), String> {
        eckey_from_str(&Value::str(s), private).map_err(|e| match e {
            KeyError::Value(v) => v,
            KeyError::Crash(c) => format!("CRASH {c}"),
        })
    }

    #[test]
    fn public_key() {
        assert_eq!(check(P256_PUB, false), Ok(()));
        assert_eq!(
            check(P256_PUB, true),
            Err("ECKey is a public key, but must be a private key".to_owned())
        );
        assert_eq!(
            check(&P256_PUB.replace("DDbfu0", "DDbfu1"), false),
            Err("Invalid key".to_owned())
        );
    }

    #[test]
    fn errors_match_cryptography() {
        // Texts observed from v4's eckey_from_str with cryptography 50.
        assert_eq!(
            check("invalid", false),
            Err(format!(
                "{DESERIALIZE_PREFIX}ASN.1 parsing error: short data (needed at least 105 additional bytes)"
            ))
        );
        assert_eq!(
            check(" ", false),
            Err(format!(
                "{DESERIALIZE_PREFIX}ASN.1 parsing error: short data (needed at least 1 additional bytes)"
            ))
        );
        assert_eq!(
            check(
                &(P256_PUB[..60].to_owned() + "\n-----END PUBLIC KEY-----\n"),
                false
            ),
            Err(format!(
                "{PEM_LOAD_PREFIX}InvalidData(Invalid input length: 33)"
            ))
        );
        assert_eq!(
            check(&P256_PUB.replace("MFkw", "M!kw"), false),
            Err(format!(
                "{PEM_LOAD_PREFIX}InvalidData(Invalid symbol 33, offset 1.)"
            ))
        );
        assert_eq!(
            check(P256_PUB.split("-----END").next().unwrap_or(""), false),
            Err(format!("{PEM_LOAD_PREFIX}MalformedFraming"))
        );
        assert_eq!(
            check(
                &P256_PUB.replace("END PUBLIC KEY", "END PRIVATE KEY"),
                false
            ),
            Err(format!(
                "{PEM_LOAD_PREFIX}MismatchedTags(\"PUBLIC KEY\", \"PRIVATE KEY\")"
            ))
        );
        assert_eq!(
            check(
                "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
                false
            ),
            Err(format!(
                "{DESERIALIZE_PREFIX}ASN.1 parsing error: unexpected tag (got Tag {{ value: 0, constructed: false, class: Universal }})"
            ))
        );
        assert_eq!(
            check("ecdsa-sha2-nistp256 AAAA", false),
            Err("Invalid data".to_owned())
        );
        assert_eq!(
            check("OPENSSH PRIVATE", false),
            Err("Not OpenSSH private key format".to_owned())
        );
    }
}
