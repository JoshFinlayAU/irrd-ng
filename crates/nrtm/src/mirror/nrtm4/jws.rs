//! v4's `jws_deserialize` (joserfc `deserialize_compact` with v4's
//! registry) and `eckey_from_str` for public keys: verify an ES256 JWS
//! compact serialization with a P-256 key.
//!
//! The error texts are joserfc's (`error: description`), for the paths an
//! Update Notification File can take.

use p256::ecdsa::signature::Verifier as _;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::pkcs8::DecodePublicKey as _;

use crate::mirror::nrtm4::json;

/// v4 raises `jws_registry.max_payload_length` to 10 MiB.
const MAX_PAYLOAD_LENGTH: usize = 10 * 1024 * 1024;
const MAX_HEADER_LENGTH: usize = 512;
const MAX_SIGNATURE_LENGTH: usize = 1024;

/// joserfc's recommended algorithms, the only ones v4's registry allows
/// without an explicit list.
const RECOMMENDED: &[&str] = &["HS256", "RS256", "ES256"];
const SUPPORTED: &[&str] = &[
    "ES256", "ES256K", "ES384", "ES512", "Ed25519", "Ed448", "EdDSA", "HS256", "HS384", "HS512",
    "PS256", "PS384", "PS512", "RS256", "RS384", "RS512", "none",
];

/// JWS header parameters joserfc knows (`JWS_HEADER_REGISTRY`).
const HEADER_REGISTRY: &[&str] = &[
    "alg", "jku", "jwk", "kid", "x5u", "x5c", "x5t", "x5t#S256", "typ", "cty", "crit", "b64",
];

/// An EC public key, as far as signature checks need it.
#[derive(Debug, Clone)]
pub enum EcKey {
    /// A P-256 key.
    P256(VerifyingKey),
    /// A key on another curve (`P-384`, `P-521`, `secp256k1`).
    Other(&'static str),
}

/// `eckey_from_str(key)` for verification: PEM public or private keys and
/// OpenSSH public keys. The error is the `ValueError` text.
pub fn eckey_from_str(s: &str) -> Result<EcKey, String> {
    let t = s.trim();
    if let Ok(k) = p256::PublicKey::from_public_key_pem(t) {
        return Ok(EcKey::P256(VerifyingKey::from(k)));
    }
    if let Ok(k) = <p256::SecretKey as p256::pkcs8::DecodePrivateKey>::from_pkcs8_pem(t) {
        return Ok(EcKey::P256(VerifyingKey::from(k.public_key())));
    }
    if let Ok(k) = p256::SecretKey::from_sec1_pem(t) {
        return Ok(EcKey::P256(VerifyingKey::from(k.public_key())));
    }
    if let Some(k) = openssh_p256(t) {
        return Ok(EcKey::P256(k));
    }
    // Other curves: the curve OID inside the DER is enough here.
    if let Some(der) = pem_body(t) {
        let curves: [(&[u8], &'static str); 3] = [
            (&[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22], "P-384"),
            (&[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23], "P-521"),
            (&[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x0a], "secp256k1"),
        ];
        for (oid, name) in curves {
            if der.windows(oid.len()).any(|w| w == oid) {
                return Ok(EcKey::Other(name));
            }
        }
    }
    match config::eckey_check(s) {
        Err(Ok(ve)) => Err(ve),
        Err(Err(e)) => Err(e.message),
        Ok(()) => Err("Invalid key".into()),
    }
}

fn pem_body(s: &str) -> Option<Vec<u8>> {
    let mut body = String::new();
    let mut inside = false;
    for line in s.lines() {
        let l = line.trim();
        if l.starts_with("-----BEGIN") {
            inside = true;
        } else if l.starts_with("-----END") {
            break;
        } else if inside {
            body.push_str(l);
        }
    }
    b64_standard(&body)
}

fn b64_standard(s: &str) -> Option<Vec<u8>> {
    let val = |c: u8| -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => u32::from(c - b'A'),
            b'a'..=b'z' => u32::from(c - b'a') + 26,
            b'0'..=b'9' => u32::from(c - b'0') + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            _ => return None,
        })
    };
    let mut out = Vec::new();
    let mut acc = 0u32;
    let mut bits = 0;
    for c in s.bytes().filter(|c| *c != b'=') {
        acc = (acc << 6) | val(c)?;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

fn openssh_p256(s: &str) -> Option<VerifyingKey> {
    let mut parts = s.split_whitespace();
    if parts.next()? != "ecdsa-sha2-nistp256" {
        return None;
    }
    let blob = b64_standard(parts.next()?)?;
    let mut rest: &[u8] = &blob;
    let mut field = || -> Option<Vec<u8>> {
        let len = u32::from_be_bytes(rest.get(..4)?.try_into().ok()?) as usize;
        let v = rest.get(4..4 + len)?.to_vec();
        rest = &rest[4 + len..];
        Some(v)
    };
    let (kind, curve, point) = (field()?, field()?, field()?);
    if kind != b"ecdsa-sha2-nistp256" || curve != b"nistp256" {
        return None;
    }
    VerifyingKey::from_sec1_bytes(&point).ok()
}

/// joserfc's `urlsafe_b64decode`: no `+`, `/` or `=`, canonical trailing
/// bits.
fn urlsafe_b64decode(s: &[u8]) -> Option<Vec<u8>> {
    if s.iter().any(|c| matches!(c, b'+' | b'/' | b'=')) {
        return None;
    }
    let pad = (4 - s.len() % 4) % 4;
    if pad == 3 {
        return None;
    }
    let safe_ending: [&[u8]; 2] = [b"AEIMQUYcgkosw048", b"AQgw"];
    if pad > 0 && !safe_ending[pad - 1].contains(s.last()?) {
        return None;
    }
    let mut out = Vec::new();
    let mut acc = 0u32;
    let mut bits = 0;
    for &c in s {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

fn jose(error: &str, description: &str) -> String {
    format!("{error}: {description}")
}

/// `jws_deserialize(value, public_key)`: the payload, or the `ValueError`
/// text v4 wraps the joserfc error in.
pub fn jws_deserialize(value: &[u8], key: &EcKey) -> Result<Vec<u8>, String> {
    let parts: Vec<&[u8]> = value.split(|b| *b == b'.').collect();
    if parts.len() != 3 {
        return Err(jose("decode_error", "Invalid JSON Web Signature"));
    }
    let (header_seg, payload_seg, sig_seg) = (parts[0], parts[1], parts[2]);
    if !header_seg.is_empty() && header_seg.len() > MAX_HEADER_LENGTH {
        return Err(jose(
            "exceeded_size",
            &format!("Header size exceeds {MAX_HEADER_LENGTH} bytes."),
        ));
    }
    if sig_seg.len() > MAX_SIGNATURE_LENGTH {
        return Err(jose(
            "exceeded_size",
            &format!("Signature of exceeds {MAX_SIGNATURE_LENGTH} bytes."),
        ));
    }
    if !payload_seg.is_empty() && payload_seg.len() > MAX_PAYLOAD_LENGTH {
        return Err(jose(
            "exceeded_size",
            &format!("Payload size exceeds {MAX_PAYLOAD_LENGTH} bytes."),
        ));
    }
    // decode_header
    let invalid_header = || jose("decode_error", "Invalid header");
    let header_bytes = urlsafe_b64decode(header_seg).ok_or_else(invalid_header)?;
    let header = json::loads(&header_bytes).map_err(|_| invalid_header())?;
    let has_alg = match &header {
        config::Value::Dict(_) => json::get(&header, "alg").is_some(),
        config::Value::List(l) => l.iter().any(|v| v.as_str() == Some("alg")),
        config::Value::Str(s) => s.contains("alg"),
        _ => return Err(invalid_header()),
    };
    if !has_alg {
        return Err(jose("missing_algorithm", "Missing 'alg' value in header"));
    }
    let config::Value::Dict(d) = &header else {
        return Err(invalid_header());
    };
    let rfc7797 = matches!(json::get(&header, "b64"), Some(config::Value::Bool(false)));
    let payload = if rfc7797 {
        payload_seg.to_vec()
    } else {
        urlsafe_b64decode(payload_seg).ok_or_else(|| jose("decode_error", "Invalid payload"))?
    };

    // check_header: crit, registry values, unknown keys.
    if let Some(crit) = json::get(&header, "crit") {
        let names: Vec<String> = match crit {
            config::Value::List(l) => l.iter().map(config::Value::py_str).collect(),
            _ => Vec::new(),
        };
        let missing: Vec<&String> = names
            .iter()
            .filter(|k| json::get(&header, k).is_none())
            .collect();
        let unsupported: Vec<String> = names
            .iter()
            .filter(|k| json::get(&header, k).is_some() && !HEADER_REGISTRY.contains(&k.as_str()))
            .cloned()
            .collect();
        if !missing.is_empty() {
            return Err(jose(
                "missing_crit_header",
                &missing
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(","),
            ));
        } else if !unsupported.is_empty() {
            return Err(jose(
                "unsupported_header",
                &format!(
                    "Unsupported {} in header",
                    config::str_list_repr(&unsupported)
                ),
            ));
        }
    }
    let alg = match json::get(&header, "alg") {
        Some(config::Value::Str(s)) => s.clone(),
        _ => {
            return Err(jose(
                "invalid_header_value",
                "'alg' in header must be a str",
            ));
        }
    };
    let unknown: Vec<String> = d
        .keys()
        .map(config::Value::py_str)
        .filter(|k| !HEADER_REGISTRY.contains(&k.as_str()))
        .collect();
    if !unknown.is_empty() {
        let set = format!(
            "{{{}}}",
            unknown
                .iter()
                .map(|k| config::str_repr(k))
                .collect::<Vec<_>>()
                .join(", ")
        );
        return Err(jose(
            "unsupported_header",
            &format!("Unsupported {set} in header"),
        ));
    }
    // get_alg
    if !SUPPORTED.contains(&alg.as_str()) {
        return Err(jose(
            "unsupported_algorithm",
            &format!("Algorithm of '{alg}' is not supported"),
        ));
    }
    if !RECOMMENDED.contains(&alg.as_str()) {
        return Err(jose(
            "unsupported_algorithm",
            &format!("Algorithm of '{alg}' is not recommended"),
        ));
    }
    match alg.as_str() {
        "HS256" => {
            return Err(jose(
                "invalid_key_type",
                "Algorithm 'HS256' requires 'oct' key",
            ));
        }
        "RS256" => {
            return Err(jose(
                "invalid_key_type",
                "Algorithm 'RS256' requires 'RSA' key",
            ));
        }
        _ => {}
    }
    let vk = match key {
        EcKey::P256(k) => k,
        EcKey::Other(_) => {
            return Err(jose(
                "invalid_key_curve",
                "Key for 'ES256' not supported, only 'P-256' allowed",
            ));
        }
    };
    let bad = || jose("bad_signature", "");
    let sig = urlsafe_b64decode(sig_seg).ok_or_else(bad)?;
    if sig.len() != 64 {
        return Err(bad());
    }
    let sig = Signature::from_slice(&sig).map_err(|_| bad())?;
    let mut signing_input = header_seg.to_vec();
    signing_input.push(b'.');
    signing_input.extend_from_slice(payload_seg);
    vk.verify(&signing_input, &sig).map_err(|_| bad())?;
    Ok(payload)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use p256::ecdsa::SigningKey;
    use p256::ecdsa::signature::Signer as _;

    // v4's irrd/mirroring/nrtm4/tests/__init__.py keys.
    pub(crate) const PRIVATE: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgGQrdALKHTVC4sVav\nmKUjXaPB22CWZP3t5XSkLqKHMO2hRANCAAQ9U/aaZwLV4koey4Jvu9cRaxiXna9k\naQ3YwrPzZlwd5MQSZ59kfT2+LAbQmXbZg0NGzptqHoOK0YD3YVBjv4kc\n-----END PRIVATE KEY-----\n";
    pub(crate) const PUBLIC: &str = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEPVP2mmcC1eJKHsuCb7vXEWsYl52v\nZGkN2MKz82ZcHeTEEmefZH09viwG0Jl22YNDRs6bah6DitGA92FQY7+JHA==\n-----END PUBLIC KEY-----\n";
    pub(crate) const PRIVATE_OTHER: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgmHtbXrQ0uEcrzeZK\niaK8UnpD5c/YAmqdUHqoHLz997ShRANCAAQ18hSL1o3ynp1kLsfXgZBtlWSYwKvc\nLT2qRj7QeJPxHA6X3XMk7eD6xbdeyNFnLXiKwNPFMPcwRLC6oLN81Fvb\n-----END PRIVATE KEY-----\n";

    fn b64(b: &[u8]) -> String {
        const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut out = String::new();
        for c in b.chunks(3) {
            let n = c.iter().fold(0u32, |a, x| (a << 8) | u32::from(*x)) << (8 * (3 - c.len()));
            for i in 0..=c.len() {
                out.push(A[((n >> (18 - 6 * i)) & 63) as usize] as char);
            }
        }
        out
    }

    /// `jws_serialize(payload, private_key)` for tests.
    pub(crate) fn sign(payload: &[u8], private_pem: &str) -> String {
        let sk = <p256::SecretKey as p256::pkcs8::DecodePrivateKey>::from_pkcs8_pem(private_pem)
            .expect("key");
        let signing = SigningKey::from(sk);
        let input = format!("{}.{}", b64(br#"{"alg":"ES256"}"#), b64(payload));
        let sig: Signature = signing.sign(input.as_bytes());
        format!("{input}.{}", b64(&sig.to_bytes()))
    }

    // Recorded from joserfc 1.7.4 in the pinned v4.
    #[test]
    fn joserfc_outcomes() {
        let pub_key = eckey_from_str(PUBLIC).expect("public");
        let other = eckey_from_str(PRIVATE_OTHER).expect("private");
        let good = sign(br#"{"a":1}"#, PRIVATE);
        assert_eq!(
            jws_deserialize(good.as_bytes(), &pub_key).expect("good"),
            br#"{"a":1}"#
        );
        assert_eq!(
            jws_deserialize(good.as_bytes(), &other).expect_err("key"),
            "bad_signature: "
        );
        let cases: Vec<(String, &str)> = vec![
            ("garbage".into(), "decode_error: Invalid JSON Web Signature"),
            ("a.b".into(), "decode_error: Invalid JSON Web Signature"),
            ("!!!.e30.AAAA".into(), "decode_error: Invalid header"),
            (
                format!("{}.e30.{}", b64(b"xx"), b64(&[b'x'; 64])),
                "decode_error: Invalid header",
            ),
            (
                format!("{}.e30.{}", b64(br#"{"alg":"HS256"}"#), b64(&[b'x'; 32])),
                "invalid_key_type: Algorithm 'HS256' requires 'oct' key",
            ),
            (
                format!("{}.e30.", b64(br#"{"alg":"none"}"#)),
                "unsupported_algorithm: Algorithm of 'none' is not recommended",
            ),
            (
                format!("{}.e30.{}", b64(br#"{"alg":"ES384"}"#), b64(&[b'x'; 96])),
                "unsupported_algorithm: Algorithm of 'ES384' is not recommended",
            ),
            (
                format!("{}.e30.{}", b64(b"{}"), b64(&[b'x'; 64])),
                "missing_algorithm: Missing 'alg' value in header",
            ),
            (
                format!(
                    "{}.{}",
                    good.rsplit_once('.').expect("sig").0,
                    b64(&[b'x'; 10])
                ),
                "bad_signature: ",
            ),
            (format!("{good}=="), "bad_signature: "),
            (
                format!(
                    "{}.e30.{}",
                    b64(br#"{"alg":"ES256","crit":["foo"],"foo":1}"#),
                    b64(&[b'x'; 64])
                ),
                "unsupported_header: Unsupported ['foo'] in header",
            ),
            (String::new(), "decode_error: Invalid JSON Web Signature"),
        ];
        for (v, want) in cases {
            assert_eq!(
                jws_deserialize(v.as_bytes(), &pub_key).expect_err(&v),
                want,
                "{v}"
            );
        }
    }
}
