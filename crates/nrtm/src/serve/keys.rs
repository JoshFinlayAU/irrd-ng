//! The NRTMv4 server's side of `irrd/utils/crypto.py`: private keys from
//! the configuration, their PEM forms as joserfc's `ECKey.as_pem()` writes
//! them (PKCS#8 and SubjectPublicKeyInfo, 64-column base64, LF), ES256 JWS
//! compact serialisation, and `ECKey.generate_key()`.
//!
//! The signatures are deterministic (RFC 6979) where cryptography's are
//! randomised. Both are valid ES256 signatures of the same input, and a
//! signature is never the same twice in v4 either.

use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};
use p256::pkcs8::{DecodePrivateKey as _, EncodePrivateKey as _, EncodePublicKey as _, LineEnding};

/// A P-256 private key.
pub type PrivateKey = p256::SecretKey;

/// `eckey_from_str(value)` for a private key setting. The configuration
/// check has already rejected anything that is not a private EC key; P-256
/// in PKCS#8 or SEC 1 PEM is what NRTMv4 uses.
pub fn private_key_from_str(value: &str) -> Result<PrivateKey, String> {
    let t = value.trim();
    if let Ok(k) = PrivateKey::from_pkcs8_pem(t) {
        return Ok(k);
    }
    if let Ok(k) = PrivateKey::from_sec1_pem(t) {
        return Ok(k);
    }
    Err("Could not deserialize key data. The data may be in an incorrect format, it may be encrypted with an unsupported algorithm, or it may be an unsupported key type (e.g. EC curves with explicit parameters).".to_owned())
}

/// `eckey_public_key_as_str(key)`
pub fn public_key_pem(key: &PrivateKey) -> String {
    key.public_key()
        .to_public_key_pem(LineEnding::LF)
        .unwrap_or_default()
}

/// `eckey_private_key_as_str(key)`
pub fn private_key_pem(key: &PrivateKey) -> String {
    key.to_pkcs8_pem(LineEnding::LF)
        .map(|z| z.as_str().to_owned())
        .unwrap_or_default()
}

/// `ECKey.generate_key()` (P-256).
pub fn generate_private_key() -> std::io::Result<PrivateKey> {
    loop {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes).map_err(|e| std::io::Error::other(e.to_string()))?;
        if let Ok(k) = PrivateKey::from_slice(&bytes) {
            return Ok(k);
        }
    }
}

/// Unpadded base64url.
fn b64url(b: &[u8]) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(b.len().div_ceil(3) * 4);
    for c in b.chunks(3) {
        let n = c.iter().fold(0u32, |a, x| (a << 8) | u32::from(*x)) << (8 * (3 - c.len()));
        for i in 0..=c.len() {
            out.push(A[((n >> (18 - 6 * i)) & 63) as usize] as char);
        }
    }
    out
}

/// `jws_serialize(payload, key)`: compact JWS with the header
/// `{"alg":"ES256"}`.
pub fn jws_serialize(payload: &[u8], key: &PrivateKey) -> String {
    let signing = SigningKey::from(key);
    let input = format!("{}.{}", b64url(br#"{"alg":"ES256"}"#), b64url(payload));
    let sig: Signature = signing.sign(input.as_bytes());
    format!("{input}.{}", b64url(&sig.to_bytes()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::mirror::nrtm4::jws;

    // v4's irrd/mirroring/nrtm4/tests/__init__.py keys.
    const PRIVATE: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgGQrdALKHTVC4sVav\nmKUjXaPB22CWZP3t5XSkLqKHMO2hRANCAAQ9U/aaZwLV4koey4Jvu9cRaxiXna9k\naQ3YwrPzZlwd5MQSZ59kfT2+LAbQmXbZg0NGzptqHoOK0YD3YVBjv4kc\n-----END PRIVATE KEY-----\n";
    const PUBLIC: &str = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEPVP2mmcC1eJKHsuCb7vXEWsYl52v\nZGkN2MKz82ZcHeTEEmefZH09viwG0Jl22YNDRs6bah6DitGA92FQY7+JHA==\n-----END PUBLIC KEY-----\n";

    #[test]
    fn pem_like_joserfc() {
        let k = private_key_from_str(PRIVATE).unwrap();
        assert_eq!(private_key_pem(&k), PRIVATE);
        assert_eq!(public_key_pem(&k), PUBLIC);
        let g = generate_private_key().unwrap();
        let pem = private_key_pem(&g);
        assert!(pem.starts_with(
            "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg"
        ));
        assert_eq!(private_key_from_str(&pem).unwrap(), g);
    }

    #[test]
    fn signatures_verify_like_the_client() {
        let k = private_key_from_str(PRIVATE).unwrap();
        let jws_text = jws_serialize(br#"{"a":"b"}"#, &k);
        assert!(jws_text.starts_with("eyJhbGciOiJFUzI1NiJ9."));
        let public = jws::eckey_from_str(PUBLIC).unwrap();
        assert_eq!(
            jws::jws_deserialize(jws_text.as_bytes(), &public).unwrap(),
            br#"{"a":"b"}"#
        );
    }
}
