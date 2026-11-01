//! Password and key checks on `auth:` lines (`irrd/rpsl/auth.py`) and the
//! `RPSLMntner` helpers built on them.
//!
//! v4 verifies with passlib 1.7.4: `des_crypt` and `md5_crypt` from its
//! builtin backends (Python 3.13 has no `crypt` module) and `bcrypt` over
//! the `bcrypt` 4.3 package, which silently truncates passwords at 72
//! bytes. passlib refuses passwords containing a NUL byte for all three
//! schemes, and any malformed hash raises `ValueError`; v4 treats both as a
//! failed check.

use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::Arc;

use crate::fields::{PASSWORD_HASH_DUMMY_VALUE, RPSL_MNTNER_AUTH_INTERNAL};
use crate::parser::{RpslObject, Value};
use crate::py;
use crate::settings::{PasswordHasher, RpslSettings};

/// Verify one password against a hash of one scheme, as passlib's
/// `hasher.verify(password, hash)` inside v4's `try/except ValueError`.
pub fn verify_password(hasher: PasswordHasher, password: &str, hash: &str) -> bool {
    if password.contains('\0') {
        return false;
    }
    match hasher {
        PasswordHasher::CryptPw => des_crypt_verify(password, hash),
        PasswordHasher::Md5Pw => md5_crypt_verify(password, hash),
        PasswordHasher::BcryptPw => bcrypt_verify(password, hash),
    }
}

const HASH64: &[u8] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

fn des_crypt_verify(password: &str, hash: &str) -> bool {
    // passlib: ^(?P<salt>[./a-z0-9]{2})(?P<chk>[./a-z0-9]{11})?$ (re.I);
    // a config string without checksum raises.
    if hash.len() != 13 || !hash.bytes().all(|b| HASH64.contains(&b)) {
        return false;
    }
    pwhash::unix_crypt::verify(password.as_bytes(), hash)
}

fn md5_crypt_verify(password: &str, hash: &str) -> bool {
    // passlib: ^\$1\$(?P<salt>[./0-9A-Za-z]{0,8})(\$(?P<chk>[./0-9A-Za-z]{22})?)?$
    let Some(rest) = hash.strip_prefix("$1$") else {
        return false;
    };
    let Some((salt, chk)) = rest.split_once('$') else {
        return false;
    };
    if salt.len() > 8
        || !salt.bytes().all(|b| HASH64.contains(&b))
        || chk.len() != 22
        || !chk.bytes().all(|b| HASH64.contains(&b))
    {
        return false;
    }
    pwhash::md5_crypt::verify(password.as_bytes(), hash)
}

/// bcrypt results worked out ahead of time, keyed by (hash, password).
pub type BcryptResults = HashMap<(String, String), bool>;

thread_local! {
    static PRECOMPUTED: RefCell<Option<Arc<BcryptResults>>> = const { RefCell::new(None) };
}

/// Check every password against every bcrypt hash in parallel, so the
/// results can be used later without doing the work again. Bcrypt at the
/// highest cost v4 allows takes seconds per check, and a submission is
/// checked while the store's single write lock is held, so the
/// submission handler does this first, outside the lock.
pub fn precompute_bcrypt(hashes: &[String], passwords: &[String]) -> BcryptResults {
    let pairs: Vec<(&String, &String)> = hashes
        .iter()
        .flat_map(|h| passwords.iter().map(move |p| (h, p)))
        .collect();
    let threads = std::thread::available_parallelism()
        .map_or(1, |n| n.get())
        .min(8)
        .min(pairs.len().max(1));
    let chunk = pairs.len().div_ceil(threads).max(1);
    let mut out = BcryptResults::new();
    std::thread::scope(|scope| {
        let workers: Vec<_> = pairs
            .chunks(chunk)
            .map(|part| {
                scope.spawn(move || {
                    part.iter()
                        .map(|(h, p)| (((*h).clone(), (*p).clone()), bcrypt_verify_now(p, h)))
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        for w in workers {
            if let Ok(results) = w.join() {
                out.extend(results);
            }
        }
    });
    out
}

/// Run `f` with `results` consulted before any bcrypt check on this thread.
/// A check that is not in `results` is done as usual.
pub fn with_precomputed_bcrypt<R>(results: Arc<BcryptResults>, f: impl FnOnce() -> R) -> R {
    // Restored on drop, so a panic in `f` does not leave the results on a
    // thread that handles other work afterwards.
    struct Restore(Option<Arc<BcryptResults>>);
    impl Drop for Restore {
        fn drop(&mut self) {
            let previous = self.0.take();
            PRECOMPUTED.with(|c| *c.borrow_mut() = previous);
        }
    }
    let _restore = Restore(PRECOMPUTED.with(|c| c.replace(Some(results))));
    f()
}

fn bcrypt_verify(password: &str, hash: &str) -> bool {
    let known = PRECOMPUTED.with(|c| {
        c.borrow()
            .as_ref()
            .and_then(|m| m.get(&(hash.to_owned(), password.to_owned())).copied())
    });
    known.unwrap_or_else(|| bcrypt_verify_now(password, hash))
}

fn bcrypt_verify_now(password: &str, hash: &str) -> bool {
    // passlib accepts 2a, 2b and 2y (its backend refuses 2 and 2x), any
    // cost from 4 to 31, and raises on a config string without checksum.
    if !hash_shape_ok_ignoring_cost(hash) {
        return false;
    }
    // bcrypt 4.3 truncates at 72 bytes; pwhash implements 2a, 2b and 2y
    // identically, as bcrypt does for passwords this short.
    pwhash::bcrypt::verify(truncate_bytes(password.as_bytes(), 72), hash)
}

/// Whether `hash` is a bcrypt hash passlib would check, with a cost no
/// higher than v4 accepts in a submission (`BCRYPT_MAX_ROUNDS`).
pub fn bcrypt_hash_within_limits(hash: &str) -> bool {
    hash_shape_ok_ignoring_cost(hash)
        && hash
            .get(4..6)
            .and_then(|c| c.parse::<u32>().ok())
            .is_some_and(|c| c <= crate::fields::BCRYPT_MAX_ROUNDS)
}

fn hash_shape_ok_ignoring_cost(hash: &str) -> bool {
    let Some(tail) = ["$2a$", "$2y$", "$2b$"]
        .iter()
        .find_map(|ident| hash.strip_prefix(ident))
    else {
        return false;
    };
    let Some((cost, data)) = tail.split_once('$') else {
        return false;
    };
    cost.len() == 2
        && cost.bytes().all(|b| b.is_ascii_digit())
        && cost.parse::<u32>().is_ok_and(|c| (4..=31).contains(&c))
        && data.len() == 53
        // passlib raises ValueError on other characters, which v4 treats
        // as a failed check; pwhash would panic on control characters.
        && data.bytes().all(|b| HASH64.contains(&b))
}

fn truncate_bytes(b: &[u8], n: usize) -> &[u8] {
    &b[..b.len().min(n)]
}

/// `PASSWORD_REPLACEMENT_HASH`: a new `BCRYPT-PW` hash of `password`, as
/// passlib's `bcrypt.hash(password)` makes it (ident 2b, 12 rounds, random
/// salt).
pub fn bcrypt_hash(password: &str) -> Option<String> {
    use pwhash::bcrypt::{BcryptSetup, BcryptVariant};
    let truncated = truncate_bytes(password.as_bytes(), 72);
    pwhash::bcrypt::hash_with(
        BcryptSetup {
            salt: None,
            cost: Some(12),
            variant: Some(BcryptVariant::V2b),
        },
        truncated,
    )
    .ok()
}

/// `verify_auth_lines(auth_lines, passwords, keycert_obj_pk)`: the scheme
/// (or key-cert key) that authenticated, or `None`.
pub fn verify_auth_lines(
    auth_lines: &[String],
    passwords: &[String],
    keycert_obj_pk: Option<&str>,
    settings: &RpslSettings,
) -> Option<String> {
    let hashers = settings.password_hashers(true);
    for auth in auth_lines {
        if let Some(pk) = keycert_obj_pk
            && !pk.is_empty()
            && py::upper(auth) == py::upper(pk)
        {
            return Some(py::upper(pk).into_owned());
        }
        let Some((scheme, hash)) = auth.split_once(' ') else {
            continue;
        };
        let scheme = py::upper(scheme);
        let Some(hasher) = hashers.iter().find(|h| h.scheme() == scheme) else {
            continue;
        };
        for password in passwords {
            if verify_password(*hasher, password, hash) {
                return Some(scheme.into_owned());
            }
        }
    }
    None
}

impl RpslObject {
    fn auth_values(&self) -> &[String] {
        self.parsed_value("auth")
            .and_then(Value::as_list)
            .unwrap_or_default()
    }

    /// `RPSLMntner.verify_auth(passwords, keycert_obj_pk)`.
    pub fn verify_auth(
        &self,
        passwords: &[String],
        keycert_obj_pk: Option<&str>,
        settings: &RpslSettings,
    ) -> Option<String> {
        verify_auth_lines(self.auth_values(), passwords, keycert_obj_pk, settings)
    }

    /// `RPSLMntner.has_internal_auth()`.
    pub fn has_internal_auth(&self) -> bool {
        self.auth_values()
            .iter()
            .any(|a| a == RPSL_MNTNER_AUTH_INTERNAL)
    }

    /// `RPSLMntner.force_single_new_password(password)`: drop every password
    /// hash, keep the other methods and append one new `BCRYPT-PW` hash.
    pub fn force_single_new_password(&mut self, password: &str) {
        let mut auths: Vec<String> = self
            .auth_values()
            .iter()
            .filter(|a| !a.contains(' '))
            .cloned()
            .collect();
        let hash = bcrypt_hash(password).unwrap_or_default();
        auths.push(format!("BCRYPT-PW {hash}"));
        self.update_attribute_value("auth", auths, false);
    }

    /// Whether every password hash on this object is the dummy value.
    pub fn all_hashes_dummy(&self) -> bool {
        let hashes: Vec<&str> = self
            .auth_values()
            .iter()
            .filter_map(|a| a.split_once(' ').map(|(_, h)| h))
            .collect();
        !hashes.is_empty() && hashes.iter().all(|h| *h == PASSWORD_HASH_DUMMY_VALUE)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    // Hashes made by passlib 1.7.4 in the pinned v4 image.
    const DES: &str = "1HS6flSnGGO/U"; // pässwörd1234
    const MD5: &str = "$1$J6KycItM$MbPaBU6iFSGFV299Rk7Di0";

    #[test]
    fn des_crypt_uses_eight_bytes() {
        assert!(verify_password(PasswordHasher::CryptPw, "pässwör", DES));
        assert!(verify_password(PasswordHasher::CryptPw, "pässwörd", DES));
        assert!(!verify_password(PasswordHasher::CryptPw, "pässw", DES));
        assert!(!verify_password(PasswordHasher::CryptPw, "x", "ab"));
    }

    #[test]
    fn md5_crypt_shapes() {
        assert!(!verify_password(PasswordHasher::Md5Pw, "x", MD5));
        assert!(!verify_password(
            PasswordHasher::Md5Pw,
            "x",
            "$1$123456789$MbPaBU6iFSGFV299Rk7Di0"
        ));
        let h = "$1$abcdefgh$cHJi5PXp/ki/ktXzqlk6I1"; // passlib, "secret"
        assert!(verify_password(PasswordHasher::Md5Pw, "secret", h));
        assert!(!verify_password(PasswordHasher::Md5Pw, "sec\0ret", h));
    }

    #[test]
    fn bcrypt_truncates_at_72() {
        let h = bcrypt_hash(&"a".repeat(72)).unwrap();
        assert!(h.starts_with("$2b$12$"));
        assert!(verify_password(
            PasswordHasher::BcryptPw,
            &"a".repeat(80),
            &h
        ));
        assert!(!verify_password(
            PasswordHasher::BcryptPw,
            &"a".repeat(71),
            &h
        ));
    }

    #[test]
    fn bcrypt_hash_with_bad_characters_fails_without_panicking() {
        let good = "$2b$12$68P0mc5.vVbdrqqSAnLtKuxfpUpqglWcjtR4QNxdwJL8iy.sOvWdW";
        for bad in ['\u{1}', '\u{1f}', ' ', '$', '!'] {
            let mut h = good.to_owned();
            h.replace_range(20..21, &bad.to_string());
            assert!(
                !verify_password(PasswordHasher::BcryptPw, "x", &h),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn bcrypt_passlib_hash_verifies() {
        // passlib: bcrypt.hash("x")
        let h = "$2b$12$68P0mc5.vVbdrqqSAnLtKuxfpUpqglWcjtR4QNxdwJL8iy.sOvWdW";
        assert!(verify_password(PasswordHasher::BcryptPw, "x", h));
        assert!(!verify_password(PasswordHasher::BcryptPw, "y", h));
    }

    // The precomputed results agree with checking directly, and are what a
    // check under with_precomputed_bcrypt uses.
    #[test]
    fn bcrypt_precomputed() {
        let h = "$2b$12$68P0mc5.vVbdrqqSAnLtKuxfpUpqglWcjtR4QNxdwJL8iy.sOvWdW".to_owned();
        let results =
            precompute_bcrypt(std::slice::from_ref(&h), &["x".to_owned(), "y".to_owned()]);
        assert_eq!(results.get(&(h.clone(), "x".to_owned())), Some(&true));
        assert_eq!(results.get(&(h.clone(), "y".to_owned())), Some(&false));

        let mut forged = BcryptResults::new();
        forged.insert((h.clone(), "y".to_owned()), true);
        let used = with_precomputed_bcrypt(Arc::new(forged), || {
            (
                verify_password(PasswordHasher::BcryptPw, "y", &h),
                verify_password(PasswordHasher::BcryptPw, "x", &h),
            )
        });
        assert_eq!(used, (true, true));
        assert!(!verify_password(PasswordHasher::BcryptPw, "y", &h));
    }

    #[test]
    fn bcrypt_hash_limits() {
        let ok = "$2b$12$68P0mc5.vVbdrqqSAnLtKuxfpUpqglWcjtR4QNxdwJL8iy.sOvWdW";
        assert!(bcrypt_hash_within_limits(ok));
        assert!(bcrypt_hash_within_limits(&ok.replace("$12$", "$16$")));
        assert!(!bcrypt_hash_within_limits(&ok.replace("$12$", "$17$")));
        assert!(!bcrypt_hash_within_limits(&ok.replace("$12$", "$31$")));
        assert!(!bcrypt_hash_within_limits("xN"));
        assert!(!bcrypt_hash_within_limits(&ok[..40]));
    }
}
