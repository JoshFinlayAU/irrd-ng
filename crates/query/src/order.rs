//! The order v4 returns RPSL objects in.
//!
//! `BaseRPSLObjectDatabaseQuery.finalise_statement()` (`irrd/storage/
//! queries.py`) orders every object query by
//! `[CASE source ...,] ip_first ASC, asn_first ASC, rpsl_pk ASC`:
//!
//! - the `CASE` only for `ordered_by_sources` queries (`!m`), by position in
//!   the query's source list;
//! - `ip_first` is an `inet`: IPv4 before IPv6, then by address, NULL last;
//! - `asn_first` is a `bigint`, NULL last;
//! - `rpsl_pk` is `varchar` in the database's collation. v4 databases are
//!   created by `initdb` under `en_US.UTF-8` (the official PostgreSQL image's
//!   default), so this is glibc's ISO 14651 collation, not byte order; see
//!   [`collate_cmp`].
//!
//! Rows equal on all of these come back in whatever order PostgreSQL's sort
//! leaves them, which for the small groups seen in practice is the order it
//! read them in, i.e. the order they were written. irrd-ng breaks such ties
//! by internal object id, which is also write order.

use std::cmp::Ordering;
use std::net::IpAddr;

use store::RpslObjectRef;

/// glibc 2.41's `en_US.UTF-8` collation (`iso14651_t1_common`), as
/// PostgreSQL's `varstr_cmp()` applies it: `strcoll()`, and `strcmp()` to
/// break exact ties.
///
/// For ASCII, measured against PostgreSQL 18.6 on Debian trixie:
///
/// 1. Letters (case-insensitively) and digits, with every punctuation
///    character and space ignored, except `$`, which sorts before the
///    digits. Digits sort before letters.
/// 2. Case, letter by letter: lower before upper.
/// 3. Every character in order, punctuation before digits and letters,
///    punctuation in the order `' !"#%&'()*+,-./:;<=>?@[\]^_`{|}~'`.
///
/// Characters outside ASCII sort after `z` by code point. That is an
/// approximation of the full ISO 14651 table, and only matters for keys
/// with non-ASCII characters, which RPSL primary keys practically never
/// have.
pub fn collate_cmp(a: &str, b: &str) -> Ordering {
    level1(a)
        .cmp(level1(b))
        .then_with(|| level_case(a).cmp(level_case(b)))
        .then_with(|| level4(a).cmp(level4(b)))
        .then_with(|| a.as_bytes().cmp(b.as_bytes()))
}

/// Primary weights: `$`, digits, letters (folded), others by code point.
fn level1(s: &str) -> impl Iterator<Item = u32> + Clone + '_ {
    s.chars().filter_map(|c| match c {
        '$' => Some(1),
        '0'..='9' => Some(10 + (c as u32 - '0' as u32)),
        'a'..='z' => Some(100 + 2 * (c as u32 - 'a' as u32)),
        'A'..='Z' => Some(100 + 2 * (c as u32 - 'A' as u32)),
        c if c.is_ascii() => None,
        c => Some(1000 + c as u32),
    })
}

/// Tertiary weights: case of each character that has a primary weight.
fn level_case(s: &str) -> impl Iterator<Item = u8> + Clone + '_ {
    s.chars().filter_map(|c| match c {
        'A'..='Z' => Some(1),
        '$' | '0'..='9' | 'a'..='z' => Some(0),
        c if c.is_ascii() => None,
        _ => Some(0),
    })
}

/// The punctuation order at the last level.
const PUNCT_ORDER: &[u8] = b" !\"#%&'()*+,-./:;<=>?@[\\]^_`{|}~";

/// Last-level weights: every character.
fn level4(s: &str) -> impl Iterator<Item = u32> + Clone + '_ {
    s.chars().map(|c| {
        if c.is_ascii()
            && let Some(p) = PUNCT_ORDER.iter().position(|&x| x == c as u8)
        {
            return p as u32;
        }
        match c {
            '$' => 100,
            '0'..='9' => 110 + (c as u32 - '0' as u32),
            'a'..='z' => 200 + 2 * (c as u32 - 'a' as u32),
            'A'..='Z' => 201 + 2 * (c as u32 - 'A' as u32),
            c if c.is_ascii() => 50 + c as u32,
            c => 1000 + c as u32,
        }
    })
}

/// `ip_first` as `inet` sorts it: family, then address. `None` sorts last.
fn inet_key(ip: Option<IpAddr>) -> (u8, u128) {
    match ip {
        Some(IpAddr::V4(v)) => (0, u128::from(u32::from(v))),
        Some(IpAddr::V6(v)) => (1, u128::from(v)),
        None => (2, 0),
    }
}

/// The columns of v4's object order, plus the object id for ties: small
/// enough to collect for a whole source before reading the objects in
/// order (exports, NRTMv4 snapshots).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OrderKey<'a> {
    /// `ip_first`
    pub ip_first: Option<IpAddr>,
    /// `asn_first`
    pub asn_first: Option<u32>,
    /// `rpsl_pk`
    pub rpsl_pk: &'a str,
    /// The internal object id.
    pub id: u64,
}

impl<'a> OrderKey<'a> {
    /// The key of a stored object.
    pub fn of(id: u64, o: &RpslObjectRef<'a>) -> Self {
        OrderKey {
            ip_first: o.ip_first,
            asn_first: o.asn_first,
            rpsl_pk: o.rpsl_pk,
            id,
        }
    }

    /// v4's `ORDER BY ip_first, asn_first, rpsl_pk`, then object id.
    pub fn v4_cmp(&self, other: &Self) -> Ordering {
        inet_key(self.ip_first)
            .cmp(&inet_key(other.ip_first))
            .then_with(|| match (self.asn_first, other.asn_first) {
                (Some(x), Some(y)) => x.cmp(&y),
                (Some(_), None) => Ordering::Less,
                (None, Some(_)) => Ordering::Greater,
                (None, None) => Ordering::Equal,
            })
            .then_with(|| collate_cmp(self.rpsl_pk, other.rpsl_pk))
            .then_with(|| self.id.cmp(&other.id))
    }
}

/// v4's `ORDER BY ip_first, asn_first, rpsl_pk`, then object id.
pub fn object_cmp(a: &(u64, RpslObjectRef<'_>), b: &(u64, RpslObjectRef<'_>)) -> Ordering {
    OrderKey::of(a.0, &a.1).v4_cmp(&OrderKey::of(b.0, &b.1))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sorted by PostgreSQL 18.6 `ORDER BY x` in an `en_US.utf8` database.
    const POSTGRES_ORDER: &[&str] = &[
        "1.2.3.0/23AS1",
        "1.2.30/24",
        "1.2.3.0/24AS1",
        "1.2.3.0/24AS10",
        "-A",
        "_A",
        "A",
        "aa",
        "aA",
        "Aa",
        "AA",
        "a-b",
        "ab",
        "A B",
        "A-B",
        "A.B",
        "A/B",
        "A:B",
        "A_B",
        "AB",
        "AB-",
        "AS-1",
        "AS1",
        "AS10",
        "AS2",
        "AS-A",
        "ASA",
        "AS-FOO:AS-B",
        "AS-FOO-B",
        "AS-FOOB",
        "Z",
    ];

    #[test]
    fn matches_postgres_en_us() {
        let mut v: Vec<&str> = POSTGRES_ORDER.to_vec();
        v.reverse();
        v.sort_by(|a, b| collate_cmp(a, b));
        assert_eq!(v, POSTGRES_ORDER);
    }

    #[test]
    fn single_characters() {
        let expected: Vec<String> = " !\"#%&'()*+,-./:;<=>?@[\\]^_`{|}~$0123456789aAbBcCdDeEfFgGhHiIjJkKlLmMnNoOpPqQrRsStTuUvVwWxXyYzZ"
            .chars()
            .map(String::from)
            .collect();
        let mut v = expected.clone();
        v.sort();
        v.sort_by(|a, b| collate_cmp(a, b));
        assert_eq!(v, expected);
    }
}
