//! Order-preserving key encodings for the LMDB tables.
//!
//! String components are escaped so that `0x00` can terminate them: a `0x00`
//! byte in the string becomes `0x00 0xFF` and the terminator is `0x00 0x01`.
//! Byte order of the encoded keys is the byte order of the components, so
//! range and prefix scans follow (component 1, component 2, ...).

/// Longest string component kept in an index key. Longer values are cut
/// here and the reader re-checks the full value from the record.
pub(crate) const MAX_INDEX_COMPONENT: usize = 1024;

/// Append an escaped, terminated string component.
pub(crate) fn push_str(out: &mut Vec<u8>, s: &[u8]) {
    for &b in s {
        if b == 0 {
            out.extend_from_slice(&[0, 0xFF]);
        } else {
            out.push(b);
        }
    }
    out.extend_from_slice(&[0, 1]);
}

/// Append a string component cut to [`MAX_INDEX_COMPONENT`] bytes (on a
/// character boundary). Returns whether it was cut.
pub(crate) fn push_index_str(out: &mut Vec<u8>, s: &str) -> bool {
    if s.len() <= MAX_INDEX_COMPONENT {
        push_str(out, s.as_bytes());
        false
    } else {
        let mut end = MAX_INDEX_COMPONENT;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        push_str(out, &s.as_bytes()[..end]);
        true
    }
}

/// Read one escaped component from the front of `key`, returning it and the
/// rest of the key.
pub(crate) fn take_str(key: &[u8]) -> Option<(Vec<u8>, &[u8])> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < key.len() {
        if key[i] == 0 {
            match key.get(i + 1)? {
                0xFF => out.push(0),
                1 => return Some((out, &key[i + 2..])),
                _ => return None,
            }
            i += 2;
        } else {
            out.push(key[i]);
            i += 1;
        }
    }
    None
}

/// Read one component as UTF-8.
pub(crate) fn take_string(key: &[u8]) -> Option<(String, &[u8])> {
    let (b, rest) = take_str(key)?;
    Some((String::from_utf8(b).ok()?, rest))
}

/// A signed serial as 8 bytes that sort numerically.
pub(crate) fn serial_bytes(v: i64) -> [u8; 8] {
    ((v as u64) ^ (1 << 63)).to_be_bytes()
}

/// Inverse of [`serial_bytes`].
pub(crate) fn serial_from(b: &[u8]) -> Option<i64> {
    let a: [u8; 8] = b.get(..8)?.try_into().ok()?;
    Some((u64::from_be_bytes(a) ^ (1 << 63)) as i64)
}

/// An internal object id as 8 big-endian bytes.
pub(crate) fn id_bytes(id: u64) -> [u8; 8] {
    id.to_be_bytes()
}

/// The object id at the end of an index key.
pub(crate) fn id_from_tail(key: &[u8]) -> Option<u64> {
    let tail = key.get(key.len().checked_sub(8)?..)?;
    Some(u64::from_be_bytes(tail.try_into().ok()?))
}

/// A value of `width` bytes (4 for IPv4 and ASNs, 16 for IPv6), big endian.
pub(crate) fn push_uint(out: &mut Vec<u8>, v: u128, width: usize) {
    let b = v.to_be_bytes();
    out.extend_from_slice(&b[16 - width..]);
}

/// Read a `width`-byte big-endian value.
pub(crate) fn read_uint(b: &[u8], width: usize) -> Option<u128> {
    let s = b.get(..width)?;
    let mut buf = [0u8; 16];
    buf[16 - width..].copy_from_slice(s);
    Some(u128::from_be_bytes(buf))
}

/// The length of the common bit prefix of `a` and `b` in a `bits`-wide
/// space: the length of the smallest prefix covering both.
pub(crate) fn common_prefix_len(a: u128, b: u128, bits: u32) -> u8 {
    let x = (a ^ b) << (128 - bits);
    if bits == 0 {
        return 0;
    }
    x.leading_zeros().min(bits) as u8
}

/// `v` with all but the top `len` bits (of `bits`) cleared.
pub(crate) fn mask(v: u128, len: u8, bits: u32) -> u128 {
    v & crate::model::net_mask(len, bits)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn string_components_sort_and_round_trip() {
        let mut a = Vec::new();
        push_str(&mut a, b"AB");
        push_str(&mut a, b"x");
        let mut b = Vec::new();
        push_str(&mut b, b"AB\0");
        push_str(&mut b, b"a");
        let mut c = Vec::new();
        push_str(&mut c, b"ABC");
        assert!(a < b && b < c);
        let (s, rest) = take_str(&b).expect("component");
        assert_eq!(s, b"AB\0");
        assert_eq!(take_str(rest).expect("component").0, b"a");
    }

    #[test]
    fn serials_sort_numerically() {
        assert!(serial_bytes(-1) < serial_bytes(0));
        assert!(serial_bytes(0) < serial_bytes(1));
        assert!(serial_bytes(255) < serial_bytes(256));
        assert_eq!(serial_from(&serial_bytes(-42)), Some(-42));
    }

    #[test]
    fn cover_prefix() {
        assert_eq!(common_prefix_len(0xC0000200, 0xC00002FF, 32), 24);
        assert_eq!(common_prefix_len(5, 5, 32), 32);
        assert_eq!(common_prefix_len(0, u32::MAX as u128, 32), 0);
        assert_eq!(common_prefix_len(0, u128::MAX, 128), 0);
        assert_eq!(common_prefix_len(1, 1, 128), 128);
    }
}
