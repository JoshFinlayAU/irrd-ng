//! A port of the parts of IPy 1.01 that IRRd v4 uses to parse and print
//! addresses.
//!
//! v4 stores and prints prefixes through `IPy.IP`, so its quirks are visible
//! in object text, in `parsed_data` and in error messages: `str()` drops the
//! prefix length of a single address, IPv6 compression has its own rules,
//! `IP.broadcast()` re-guesses the IP version from the integer, and `int()`
//! accepts more than an address parser normally would. This module follows
//! IPy's control flow line by line, including the text of its `ValueError`s.

use std::fmt;

use crate::py::{self, IntError, PyInt};

const MAX_IPV4_ADDRESS: u128 = 0xffff_ffff;
const MAX_IPV6_ADDRESS: u128 = u128::MAX;

/// An `IPy.IP` value: an address or network with its IP version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ip {
    ip: u128,
    version: u8,
    prefixlen: u32,
}

/// IPy's `ValueError`, holding the exception text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpError(pub String);

impl fmt::Display for IpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

type IpResult<T> = Result<T, IpError>;

fn err<T>(msg: String) -> IpResult<T> {
    Err(IpError(msg))
}

fn version_to_len(version: u8) -> u32 {
    if version == 4 { 32 } else { 128 }
}

/// `int(text)` with base 10, mapping failures to CPython's message.
fn py_int10(text: &str) -> IpResult<PyInt> {
    py::parse_int(text, 10).map_err(|e| IpError(py::int_error_message(text, 10, &e)))
}

/// The prefix length as IPy stores it: a Python int that may be anything,
/// here clamped into an `i128` (larger values are invalid either way).
#[derive(Debug, Clone, Copy)]
struct PrefixLen(i128);

fn prefixlen_to_netmask(prefixlen: i128, version: u8) -> Option<u128> {
    let bits = i128::from(version_to_len(version));
    if prefixlen == 0 {
        return Some(0);
    }
    if prefixlen < 0 || prefixlen > bits {
        // IPy raises ValueError here (negative prefix or negative shift).
        return None;
    }
    let ones: u128 = if prefixlen == 128 {
        u128::MAX
    } else {
        (1u128 << prefixlen) - 1
    };
    Some(ones << (bits - prefixlen))
}

fn check_netaddr_works_with_prefixlen(net: u128, prefixlen: i128, version: u8) -> bool {
    match prefixlen_to_netmask(prefixlen, version) {
        Some(mask) => net & mask == net,
        None => false,
    }
}

/// `_count1Bits`: the bit length.
fn count1_bits(num: u128) -> u32 {
    128 - num.leading_zeros()
}

/// `_count0Bits`: trailing zero bits, 0 for 0.
fn count0_bits(num: u128) -> u32 {
    if num == 0 { 0 } else { num.trailing_zeros() }
}

fn netmask_to_prefixlen(netmask: u128) -> IpResult<i128> {
    let netlen = count0_bits(netmask);
    let masklen = count1_bits(netmask);
    // _checkNetmask
    let mut num = netmask;
    let mut bits = masklen;
    while num & 1 == 0 && bits != 0 {
        num >>= 1;
        bits -= 1;
        if bits == 0 {
            break;
        }
    }
    while bits > 0 {
        if num & 1 == 0 {
            return err(format!(
                "Netmask 0x{netmask:x} can't be expressed as an prefix."
            ));
        }
        num >>= 1;
        bits -= 1;
    }
    Ok(i128::from(masklen) - i128::from(netlen))
}

/// `intToIp`.
fn int_to_ip(ip: u128, version: u8) -> IpResult<String> {
    if version == 4 {
        if ip > MAX_IPV4_ADDRESS {
            return err(format!(
                "IPv4 Address can't be larger than {MAX_IPV4_ADDRESS:x}: {ip:x}"
            ));
        }
        let v = ip as u32;
        Ok(format!(
            "{}.{}.{}.{}",
            v >> 24,
            (v >> 16) & 0xff,
            (v >> 8) & 0xff,
            v & 0xff
        ))
    } else {
        let mut out = String::with_capacity(39);
        for i in 0..8 {
            if i > 0 {
                out.push(':');
            }
            let hextet = (ip >> (112 - 16 * i)) & 0xffff;
            out.push_str(&format!("{hextet:04x}"));
        }
        Ok(out)
    }
}

/// `parseAddress(ipstr, ipversion)`.
fn parse_address(ipstr: &str, ipversion: u8) -> IpResult<(u128, u8)> {
    let hexval = py::parse_int(ipstr, 16).ok();
    let intval = match py::parse_int(ipstr, 10) {
        Ok(v) => Some(v),
        Err(IntError::Invalid | IntError::TooManyDigits(_)) => None,
    };

    if ipstr.starts_with("0x") {
        if let Some(hv) = &hexval {
            let Some(v) = hv.to_u128() else {
                return err(format!(
                    "IP Address can't be larger than {MAX_IPV6_ADDRESS:x}: {}",
                    hv.hex()
                ));
            };
            return Ok((v, if v <= MAX_IPV4_ADDRESS { 4 } else { 6 }));
        }
    }

    if ipstr.contains(':') {
        return Ok((parse_address_ipv6(ipstr)?, 6));
    }
    if ipstr.chars().count() == 32 {
        if let Some(hv) = &hexval {
            // 32 hex digits fit; a sign or whitespace only makes it shorter.
            return Ok((hv.to_u128().unwrap_or(0), 6));
        }
    }
    let small_int = intval
        .as_ref()
        .and_then(PyInt::to_i128)
        .is_some_and(|v| v < 256);
    if ipstr.contains('.') || (small_int && ipversion != 6) {
        let mut bytes: Vec<&str> = ipstr.split('.').collect();
        if bytes.len() > 4 {
            return err("IPv4 Address with more than 4 bytes".to_owned());
        }
        while bytes.len() < 4 {
            bytes.push("0");
        }
        let mut values = [0i128; 4];
        for (slot, b) in values.iter_mut().zip(&bytes) {
            let v = py_int10(b)?;
            *slot = v.to_i128().unwrap_or(i128::MAX);
        }
        for v in values {
            if !(0..=255).contains(&v) {
                return err(format!(
                    "{}: single byte must be 0 <= byte < 256",
                    py::repr(ipstr)
                ));
            }
        }
        let value = (values[0] << 24) + (values[1] << 16) + (values[2] << 8) + values[3];
        return Ok((value as u128, 4));
    }
    if let Some(iv) = intval {
        if iv.is_negative() {
            // Unreachable from string input: negatives take the IPv4 branch.
            return err(format!("IP Address format was invalid: {ipstr}"));
        }
        let Some(v) = iv.to_u128() else {
            return err(format!(
                "IP Address can't be larger than {MAX_IPV6_ADDRESS:x}: {}",
                iv.hex()
            ));
        };
        if v <= MAX_IPV4_ADDRESS && ipversion != 6 {
            return Ok((v, 4));
        }
        return Ok((v, 6));
    }
    err(format!("IP Address format was invalid: {ipstr}"))
}

/// `_parseAddressIPv6(ipstr)`.
fn parse_address_ipv6(ipstr: &str) -> IpResult<u128> {
    let r = py::repr(ipstr);
    let mut items: Vec<String> = Vec::new();
    let mut index = 0usize;
    let mut fill_pos: Option<usize> = None;
    while index < ipstr.len() {
        let text = &ipstr[index..];
        if text.starts_with("::") {
            if fill_pos.is_some() {
                return err(format!("{r}: Invalid IPv6 address: more than one '::'"));
            }
            fill_pos = Some(items.len());
            index += 2;
            continue;
        }
        match text.find(':') {
            Some(0) => return err(format!("{r}: Invalid IPv6 address")),
            Some(pos) => {
                items.push(text[..pos].to_owned());
                if text[pos..].starts_with("::") {
                    index += pos;
                } else {
                    index += pos + 1;
                }
                if index == ipstr.len() {
                    return err(format!("{r}: Invalid IPv6 address"));
                }
            }
            None => {
                items.push(text.to_owned());
                break;
            }
        }
    }

    if items.last().is_some_and(|last| last.contains('.')) {
        if let Some(fp) = fill_pos {
            if fp > items.len() - 1 {
                return err(format!("{r}: Invalid IPv6 address: '::' after IPv4"));
            }
        }
        let last = items.pop().unwrap_or_default();
        let (value, _) = parse_address(&last, 0)?;
        items.push(format!("{:04x}", value >> 16));
        items.push(format!("{:04x}", value & 0xffff));
    }

    if let Some(fp) = fill_pos {
        let diff = 8i64 - items.len() as i64;
        if diff <= 0 {
            return err(format!("{r}: Invalid IPv6 address: '::' is not needed"));
        }
        let tail = items.split_off(fp);
        items.extend(std::iter::repeat_n(String::from("0"), diff as usize));
        items.extend(tail);
    }

    if items.len() != 8 {
        return err(format!("{r}: Invalid IPv6 address: should have 8 hextets"));
    }

    let mut value: u128 = 0;
    for item in &items {
        match py::parse_int(item, 16) {
            Ok(v) => match v.to_i128() {
                Some(h) if (0..=0xffff).contains(&h) => {
                    value = (value << 16) + h as u128;
                }
                _ => {
                    return err(format!("{r}: Invalid IPv6 address: invalid hexlet {v}"));
                }
            },
            Err(_) => {
                return err(format!(
                    "{r}: Invalid IPv6 address: invalid hexlet {}",
                    py::repr(item)
                ));
            }
        }
    }
    Ok(value)
}

impl Ip {
    /// `IP(data, ipversion=ipversion)` for a string. `ipversion` 0 means
    /// "guess".
    pub fn parse(data: &str, ipversion: u8) -> IpResult<Ip> {
        let mut netbits: u32 = 0;
        let parts: Vec<&str> = data.split('-').collect();
        let ip_part: &str;
        let mut prefix: Option<PrefixLenSource<'_>> = None;
        match parts.len() {
            2 => {
                let (ip, last) = (parts[0], parts[1]);
                let (first, parsed_version) = parse_address(ip, 0)?;
                if parsed_version != 4 {
                    return err("first-last notation only allowed for IPv4".to_owned());
                }
                let (last, last_version) = parse_address(last, 0)?;
                if last_version != 4 {
                    return err("last address should be IPv4, too".to_owned());
                }
                if last < first {
                    return err("last address should be larger than first".to_owned());
                }
                let size = last - first;
                netbits = count1_bits(size);
                let check = Ip::parse(&format!("{ip}/{}", 32 - i64::from(netbits)), 0)?;
                if check.broadcast_int() != last {
                    return err(format!("the range {data} is not on a network boundary."));
                }
                ip_part = ip;
            }
            1 => {
                let slash: Vec<&str> = data.split('/').collect();
                match slash.len() {
                    1 => ip_part = slash[0],
                    2 => {
                        ip_part = slash[0];
                        let p = slash[1];
                        if p.contains('.') {
                            let (netmask, vers) = parse_address(p, 0)?;
                            if vers != 4 {
                                return err("netmask must be IPv4".to_owned());
                            }
                            prefix = Some(PrefixLenSource::Int(netmask_to_prefixlen(netmask)?));
                        } else {
                            prefix = Some(PrefixLenSource::Str(p));
                        }
                    }
                    _ => return err("only one '/' allowed in IP Address".to_owned()),
                }
            }
            _ => return err("only one '-' allowed in IP Address".to_owned()),
        }

        let (ip, parsed_version) = parse_address(ip_part, ipversion)?;
        let version = if ipversion == 0 {
            parsed_version
        } else {
            ipversion
        };
        let prefixlen = match prefix {
            None => PrefixLen(i128::from(version_to_len(version)) - i128::from(netbits)),
            Some(PrefixLenSource::Int(v)) => PrefixLen(v),
            Some(PrefixLenSource::Str(s)) => {
                let v = py_int10(s)?;
                PrefixLen(v.to_i128().unwrap_or(i128::MAX))
            }
        };

        if !check_netaddr_works_with_prefixlen(ip, prefixlen.0, version) {
            let r = repr_unchecked(ip, version, prefixlen.0)?;
            return err(format!("{r} has invalid prefix length ({})", prefixlen.0));
        }
        Ok(Ip {
            ip,
            version,
            prefixlen: prefixlen.0 as u32,
        })
    }

    /// `IP(int, ipversion=version)`.
    fn from_int(ip: u128, ipversion: u8) -> Ip {
        let version = match ipversion {
            0 if ip <= MAX_IPV4_ADDRESS => 4,
            0 => 6,
            v => v,
        };
        Ip {
            ip,
            version,
            prefixlen: version_to_len(version),
        }
    }

    /// `IP.int()`: the first address as an integer.
    pub fn int(&self) -> u128 {
        self.ip
    }

    /// `IP.version()`.
    pub fn version(&self) -> u8 {
        self.version
    }

    /// `IP.prefixlen()`.
    pub fn prefixlen(&self) -> u32 {
        self.prefixlen
    }

    fn len_minus_one(&self) -> u128 {
        let host_bits = version_to_len(self.version) - self.prefixlen;
        if host_bits >= 128 {
            u128::MAX
        } else {
            (1u128 << host_bits) - 1
        }
    }

    fn broadcast_int(&self) -> u128 {
        self.ip + self.len_minus_one()
    }

    /// `IP.net()`: the first address, keeping the version.
    pub fn net(&self) -> Ip {
        Ip::from_int(self.ip, self.version)
    }

    /// `IP.broadcast()`: the last address. Like IPy, the version is guessed
    /// again from the integer, so the last address of `::/96` is IPv4.
    pub fn broadcast(&self) -> Ip {
        Ip::from_int(self.broadcast_int(), 0)
    }

    /// `str(IP)`: compressed, with `/len` unless it is a single address.
    pub fn str_compressed(&self) -> String {
        // A constructed Ip always has a printable address.
        compressed(self.ip, self.version, i128::from(self.prefixlen)).unwrap_or_default()
    }
}

impl fmt::Display for Ip {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.str_compressed())
    }
}

enum PrefixLenSource<'a> {
    Int(i128),
    Str(&'a str),
}

/// `_printPrefix(1)`.
fn print_prefix(version: u8, prefixlen: i128) -> String {
    if (version == 4 && prefixlen == 32) || (version == 6 && prefixlen == 128) {
        String::new()
    } else {
        format!("/{prefixlen}")
    }
}

/// `strCompressed(1)` on possibly inconsistent state (used for `repr()`
/// while the constructor is still validating).
fn compressed(ip: u128, version: u8, prefixlen: i128) -> IpResult<String> {
    if version == 4 {
        return Ok(int_to_ip(ip, 4)? + &print_prefix(version, prefixlen));
    }
    if ip >> 32 == 0xffff {
        let v4 = int_to_ip(ip & MAX_IPV4_ADDRESS, 4)?;
        return Ok(format!("::ffff:{v4}{}", print_prefix(version, prefixlen)));
    }
    let hextets: Vec<u16> = (0..8).map(|i| (ip >> (112 - 16 * i)) as u16).collect();
    let following_zeros: Vec<usize> = (0..8)
        .map(|i| hextets[i..].iter().take_while(|&&h| h == 0).count())
        .collect();
    let max = following_zeros.iter().copied().max().unwrap_or(0);
    let compressionpos = following_zeros.iter().position(|&z| z == max).unwrap_or(0);
    let mut parts: Vec<String> = hextets.iter().map(|h| format!("{h:x}")).collect();
    if max > 1 {
        while compressionpos < parts.len() && parts[compressionpos] == "0" {
            parts.remove(compressionpos);
        }
        parts.insert(compressionpos, String::new());
        if compressionpos + 1 >= parts.len() {
            parts.push(String::new());
        }
        if compressionpos == 0 {
            parts.insert(0, String::new());
        }
    }
    Ok(parts.join(":") + &print_prefix(version, prefixlen))
}

/// `repr(IP)`, which can itself raise for an IPv4 object holding an IPv6
/// sized integer.
fn repr_unchecked(ip: u128, version: u8, prefixlen: i128) -> IpResult<String> {
    Ok(format!("IP('{}')", compressed(ip, version, prefixlen)?))
}

/// `clean_ip_value_error` (`irrd/utils/text.py`): strip a leading
/// `IP('...') has ` from IPy's messages.
pub fn clean_ip_value_error(msg: &str) -> String {
    let mut out = String::with_capacity(msg.len());
    let mut rest = msg;
    while let Some(pos) = find_ci(rest, "IP('") {
        let after = &rest[pos + 4..];
        let body_len = after
            .bytes()
            .take_while(|b| b.is_ascii_hexdigit() || matches!(b, b':' | b'.' | b'/'))
            .count();
        if body_len > 0 && after[body_len..].starts_with("') has ") {
            out.push_str(&rest[..pos]);
            rest = &after[body_len + "') has ".len()..];
        } else {
            out.push_str(&rest[..pos + 1]);
            rest = &rest[pos + 1..];
        }
    }
    out.push_str(rest);
    out
}

/// Case-insensitive ASCII find (the pattern is compiled with IGNORECASE).
fn find_ci(haystack: &str, needle: &str) -> Option<usize> {
    let h = haystack.as_bytes();
    let n = needle.as_bytes();
    if n.len() > h.len() {
        return None;
    }
    (0..=h.len() - n.len()).find(|&i| {
        haystack.is_char_boundary(i) && h[i..i + n.len()].eq_ignore_ascii_case(n)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(data: &str, v: u8) -> String {
        match Ip::parse(data, v) {
            Ok(ip) => ip.to_string(),
            Err(e) => format!("ERR {e}"),
        }
    }

    #[test]
    fn prints_like_ipy() {
        assert_eq!(s("192.0.2.0/24", 4), "192.0.2.0/24");
        assert_eq!(s("192.0.2.1/32", 4), "192.0.2.1");
        assert_eq!(s("2001:DB8::/32", 6), "2001:db8::/32");
        assert_eq!(s("::/0", 6), "::/0");
        assert_eq!(s("::ffff:1.2.3.4", 0), "::ffff:1.2.3.4");
        assert_eq!(s("1:0:0:1:0:0:0:1", 0), "1:0:0:1::1");
        assert_eq!(s("1:0:1:0:1:0:1:0", 0), "1:0:1:0:1:0:1:0");
        assert_eq!(s("127", 0), "127.0.0.0");
        assert_eq!(s("1.2.3.0-1.2.3.255", 0), "1.2.3.0/24");
    }

    #[test]
    fn errors_like_ipy() {
        assert_eq!(
            s("192.0.2.1/24", 4),
            "ERR IP('192.0.2.1/24') has invalid prefix length (24)"
        );
        assert_eq!(
            s("1.2.3.256/32", 4),
            "ERR '1.2.3.256': single byte must be 0 <= byte < 256"
        );
        assert_eq!(
            clean_ip_value_error("IP('192.0.2.1/24') has invalid prefix length (24)"),
            "invalid prefix length (24)"
        );
    }

    #[test]
    fn broadcast_regresses_version() {
        let ip = Ip::parse("::/96", 6).unwrap();
        assert_eq!(ip.broadcast().to_string(), "255.255.255.255");
        assert_eq!(ip.net().to_string(), "::");
    }
}
