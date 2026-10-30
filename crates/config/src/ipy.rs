//! The parts of IPy 1.1 that v4's config check calls: the `IP()`
//! constructor, and the `repr()` it embeds in one of its errors.
//!
//! v4 validates access list entries and scope filter prefixes with
//! `IP(item)` and prints the `ValueError` text, so irrd-ng has to accept
//! exactly what IPy accepts (including oddities like `10/8`, `127`,
//! `0x0a000000` and `10.0.0.0-10.0.0.255`) and fail with IPy's words.

use num_bigint::BigInt;
use num_traits::{One, Signed, ToPrimitive, Zero};

use crate::python::{PyException, Value, int_from_str, str_repr};

/// Why `IP(data)` failed.
#[derive(Debug)]
pub(crate) enum IpError {
    /// A `ValueError`, caught by v4; the text is `str(exc)`.
    Value(String),
    /// Anything else, which v4 does not catch.
    Crash(PyException),
}

impl From<PyException> for IpError {
    fn from(e: PyException) -> Self {
        if e.kind == "ValueError" {
            IpError::Value(e.message)
        } else {
            IpError::Crash(e)
        }
    }
}

type Result<T> = std::result::Result<T, IpError>;

fn value_error(msg: impl Into<String>) -> IpError {
    IpError::Value(msg.into())
}

fn max_v4() -> BigInt {
    BigInt::from(0xffff_ffffu32)
}

fn max_v6() -> BigInt {
    (BigInt::one() << 128u32) - 1
}

fn hex(i: &BigInt) -> String {
    format!("{i:x}")
}

/// The successful result of `IP(...)`.
#[derive(Debug, Clone)]
pub(crate) struct Ip {
    ip: BigInt,
    version: u8,
    prefixlen: BigInt,
}

/// `IP(data)`.
pub(crate) fn ip(data: &Value) -> Result<Ip> {
    match data {
        Value::Bool(b) => from_int(&BigInt::from(u8::from(*b))),
        Value::Int(i) => from_int(i),
        Value::Str(s) => from_str(s),
        other => {
            let class = match other {
                Value::Dict(_) | Value::List(_) => {
                    format!("irrd.vendor.dotted.collection.{}", other.type_name())
                }
                _ => other.type_name().to_owned(),
            };
            Err(IpError::Crash(PyException::type_error(format!(
                "Unsupported data type: <class '{class}'>"
            ))))
        }
    }
}

fn from_int(i: &BigInt) -> Result<Ip> {
    if *i <= max_v4() {
        return Ok(Ip {
            ip: i.clone(),
            version: 4,
            prefixlen: BigInt::from(32),
        });
    }
    if *i > max_v6() {
        return Err(value_error(format!(
            "IPv6 Address can't be larger than {}: {}",
            hex(&max_v6()),
            hex(i)
        )));
    }
    Ok(Ip {
        ip: i.clone(),
        version: 6,
        prefixlen: BigInt::from(128),
    })
}

enum Prefix {
    Unset,
    Text(String),
    Int(BigInt),
}

fn from_str(data: &str) -> Result<Ip> {
    let mut netbits: u32 = 0;
    let mut prefixlen = Prefix::Unset;
    let ipstr: &str;
    let dash: Vec<&str> = data.split('-').collect();
    if dash.len() == 2 {
        let (first, last) = (dash[0], dash[1]);
        let (first_ip, first_version) = parse_address(first, 0)?;
        if first_version != 4 {
            return Err(value_error("first-last notation only allowed for IPv4"));
        }
        let (last_ip, last_version) = parse_address(last, 0)?;
        if last_version != 4 {
            return Err(value_error("last address should be IPv4, too"));
        }
        if last_ip < first_ip {
            return Err(value_error("last address should be larger than first"));
        }
        let size = &last_ip - &first_ip;
        netbits = u32::try_from(size.bits()).unwrap_or(u32::MAX);
        let inner = from_str(&format!("{first}/{}", 32 - i64::from(netbits)))?;
        if inner.broadcast() != last_ip {
            return Err(value_error(format!(
                "the range {data} is not on a network boundary."
            )));
        }
        ipstr = first;
    } else if dash.len() == 1 {
        let slash: Vec<&str> = data.split('/').collect();
        if slash.len() == 1 {
            ipstr = slash[0];
        } else if slash.len() > 2 {
            return Err(value_error("only one '/' allowed in IP Address"));
        } else {
            ipstr = slash[0];
            let p = slash[1];
            if p.contains('.') {
                let (netmask, version) = parse_address(p, 0)?;
                if version != 4 {
                    return Err(value_error("netmask must be IPv4"));
                }
                prefixlen = Prefix::Int(netmask_to_prefixlen(&netmask)?);
            } else {
                prefixlen = Prefix::Text(p.to_owned());
            }
        }
    } else {
        return Err(value_error("only one '-' allowed in IP Address"));
    }

    let (ip, version) = parse_address(ipstr, 0)?;
    let prefixlen = match prefixlen {
        Prefix::Unset => BigInt::from(version_bits(version)) - netbits,
        Prefix::Int(i) => i,
        Prefix::Text(t) => int_from_str(&t, 10)?,
    };
    let result = Ip {
        ip,
        version,
        prefixlen,
    };
    if !check_netaddr_works_with_prefixlen(&result.ip, &result.prefixlen, version) {
        return Err(value_error(format!(
            "{} has invalid prefix length ({})",
            result.repr()?,
            result.prefixlen
        )));
    }
    Ok(result)
}

fn version_bits(version: u8) -> u32 {
    if version == 4 { 32 } else { 128 }
}

/// `parseAddress(ipstr, ipversion)`.
fn parse_address(ipstr: &str, ipversion: u8) -> Result<(BigInt, u8)> {
    let hexval = int_from_str(ipstr, 16).ok();
    let intval = int_from_str(ipstr, 10).ok();
    if ipstr.starts_with("0x")
        && let Some(h) = &hexval
    {
        if *h > max_v6() {
            return Err(value_error(format!(
                "IP Address can't be larger than {}: {}",
                hex(&max_v6()),
                hex(h)
            )));
        }
        return Ok((h.clone(), if *h <= max_v4() { 4 } else { 6 }));
    }
    if ipstr.contains(':') {
        return Ok((parse_address_ipv6(ipstr)?, 6));
    }
    if ipstr.chars().count() == 32
        && let Some(h) = hexval
    {
        return Ok((h, 6));
    }
    if ipstr.contains('.')
        || intval
            .as_ref()
            .is_some_and(|i| *i < BigInt::from(256) && ipversion != 6)
    {
        let mut parts: Vec<&str> = ipstr.split('.').collect();
        if parts.len() > 4 {
            return Err(value_error("IPv4 Address with more than 4 bytes"));
        }
        while parts.len() < 4 {
            parts.push("0");
        }
        let mut bytes = Vec::with_capacity(4);
        for p in parts {
            bytes.push(int_from_str(p, 10)?);
        }
        for b in &bytes {
            if *b > BigInt::from(255) || b.is_negative() {
                return Err(value_error(format!(
                    "{}: single byte must be 0 <= byte < 256",
                    str_repr(ipstr)
                )));
            }
        }
        let value = (&bytes[0] << 24u32) + (&bytes[1] << 16u32) + (&bytes[2] << 8u32) + &bytes[3];
        return Ok((value, 4));
    }
    if let Some(i) = intval {
        if i > max_v6() {
            return Err(value_error(format!(
                "IP Address can't be larger than {}: {}",
                hex(&max_v6()),
                hex(&i)
            )));
        }
        let version = if i <= max_v4() && ipversion != 6 {
            4
        } else {
            6
        };
        return Ok((i, version));
    }
    Err(value_error(format!(
        "IP Address format was invalid: {ipstr}"
    )))
}

/// `_parseAddressIPv6(ipstr)`.
fn parse_address_ipv6(ipstr: &str) -> Result<BigInt> {
    let chars: Vec<char> = ipstr.chars().collect();
    let r = str_repr(ipstr);
    let mut items: Vec<String> = Vec::new();
    let mut index = 0;
    let mut fill_pos: Option<usize> = None;
    while index < chars.len() {
        let text = &chars[index..];
        if text.starts_with(&[':', ':']) {
            if fill_pos.is_some() {
                return Err(value_error(format!(
                    "{r}: Invalid IPv6 address: more than one '::'"
                )));
            }
            fill_pos = Some(items.len());
            index += 2;
            continue;
        }
        match text.iter().position(|c| *c == ':') {
            Some(0) => return Err(value_error(format!("{r}: Invalid IPv6 address"))),
            Some(pos) => {
                items.push(text[..pos].iter().collect());
                if text.get(pos + 1) == Some(&':') {
                    index += pos;
                } else {
                    index += pos + 1;
                }
                if index == chars.len() {
                    return Err(value_error(format!("{r}: Invalid IPv6 address")));
                }
            }
            None => {
                items.push(text.iter().collect());
                break;
            }
        }
    }
    if items.last().is_some_and(|l| l.contains('.')) {
        if let Some(fp) = fill_pos
            && fp > items.len() - 1
        {
            return Err(value_error(format!(
                "{r}: Invalid IPv6 address: '::' after IPv4"
            )));
        }
        let last = items.pop().unwrap_or_default();
        let (value, _) = parse_address(&last, 0)?;
        items.push(format!("{:04x}", &value >> 16u32));
        items.push(format!("{:04x}", &value & BigInt::from(0xffff)));
    }
    if let Some(fp) = fill_pos {
        let diff = 8i64 - i64::try_from(items.len()).unwrap_or(i64::MAX);
        if diff <= 0 {
            return Err(value_error(format!(
                "{r}: Invalid IPv6 address: '::' is not needed"
            )));
        }
        let fill = usize::try_from(diff).unwrap_or(0);
        let tail = items.split_off(fp);
        items.extend(std::iter::repeat_n("0".to_owned(), fill));
        items.extend(tail);
    }
    if items.len() != 8 {
        return Err(value_error(format!(
            "{r}: Invalid IPv6 address: should have 8 hextets"
        )));
    }
    let mut value = BigInt::zero();
    for item in &items {
        let parsed = int_from_str(item, 16);
        let shown = match &parsed {
            Ok(i) if *i >= BigInt::zero() && *i <= BigInt::from(0xffff) => {
                value = (value << 16u32) + i;
                continue;
            }
            Ok(i) => i.to_string(),
            Err(_) => str_repr(item),
        };
        return Err(value_error(format!(
            "{r}: Invalid IPv6 address: invalid hexlet {shown}"
        )));
    }
    Ok(value)
}

/// `_netmaskToPrefixlen(netmask)`.
fn netmask_to_prefixlen(netmask: &BigInt) -> Result<BigInt> {
    let netlen = count_0_bits(netmask)?;
    let masklen = netmask.bits();
    check_netmask(netmask, masklen)?;
    Ok(BigInt::from(masklen) - netlen)
}

fn count_0_bits(num: &BigInt) -> Result<u64> {
    if num.is_negative() {
        return Err(value_error(format!("Only positive Numbers please: {num}")));
    }
    if num.is_zero() {
        return Ok(0);
    }
    Ok(num.trailing_zeros().unwrap_or(0))
}

fn check_netmask(netmask: &BigInt, masklen: u64) -> Result<()> {
    let mut num = netmask.clone();
    let mut bits = masklen;
    let one = BigInt::one();
    while (&num & &one).is_zero() && bits != 0 {
        num >>= 1u32;
        bits -= 1;
        if bits == 0 {
            break;
        }
    }
    while bits > 0 {
        if (&num & &one).is_zero() {
            return Err(value_error(format!(
                "Netmask 0x{} can't be expressed as an prefix.",
                hex(netmask)
            )));
        }
        num >>= 1u32;
        bits -= 1;
    }
    Ok(())
}

fn prefixlen_to_netmask(prefixlen: &BigInt, version: u8) -> Option<BigInt> {
    if prefixlen.is_zero() {
        return Some(BigInt::zero());
    }
    if prefixlen.is_negative() {
        return None;
    }
    let p = prefixlen.to_u32()?;
    let bits = version_bits(version);
    if p > bits {
        // A negative shift count: ValueError, caught by the caller.
        return None;
    }
    Some(((BigInt::from(2) << (p - 1)) - 1) << (bits - p))
}

fn check_netaddr_works_with_prefixlen(net: &BigInt, prefixlen: &BigInt, version: u8) -> bool {
    match prefixlen_to_netmask(prefixlen, version) {
        Some(mask) => (net & mask) == *net,
        None => false,
    }
}

/// `intToIp(ip, version)`.
fn int_to_ip(ip: &BigInt, version: u8) -> Result<String> {
    if ip.is_negative() {
        return Err(value_error(format!("IPs can't be negative: {ip}")));
    }
    if version == 4 {
        if *ip > max_v4() {
            return Err(value_error(format!(
                "IPv4 Address can't be larger than {}: {}",
                hex(&max_v4()),
                hex(ip)
            )));
        }
        let v = ip.to_u32().unwrap_or(0);
        return Ok(format!(
            "{}.{}.{}.{}",
            v >> 24,
            (v >> 16) & 0xff,
            (v >> 8) & 0xff,
            v & 0xff
        ));
    }
    if *ip > max_v6() {
        return Err(value_error(format!(
            "IPv6 Address can't be larger than {}: {}",
            hex(&max_v6()),
            hex(ip)
        )));
    }
    let l = format!("{ip:032x}");
    let groups: Vec<&str> = (0..8).map(|i| &l[i * 4..i * 4 + 4]).collect();
    Ok(groups.join(":"))
}

impl Ip {
    fn len(&self) -> BigInt {
        let bits = BigInt::from(version_bits(self.version));
        let local = bits - &self.prefixlen;
        match local.to_u32() {
            Some(l) => BigInt::one() << l,
            None => BigInt::zero(),
        }
    }

    fn broadcast(&self) -> BigInt {
        &self.ip + self.len() - 1
    }

    fn print_prefix(&self) -> String {
        let single = (self.version == 4 && self.prefixlen == BigInt::from(32))
            || (self.version == 6 && self.prefixlen == BigInt::from(128));
        if single {
            String::new()
        } else {
            format!("/{}", self.prefixlen)
        }
    }

    /// `strCompressed(1)`.
    fn str_compressed(&self) -> Result<String> {
        if self.version == 4 {
            return Ok(int_to_ip(&self.ip, 4)? + &self.print_prefix());
        }
        if (&self.ip >> 32u32) == BigInt::from(0xffff) {
            let v4 = int_to_ip(&(&self.ip & max_v4()), 4)?;
            return Ok(format!("::ffff:{v4}{}", self.print_prefix()));
        }
        let full = int_to_ip(&self.ip, 6)?;
        let hextets: Vec<u32> = full
            .split(':')
            .map(|x| u32::from_str_radix(x, 16).unwrap_or(0))
            .collect();
        let following: Vec<usize> = (0..hextets.len())
            .map(|i| hextets[i..].iter().take_while(|h| **h == 0).count())
            .collect();
        let max = following.iter().copied().max().unwrap_or(0);
        let compressionpos = following.iter().position(|f| *f == max).unwrap_or(0);
        let mut normal: Vec<String> = hextets.iter().map(|h| format!("{h:x}")).collect();
        if max > 1 {
            while compressionpos < normal.len() && normal[compressionpos] == "0" {
                normal.remove(compressionpos);
            }
            normal.insert(compressionpos, String::new());
            if compressionpos + 1 >= normal.len() {
                normal.push(String::new());
            }
            if compressionpos == 0 {
                normal.insert(0, String::new());
            }
        }
        Ok(normal.join(":") + &self.print_prefix())
    }

    /// `repr(IP)`.
    fn repr(&self) -> Result<String> {
        Ok(format!("IP('{}')", self.str_compressed()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn err(s: &str) -> String {
        match ip(&Value::str(s)) {
            Err(IpError::Value(m)) => m,
            Err(IpError::Crash(c)) => format!("CRASH {c}"),
            Ok(_) => "OK".to_owned(),
        }
    }

    #[test]
    fn accepts_what_ipy_accepts() {
        for ok in [
            "192.0.2.0/24",
            "10/8",
            "192/24",
            "127",
            "2001:db8::/32",
            "::",
            "::1",
            "::ffff:192.0.2.1",
            "10.0.0.0-10.0.0.255",
            "10.0.0.0/255.0.0.0",
            "0x0a000000",
            "2001:db8::32",
        ] {
            assert_eq!(err(ok), "OK", "{ok}");
        }
    }

    #[test]
    fn ipy_error_strings() {
        assert_eq!(err("192.0.2.2.1"), "IPv4 Address with more than 4 bytes");
        assert_eq!(
            err("invalid-prefix"),
            "IP Address format was invalid: invalid"
        );
        assert_eq!(
            err("10.0.0.1/8"),
            "IP('10.0.0.1/8') has invalid prefix length (8)"
        );
        assert_eq!(
            err("2001:db8::1/32"),
            "IP('2001:db8::1/32') has invalid prefix length (32)"
        );
        assert_eq!(
            err("256.0.0.0"),
            "'256.0.0.0': single byte must be 0 <= byte < 256"
        );
        assert_eq!(
            err("1.2.3.4/x"),
            "invalid literal for int() with base 10: 'x'"
        );
        assert_eq!(
            err("1::2::3"),
            "'1::2::3': Invalid IPv6 address: more than one '::'"
        );
        assert_eq!(
            err("1:2:3"),
            "'1:2:3': Invalid IPv6 address: should have 8 hextets"
        );
        assert_eq!(
            err("1:2:3:4:5:6:7:fffff"),
            "'1:2:3:4:5:6:7:fffff': Invalid IPv6 address: invalid hexlet 1048575"
        );
    }
}
