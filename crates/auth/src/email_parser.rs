//! `irrd/utils/email.py` `EmailParser` and `irrd/utils/pgp.py`
//! `validate_pgp_signature`, over a port of the parts of Python's `email`
//! package (`compat32` policy, `feedparser`) that they use.
//!
//! The input is the e-mail as `sys.stdin.read()` returns it: universal
//! newlines, UTF-8 with `surrogateescape`. Bytes that are not UTF-8 are
//! carried as the characters U+10FF80 to U+10FFFF (one per byte), standing
//! in for Python's lone surrogates U+DC80 to U+DCFF.

use regex::Regex;

use rpsl::Keyring;

use crate::charsets;

/// The first of the characters standing in for `surrogateescape` bytes.
const ESCAPE_BASE: u32 = 0x10FF00;

/// Decode raw input as Python's stdin does (UTF-8 with surrogateescape,
/// universal newlines).
pub fn decode_input(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    let mut rest = bytes;
    while !rest.is_empty() {
        match std::str::from_utf8(rest) {
            Ok(s) => {
                out.push_str(s);
                break;
            }
            Err(e) => {
                let (good, bad) = rest.split_at(e.valid_up_to());
                out.push_str(std::str::from_utf8(good).unwrap_or_default());
                let n = e.error_len().unwrap_or(bad.len());
                for &b in &bad[..n] {
                    out.push(char::from_u32(ESCAPE_BASE + u32::from(b)).unwrap_or('\u{fffd}'));
                }
                rest = &bad[n..];
            }
        }
    }
    out.replace("\r\n", "\n").replace('\r', "\n")
}

fn escaped_byte(c: char) -> Option<u8> {
    let v = c as u32;
    (ESCAPE_BASE + 0x80..=ESCAPE_BASE + 0xff)
        .contains(&v)
        .then(|| (v - ESCAPE_BASE) as u8)
}

/// One parsed message or part.
#[derive(Debug, Clone, Default)]
pub struct Part {
    /// `(name, value)` as the compat32 policy stores them: the value with
    /// leading blanks stripped and continuation lines kept.
    pub headers: Vec<(String, String)>,
    /// The payload text, for a part that is not multipart.
    pub payload: String,
    /// Subparts (multipart, or the message of a message/* part).
    pub parts: Vec<Part>,
    /// `is_multipart()`
    pub multipart: bool,
    default_type: &'static str,
}

impl Part {
    /// `msg[name]`: the first header of that name, any case.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// `get_content_type()`
    pub fn content_type(&self) -> String {
        let Some(v) = self.get("content-type") else {
            return self.default_type.to_owned();
        };
        let ctype = v.split(';').next().unwrap_or("").trim().to_lowercase();
        if ctype.matches('/').count() != 1 {
            return "text/plain".to_owned();
        }
        ctype
    }

    /// `get_param(name)` on Content-Type, unquoted.
    pub fn param(&self, name: &str) -> Option<String> {
        let v = self.get("content-type")?;
        for p in parse_params(v).into_iter().skip(1) {
            let (k, val) = match p.split_once('=') {
                Some((k, val)) => (k.trim().to_lowercase(), val.trim().to_owned()),
                None => (p.trim().to_lowercase(), String::new()),
            };
            if k == name.to_lowercase() {
                return Some(unquote(&val));
            }
        }
        None
    }

    /// `get_content_charset()`
    pub fn content_charset(&self) -> Option<String> {
        let c = self.param("charset")?;
        if c.chars()
            .any(|ch| ch as u32 > 0xff || escaped_byte(ch).is_some())
        {
            return None;
        }
        Some(c.to_lowercase())
    }

    /// `walk()`: this part and every subpart, depth first.
    pub fn walk(&self) -> Vec<&Part> {
        let mut out = vec![self];
        for p in &self.parts {
            out.extend(p.walk());
        }
        out
    }

    /// `get_payload(decode=True)` of a part that is not multipart.
    pub fn decoded_payload(&self) -> Vec<u8> {
        let cte = self
            .get("content-transfer-encoding")
            .unwrap_or("")
            .to_lowercase();
        let bpayload = payload_bytes(&self.payload);
        match cte.as_str() {
            "quoted-printable" => a2b_qp(&bpayload),
            "base64" => {
                let joined: Vec<u8> = bpayload
                    .split(|b| *b == b'\n' || *b == b'\r')
                    .flat_map(|l| l.iter().copied())
                    .collect();
                decode_b(&joined)
            }
            _ => bpayload,
        }
    }

    /// `as_string()` of a part that is not multipart: headers as parsed,
    /// a blank line, the payload with its line endings as `\n`.
    pub fn as_string(&self) -> String {
        let mut out = String::new();
        for (n, v) in &self.headers {
            out.push_str(n);
            out.push_str(": ");
            out.push_str(v);
            out.push('\n');
        }
        out.push('\n');
        out.push_str(&self.payload);
        out
    }
}

/// `payload.encode('ascii', 'surrogateescape')`, or
/// `payload.encode('raw-unicode-escape')` when that fails.
fn payload_bytes(payload: &str) -> Vec<u8> {
    let ascii_ok = payload
        .chars()
        .all(|c| c.is_ascii() || escaped_byte(c).is_some());
    let mut out = Vec::with_capacity(payload.len());
    for c in payload.chars() {
        if let Some(b) = escaped_byte(c) {
            if ascii_ok {
                out.push(b);
            } else {
                out.extend_from_slice(format!("\\udc{b:02x}").as_bytes());
            }
            continue;
        }
        let v = c as u32;
        if v < 0x100 {
            out.push(v as u8);
        } else if v < 0x10000 {
            out.extend_from_slice(format!("\\u{v:04x}").as_bytes());
        } else {
            out.extend_from_slice(format!("\\U{v:08x}").as_bytes());
        }
    }
    out
}

/// `binascii.a2b_qp(data)`
fn a2b_qp(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let hex = |b: u8| (b as char).to_digit(16).map(|d| d as u8);
    let mut i = 0;
    while i < data.len() {
        if data[i] == b'=' {
            i += 1;
            if i >= data.len() {
                break;
            }
            if data[i] == b'\n' || data[i] == b'\r' {
                if data[i] != b'\n' {
                    while i < data.len() && data[i] != b'\n' {
                        i += 1;
                    }
                }
                if i < data.len() {
                    i += 1;
                }
            } else if data[i] == b'=' {
                out.push(b'=');
                i += 1;
            } else if i + 1 < data.len()
                && let (Some(h), Some(l)) = (hex(data[i]), hex(data[i + 1]))
            {
                out.push(h * 16 + l);
                i += 2;
            } else {
                out.push(b'=');
            }
        } else {
            out.push(data[i]);
            i += 1;
        }
    }
    out
}

/// `email._encoded_words.decode_b(encoded)`, lenient as Python is.
fn decode_b(encoded: &[u8]) -> Vec<u8> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let value = |b: u8| ALPHABET.iter().position(|&a| a == b).map(|p| p as u32);
    // validate=False: characters outside the alphabet are dropped, and
    // decoding stops at the padding.
    let mut quads: Vec<u32> = Vec::new();
    for &b in encoded {
        if b == b'=' {
            break;
        }
        if let Some(v) = value(b) {
            quads.push(v);
        }
    }
    if quads.len() % 4 == 1 {
        return encoded.to_vec();
    }
    let mut out = Vec::with_capacity(quads.len() * 3 / 4);
    for chunk in quads.chunks(4) {
        let mut n = 0u32;
        for (i, v) in chunk.iter().enumerate() {
            n |= v << (18 - 6 * i);
        }
        let bytes = [(n >> 16) as u8, (n >> 8) as u8, n as u8];
        out.extend_from_slice(&bytes[..chunk.len() - 1]);
    }
    out
}

/// `email.message._parseparam`
fn parse_params(s: &str) -> Vec<String> {
    let mut s = format!(";{s}");
    let mut out = Vec::new();
    while let Some(rest) = s.strip_prefix(';') {
        let rest = rest.to_owned();
        let quotes_before =
            |end: usize| rest[..end].matches('"').count() - rest[..end].matches("\\\"").count();
        let mut end = rest.find(';');
        while let Some(e) = end {
            if e > 0 && quotes_before(e) % 2 == 1 {
                end = rest[e + 1..].find(';').map(|p| p + e + 1);
            } else {
                break;
            }
        }
        let end = end.unwrap_or(rest.len());
        let mut f = rest[..end].to_owned();
        if let Some(i) = f.find('=') {
            f = format!("{}={}", f[..i].trim().to_lowercase(), f[i + 1..].trim());
        }
        out.push(f.trim().to_owned());
        s = rest[end..].to_owned();
    }
    out
}

/// `email.utils.unquote`
fn unquote(s: &str) -> String {
    if s.len() > 1 {
        if s.starts_with('"') && s.ends_with('"') {
            return s[1..s.len() - 1]
                .replace("\\\\", "\\")
                .replace("\\\"", "\"");
        }
        if s.starts_with('<') && s.ends_with('>') {
            return s[1..s.len() - 1].to_owned();
        }
    }
    s.to_owned()
}

/// How deeply MIME parts may nest, counting the message itself. Python
/// 3.13's feed parser recurses once per level and raises `RecursionError`
/// past 987 (measured: 986 nested `message/rfc822` or `multipart` parts
/// parse, 987 do not); this parser recurses too, and stops at the same
/// depth.
pub const MAX_MIME_DEPTH: usize = 987;

/// The exception for a message nested past [`MAX_MIME_DEPTH`].
pub const MIME_RECURSION_ERROR: &str = "RecursionError: maximum recursion depth exceeded";

/// `email.message_from_string(text)`
pub fn message_from_string(text: &str) -> Part {
    message_from_string_checked(text).unwrap_or_default()
}

/// [`message_from_string`], or `None` where Python raises
/// `RecursionError`.
pub fn message_from_string_checked(text: &str) -> Option<Part> {
    let lines: Vec<&str> = text.split_inclusive('\n').collect();
    let mut pos = 0;
    let mut depth = Depth::default();
    let part = parse_part(
        &lines,
        &mut pos,
        lines.len(),
        true,
        "text/plain",
        &mut depth,
    );
    (!depth.exceeded).then_some(part)
}

/// How deep the parser is, and whether it went past [`MAX_MIME_DEPTH`].
#[derive(Default)]
struct Depth {
    level: usize,
    exceeded: bool,
}

fn is_header_line(line: &str) -> bool {
    // ^(From |[\041-\071\073-\176]*:|[\t ])
    if line.starts_with("From ") || line.starts_with(' ') || line.starts_with('\t') {
        return true;
    }
    match line.find(':') {
        Some(i) => line[..i]
            .bytes()
            .all(|b| (0x21..=0x39).contains(&b) || (0x3b..=0x7e).contains(&b)),
        None => false,
    }
}

fn parse_part(
    lines: &[&str],
    pos: &mut usize,
    end: usize,
    top: bool,
    default_type: &'static str,
    depth: &mut Depth,
) -> Part {
    let part = Part {
        default_type,
        ..Default::default()
    };
    if depth.level >= MAX_MIME_DEPTH {
        depth.exceeded = true;
        *pos = end;
        return part;
    }
    depth.level += 1;
    let part_out = parse_part_inner(lines, pos, end, top, part, depth);
    depth.level -= 1;
    part_out
}

fn parse_part_inner(
    lines: &[&str],
    pos: &mut usize,
    end: usize,
    top: bool,
    mut part: Part,
    depth: &mut Depth,
) -> Part {
    let mut first = true;
    while *pos < end {
        let line = lines[*pos];
        if line == "\n" {
            *pos += 1;
            break;
        }
        if !is_header_line(line) {
            break;
        }
        *pos += 1;
        if line.starts_with("From ") {
            if !(first && top) {
                // MisplacedEnvelopeHeaderDefect
            }
            first = false;
            continue;
        }
        first = false;
        if line.starts_with(' ') || line.starts_with('\t') {
            // header_source_parse joins the source lines as they are.
            if let Some(last) = part.headers.last_mut() {
                last.1.push_str(line);
            }
            continue;
        }
        let Some(i) = line.find(':') else { continue };
        if i == 0 {
            continue;
        }
        let name = line[..i].to_owned();
        let value = line[i + 1..].trim_start_matches([' ', '\t']).to_owned();
        part.headers.push((name, value));
    }
    for h in &mut part.headers {
        h.1 = h.1.trim_end_matches(['\r', '\n']).to_owned();
    }

    let ctype = part.content_type();
    if ctype.starts_with("multipart/") {
        if let Some(boundary) = part.param("boundary") {
            parse_multipart(&mut part, lines, pos, end, &boundary, depth);
            return part;
        }
    } else if ctype.starts_with("message/") && ctype != "message/delivery-status" {
        let sub = parse_part(lines, pos, end, false, "text/plain", depth);
        part.parts.push(sub);
        part.multipart = true;
        return part;
    }
    part.payload = lines[*pos..end].concat();
    *pos = end;
    part
}

fn parse_multipart(
    part: &mut Part,
    lines: &[&str],
    pos: &mut usize,
    end: usize,
    boundary: &str,
    depth: &mut Depth,
) {
    let separator = format!("--{boundary}");
    let re = Regex::new(&format!(
        r"^(?P<sep>{})(?P<end>--)?(?P<ws>[ \t]*)(?P<linesep>\r\n|\r|\n)?$",
        regex::escape(&separator)
    ));
    let Ok(re) = re else {
        part.payload = lines[*pos..end].concat();
        *pos = end;
        return;
    };
    // Boundary line indices and whether they close.
    let mut marks: Vec<(usize, bool)> = Vec::new();
    for (i, line) in lines.iter().enumerate().take(end).skip(*pos) {
        if let Some(c) = re.captures(line) {
            let close = c.name("end").is_some();
            marks.push((i, close));
            if close {
                break;
            }
        }
    }
    if marks.is_empty() {
        // StartBoundaryNotFoundDefect: the payload stays a string.
        part.payload = lines[*pos..end].concat();
        *pos = end;
        return;
    }
    part.multipart = true;
    let child_default = if part.content_type() == "multipart/digest" {
        "message/rfc822"
    } else {
        "text/plain"
    };
    for w in 0..marks.len() {
        let (start_line, close) = marks[w];
        if close {
            break;
        }
        let part_end = marks.get(w + 1).map_or(end, |m| m.0);
        let mut p = start_line + 1;
        let mut sub = parse_part(lines, &mut p, part_end, false, child_default, depth);
        if depth.exceeded {
            break;
        }
        if marks.get(w + 1).is_some() && !sub.multipart {
            // The line break before a boundary belongs to the boundary.
            if sub.payload.ends_with('\n') {
                sub.payload.pop();
            }
        }
        part.parts.push(sub);
    }
    *pos = end;
}

/// What `EmailParser(email_txt)` extracts.
#[derive(Debug, Clone, Default)]
pub struct EmailParser {
    /// `body`
    pub body: Option<String>,
    /// `pgp_fingerprint`
    pub pgp_fingerprint: Option<String>,
    /// `message_id`
    pub message_id: Option<String>,
    /// `message_from`
    pub message_from: Option<String>,
    /// `message_date`
    pub message_date: Option<String>,
    /// `message_subject`
    pub message_subject: Option<String>,
}

/// The name `codecs.lookup()` looks up: lower case, then
/// `encodings.normalize_encoding()`, which turns each run of characters
/// other than letters, digits and `.` into one `_` and drops them at
/// either end.
fn normalize_encoding(charset: &str) -> String {
    let mut out = String::with_capacity(charset.len());
    let mut punct = false;
    for c in charset.to_lowercase().chars() {
        if c.is_alphanumeric() || c == '.' {
            if punct && !out.is_empty() {
                out.push('_');
            }
            out.push(c);
            punct = false;
        } else {
            punct = true;
        }
    }
    out
}

/// `bytes.decode(charset)` with strict errors, for ASCII, UTF-8, Latin-1
/// and Python's single-byte codecs: `None` where Python raises
/// `UnicodeDecodeError`, and for every other codec name (Python's
/// multi-byte codecs are not supported, so they count as unknown).
pub fn decode_strict(bytes: &[u8], charset: &str) -> Option<String> {
    match normalize_encoding(charset).as_str() {
        "ascii" | "us_ascii" | "646" | "us" | "iso646_us" | "ansi_x3.4_1968" | "cp367" => bytes
            .is_ascii()
            .then(|| bytes.iter().map(|&b| b as char).collect()),
        "utf_8" | "utf8" | "u8" | "utf" | "cp65001" => {
            std::str::from_utf8(bytes).ok().map(str::to_owned)
        }
        "latin_1" | "latin1" | "l1" | "iso_8859_1" | "iso8859_1" | "8859" | "cp819" | "latin" => {
            Some(bytes.iter().map(|&b| b as char).collect())
        }
        name => {
            let table = charsets::table(name)?;
            bytes
                .iter()
                .map(|&b| match table[usize::from(b)] {
                    charsets::UNDEFINED => None,
                    c => char::from_u32(u32::from(c)),
                })
                .collect()
        }
    }
}

/// `bytes.decode(charset, errors)` for ASCII, UTF-8 and Python's
/// single-byte codecs; Python's `LookupError` text for the others.
fn decode_charset(bytes: &[u8], charset: &str, backslashreplace: bool) -> Result<String, String> {
    let norm = normalize_encoding(charset);
    let replace = |out: &mut String, b: u8| {
        if backslashreplace {
            out.push_str(&format!("\\x{b:02x}"));
        }
    };
    match norm.as_str() {
        "ascii" | "us_ascii" | "646" | "us" | "iso646_us" | "ansi_x3.4_1968" | "cp367" => {
            let mut out = String::with_capacity(bytes.len());
            for &b in bytes {
                if b.is_ascii() {
                    out.push(b as char);
                } else {
                    replace(&mut out, b);
                }
            }
            Ok(out)
        }
        "utf_8" | "utf8" | "u8" | "utf" | "cp65001" => {
            let mut out = String::with_capacity(bytes.len());
            let mut rest = bytes;
            while !rest.is_empty() {
                match std::str::from_utf8(rest) {
                    Ok(s) => {
                        out.push_str(s);
                        break;
                    }
                    Err(e) => {
                        let (good, bad) = rest.split_at(e.valid_up_to());
                        out.push_str(std::str::from_utf8(good).unwrap_or_default());
                        let n = e.error_len().unwrap_or(bad.len());
                        for &b in &bad[..n] {
                            replace(&mut out, b);
                        }
                        rest = &bad[n..];
                    }
                }
            }
            Ok(out)
        }
        "latin_1" | "latin1" | "l1" | "iso_8859_1" | "iso8859_1" | "8859" | "cp819" | "latin" => {
            Ok(bytes.iter().map(|&b| b as char).collect())
        }
        name => {
            let table =
                charsets::table(name).ok_or_else(|| format!("unknown encoding: {charset}"))?;
            let mut out = String::with_capacity(bytes.len());
            for &b in bytes {
                match table[usize::from(b)] {
                    charsets::UNDEFINED => replace(&mut out, b),
                    c => out.push(char::from_u32(u32::from(c)).unwrap_or('\u{fffd}')),
                }
            }
            Ok(out)
        }
    }
}

impl EmailParser {
    /// `EmailParser(email_txt)`. Errors are the exceptions v4 would raise.
    pub fn parse(email_txt: &str, keyring: &Keyring) -> Result<EmailParser, String> {
        let message = message_from_string_checked(email_txt)
            .ok_or_else(|| MIME_RECURSION_ERROR.to_owned())?;
        let mut out = EmailParser::default();
        let mut raw_body: Option<String> = None;
        let mut signature: Option<String> = None;
        if message.multipart {
            for part in message.walk() {
                let charset = part.content_charset().unwrap_or_else(|| "ascii".to_owned());
                if part.multipart {
                    continue;
                }
                if part.content_type() == "text/plain" {
                    out.body = Some(decode_charset(&part.decoded_payload(), &charset, false)?);
                    raw_body = Some(part.as_string());
                }
                if part.content_type() == "application/pgp-signature" {
                    let s = decode_charset(&part.decoded_payload(), &charset, true)?;
                    signature = Some(rpsl::python::strip(&s).to_owned());
                }
            }
        } else {
            let charset = message
                .content_charset()
                .unwrap_or_else(|| "ascii".to_owned());
            let body = decode_charset(&message.decoded_payload(), &charset, true)?;
            raw_body = Some(body.clone());
            out.body = Some(body);
        }
        out.message_id = message.get("Message-ID").map(str::to_owned);
        out.message_from = message.get("From").map(str::to_owned);
        out.message_date = message.get("Date").map(str::to_owned);
        out.message_subject = message.get("Subject").map(str::to_owned);

        let (Some(body), Some(raw)) = (&out.body, &raw_body) else {
            return Ok(out);
        };
        if body.is_empty() || raw.is_empty() {
            return Ok(out);
        }
        let (new_body, fingerprint) = validate_pgp_signature(raw, signature.as_deref(), keyring)?;
        out.pgp_fingerprint = fingerprint;
        if let Some(b) = new_body.filter(|b| !b.is_empty()) {
            out.body = Some(b);
        }
        Ok(out)
    }
}

/// `str.encode("latin-1")` as python-gnupg encodes what it hands to gpg.
fn latin1(s: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(s.len());
    for (i, c) in s.chars().enumerate() {
        let v = c as u32;
        if v < 0x100 {
            out.push(v as u8);
        } else {
            return Err(format!(
                "'latin-1' codec can't encode character '\\u{v:04x}' in position {i}: ordinal not in range(256)"
            ));
        }
    }
    Ok(out)
}

/// `validate_pgp_signature(message, detached_signature)`: the signed part
/// of an inline signed message (if any) and the signing key's
/// fingerprint, for a good signature by a key in the keyring.
pub fn validate_pgp_signature(
    message: &str,
    detached_signature: Option<&str>,
    keyring: &Keyring,
) -> Result<(Option<String>, Option<String>), String> {
    if let Some(sig) = detached_signature.filter(|s| !s.is_empty()) {
        let data = latin1(message)?;
        let sig = latin1(sig)?;
        let fpr = keyring.verify_detached(&data, &sig);
        log_result(fpr.as_deref());
        return Ok((None, fpr));
    }
    if message.matches("BEGIN PGP SIGNED MESSAGE").count() == 1 {
        let data = latin1(message)?;
        let verified = keyring.verify_cleartext_text(&data);
        let normalised = message.replace("\r\n", "\n").replace('\r', "\n");
        // v4's pattern is greedy (`(?s:.+)`), so it runs to the *last*
        // `-----BEGIN PGP SIGNATURE-----` line while gpg checks the
        // signature over the text before the *first*: objects appended
        // after a genuine signature, followed by a second such line, were
        // processed as signed (DIV-007). Taking the body up to the first
        // line is the same text for every message where the two agree.
        let re = Regex::new(
            r"-----BEGIN PGP SIGNED MESSAGE-----(\n.+)?\n\n((?s:.+?))\n-----BEGIN PGP SIGNATURE-----\n",
        )
        .map_err(|e| e.to_string())?;
        let Some(m) = re.captures(&normalised) else {
            tracing::info!(
                target: "irrd.utils.pgp",
                "message contained an inline PGP signature, but regular expression failed to extract body: {message}"
            );
            return Ok((None, None));
        };
        let Some((fpr, text)) = verified else {
            return Ok((None, None));
        };
        // Whatever is processed must be what the signature covers; if the
        // extracted body is not that text, the message is treated as
        // unsigned, as v4 treats a message with a bad signature.
        if !is_signed_text(&m[2], &text) {
            tracing::info!(
                target: "irrd.utils.pgp",
                "message contained an inline PGP signature, but the extracted body is not the signed text, ignoring the signature: {message}"
            );
            return Ok((None, None));
        }
        log_result(Some(&fpr));
        return Ok((Some(format!("{}\n", &m[2])), Some(fpr)));
    }
    Ok((None, None))
}

/// Whether `body`, the text extracted from a cleartext signed message, is
/// the text the signature covers, `signed` as the verifier read it
/// (Latin-1 bytes, dash-escaping removed). Line endings and trailing
/// spaces and tabs, which the signature does not cover (RFC 4880
/// section 7.1), are not compared.
fn is_signed_text(body: &str, signed: &[u8]) -> bool {
    let signed: String = signed.iter().map(|&b| char::from(b)).collect();
    let signed = signed.replace("\r\n", "\n").replace('\r', "\n");
    let unescaped = body.split('\n').map(|l| l.strip_prefix("- ").unwrap_or(l));
    let mut a = unescaped.map(|l| l.trim_end_matches([' ', '\t']));
    let mut b = signed.split('\n').map(|l| l.trim_end_matches([' ', '\t']));
    loop {
        match (a.next(), b.next()) {
            (None, None) => return true,
            (Some(x), Some(y)) if x == y => {}
            _ => return false,
        }
    }
}

fn log_result(fpr: Option<&str>) {
    if let Some(f) = fpr {
        tracing::info!(
            target: "irrd.utils.pgp",
            "Found valid PGP signature, pubkey fingerprint {f}, fingerprint {f}"
        );
    }
}

/// `email.utils.getaddresses([field])` addresses containing `@`, for the
/// shapes found in `From:`: `addr`, `Name <addr>`, `"Name, X" <addr>`,
/// `addr (comment)`, separated by commas.
pub fn reply_addresses(field: &str) -> Vec<String> {
    let mut items: Vec<String> = Vec::new();
    let mut cur = String::new();
    let (mut quote, mut depth_paren, mut depth_angle) = (false, 0i32, 0i32);
    let mut chars = field.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' if quote => {
                cur.push(c);
                if let Some(n) = chars.next() {
                    cur.push(n);
                }
                continue;
            }
            '"' if depth_paren == 0 => quote = !quote,
            '(' if !quote => depth_paren += 1,
            ')' if !quote && depth_paren > 0 => depth_paren -= 1,
            '<' if !quote && depth_paren == 0 => depth_angle += 1,
            '>' if !quote && depth_paren == 0 && depth_angle > 0 => depth_angle -= 1,
            ',' if !quote && depth_paren == 0 && depth_angle == 0 => {
                items.push(std::mem::take(&mut cur));
                continue;
            }
            _ => {}
        }
        cur.push(c);
    }
    items.push(cur);
    let mut out = Vec::new();
    for item in items {
        // Drop comments.
        let mut clean = String::new();
        let mut depth = 0;
        let mut q = false;
        for c in item.chars() {
            match c {
                '"' if depth == 0 => {
                    q = !q;
                    clean.push(c);
                }
                '(' if !q => depth += 1,
                ')' if !q && depth > 0 => depth -= 1,
                _ if depth > 0 => {}
                _ => clean.push(c),
            }
        }
        let addr = match (clean.rfind('<'), clean.rfind('>')) {
            (Some(a), Some(b)) if a < b => clean[a + 1..b].trim().to_owned(),
            _ => clean.split_whitespace().collect::<Vec<_>>().join(""),
        };
        if addr.contains('[') {
            continue;
        }
        if addr.contains('@') {
            out.push(addr);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// MIME parts nested past the limit are Python's RecursionError, not a
    /// stack overflow; up to it, the message parses.
    #[test]
    fn deep_mime_nesting_is_a_recursion_error() {
        // The CLI parses on the main thread (8 MiB of stack); test threads
        // get less, and debug builds use far more stack per level.
        std::thread::Builder::new()
            .stack_size(64 << 20)
            .spawn(deep_mime_nesting)
            .expect("thread")
            .join()
            .expect("no panic");
    }

    fn deep_mime_nesting() {
        let keyring = rpsl::Keyring::new();
        let nested = |n: usize| {
            format!(
                "{}Subject: x\n\nbody\n",
                "Content-Type: message/rfc822\n\n".repeat(n)
            )
        };
        let ok = message_from_string_checked(&nested(MAX_MIME_DEPTH - 1)).expect("parses");
        assert_eq!(ok.walk().len(), MAX_MIME_DEPTH);
        assert!(message_from_string_checked(&nested(MAX_MIME_DEPTH)).is_none());
        assert_eq!(
            EmailParser::parse(&nested(100_000), &keyring).map(|_| ()),
            Err(MIME_RECURSION_ERROR.to_owned())
        );
        let mut multipart = String::new();
        for i in 0..100_000 {
            multipart.push_str(&format!(
                "Content-Type: multipart/mixed; boundary=b{i}\n\n--b{i}\n"
            ));
        }
        assert_eq!(
            EmailParser::parse(&multipart, &keyring).map(|_| ()),
            Err(MIME_RECURSION_ERROR.to_owned())
        );
    }

    // Expected values from Python 3.13's bytes.decode().
    #[test]
    fn single_byte_charsets() {
        let b = [0x41, 0x80, 0x81, 0xe9, 0xff];
        assert_eq!(
            decode_charset(&b, "Windows 1252", true).expect("cp1252"),
            "A\u{20ac}\\x81\u{e9}\u{ff}"
        );
        assert_eq!(
            decode_charset(&b, "cp1252", false).expect("cp1252"),
            "A\u{20ac}\u{e9}\u{ff}"
        );
        assert_eq!(
            decode_charset(&[0xc1, 0xd2, 0x8d], "KOI8-R", true).expect("koi8-r"),
            "\u{430}\u{440}\u{2588}"
        );
        assert_eq!(
            decode_charset(&[0xa4], "iso-8859-15", true).expect("latin-9"),
            "\u{20ac}"
        );
        assert_eq!(
            decode_charset(&[0x41], "cp-1252", true).expect_err("unknown"),
            "unknown encoding: cp-1252"
        );
        assert_eq!(
            decode_charset(&[0x41], "Shift_JIS", true).expect_err("multi-byte"),
            "unknown encoding: Shift_JIS"
        );
    }
}
