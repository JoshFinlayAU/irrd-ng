//! `multipart/form-data` GraphQL requests as v4 reads them: Starlette's
//! `MultiPartParser` on python-multipart's parser and `email.message`'s
//! header parameter parsing, then ariadne's
//! `extract_data_from_multipart_request()` and `combine_multipart_data()`.
//!
//! v4 never answers such a request with a GraphQL result. Once the data
//! is extracted, `QueryMetadataExtension.format()` reads
//! `request._json`, which only `request.json()` sets, and the
//! `AttributeError` turns into a 500. So all this module has to get right
//! is which requests fail earlier, with which 400 text.

use std::collections::HashMap;

use graphql::Value;

/// ariadne's `file_uploads.SPEC_URL`.
const SPEC_URL: &str = "https://github.com/jaydenseric/graphql-multipart-request-spec";

/// Starlette's `MultiPartParser` limits, as `Request.form()` sets them.
const MAX_FILES: usize = 1000;
const MAX_FIELDS: usize = 1000;
const MAX_PART_SIZE: usize = 1024 * 1024;

/// What became of the request.
#[derive(Debug, PartialEq)]
pub(crate) enum Extracted {
    /// A 400 with this text: ariadne's `HttpBadRequestError` or
    /// Starlette's `HTTPException` for a `MultiPartException`.
    BadRequest(String),
    /// An exception: a 500.
    Crash(String),
}

/// `extract_data_from_multipart_request()` and everything after it,
/// for a request whose content type (before any `;`) is exactly
/// `multipart/form-data`.
pub(crate) fn extract(content_type: &str, body: &[u8]) -> Extracted {
    let form = match parse_form(content_type, body) {
        Ok(f) => f,
        Err(FormError::Starlette(m)) => return Extracted::BadRequest(m),
        Err(FormError::Value) => {
            return Extracted::BadRequest(crate::messages::GRAPHQL_INVALID_MULTIPART.to_owned());
        }
    };
    // FormData: a dict of the items, the last value of a name winning.
    let mut dict: Vec<(String, &Item)> = Vec::new();
    for (k, v) in &form {
        match dict.iter_mut().find(|(n, _)| n == k) {
            Some(slot) => slot.1 = v,
            None => dict.push((k.clone(), v)),
        }
    }
    let get = |key: &str| dict.iter().find(|(k, _)| k == key).map(|(_, v)| *v);
    let json_field = |key: &str| match get(key) {
        Some(Item::Field(text)) => graphql::value::json_loads_str(text),
        _ => None,
    };
    let Some(operations) = json_field("operations") else {
        return Extracted::BadRequest(
            "Request 'operations' multipart field is not a valid JSON".to_owned(),
        );
    };
    let Some(files_map) = json_field("map") else {
        return Extracted::BadRequest(
            "Request 'map' multipart field is not a valid JSON".to_owned(),
        );
    };
    let files: Vec<&str> = dict
        .iter()
        .filter(|(_, v)| matches!(v, Item::File))
        .map(|(k, _)| k.as_str())
        .collect();

    // combine_multipart_data()
    if !matches!(operations, Value::Object(_) | Value::List(_)) {
        return Extracted::BadRequest(format!(
            "Invalid type for the 'operations' multipart field ({SPEC_URL})."
        ));
    }
    let Value::Object(entries) = &files_map else {
        return Extracted::BadRequest(format!(
            "Invalid type for the 'map' multipart field ({SPEC_URL})."
        ));
    };
    for (field_name, paths) in entries {
        let Value::List(paths) = paths else {
            return Extracted::BadRequest(format!(
                "Invalid type for the 'map' multipart field entry key '{field_name}' array ({SPEC_URL})."
            ));
        };
        for (i, path) in paths.iter().enumerate() {
            if !matches!(path, Value::Str(_)) {
                return Extracted::BadRequest(format!(
                    "Invalid type for the 'map' multipart field entry key '{field_name}' array index '{i}' value ({SPEC_URL})."
                ));
            }
            if !files.contains(&field_name.as_str()) {
                return Extracted::BadRequest(format!(
                    "File data was missing for entry key '{field_name}' ({SPEC_URL})."
                ));
            }
        }
    }
    if let Value::List(ops) = &operations
        && let Some(op) = ops.iter().find(|o| !matches!(o, Value::Object(_)))
    {
        return Extracted::Crash(format!(
            "AttributeError: '{}' object has no attribute 'get'",
            py_type(op)
        ));
    }
    Extracted::Crash("AttributeError: 'Request' object has no attribute '_json'".to_owned())
}

fn py_type(v: &Value) -> &'static str {
    match v {
        Value::Null => "NoneType",
        Value::Bool(_) => "bool",
        Value::Int(_) | Value::BigInt(_) => "int",
        Value::Float(_) => "float",
        Value::Str(_) => "str",
        Value::List(_) => "list",
        Value::Object(_) => "dict",
    }
}

// ---- Starlette's MultiPartParser ----

/// A form item: a field's decoded text, or an uploaded file (whose
/// content nothing looks at).
#[derive(Debug, PartialEq)]
enum Item {
    Field(String),
    File,
}

#[derive(Debug, PartialEq)]
enum FormError {
    /// `MultiPartException(message)`.
    Starlette(String),
    /// A `ValueError` (python-multipart's `MultipartParseError`).
    Value,
}

#[derive(Default)]
struct Part {
    content_disposition: Option<Vec<u8>>,
    field_name: String,
    data: Vec<u8>,
    is_file: bool,
}

#[derive(Default)]
struct Form {
    items: Vec<(String, Item)>,
    files: usize,
    fields: usize,
    header_name: Vec<u8>,
    header_value: Vec<u8>,
    part: Part,
    charset: String,
}

/// `_user_safe_decode()`.
fn user_safe_decode(src: &[u8], codec: &str) -> String {
    auth::email_parser::decode_strict(src, codec)
        .unwrap_or_else(|| src.iter().map(|&b| b as char).collect())
}

impl Form {
    fn part_begin(&mut self) {
        self.part = Part::default();
    }

    fn part_data(&mut self, data: &[u8]) -> Result<(), FormError> {
        if !self.part.is_file {
            if self.part.data.len() + data.len() > MAX_PART_SIZE {
                return Err(FormError::Starlette(format!(
                    "Part exceeded maximum size of {}KB.",
                    MAX_PART_SIZE / 1024
                )));
            }
            self.part.data.extend_from_slice(data);
        }
        Ok(())
    }

    fn part_end(&mut self) {
        let item = if self.part.is_file {
            Item::File
        } else {
            Item::Field(user_safe_decode(&self.part.data, &self.charset))
        };
        self.items.push((self.part.field_name.clone(), item));
    }

    fn header_end(&mut self) {
        if self
            .header_name
            .eq_ignore_ascii_case(b"content-disposition")
        {
            self.part.content_disposition = Some(std::mem::take(&mut self.header_value));
        }
        self.header_name.clear();
        self.header_value.clear();
    }

    fn headers_finished(&mut self) -> Result<(), FormError> {
        let disposition: String = self
            .part
            .content_disposition
            .as_deref()
            .unwrap_or_default()
            .iter()
            .map(|&b| b as char)
            .collect();
        let (_, options) = parse_options_header(&disposition);
        let opt = |k: &str| options.iter().rev().find(|(n, _)| n == k).map(|(_, v)| v);
        let Some(name) = opt("name") else {
            return Err(FormError::Starlette(
                "The Content-Disposition header field \"name\" must be provided.".to_owned(),
            ));
        };
        self.part.field_name = user_safe_decode(&latin1_bytes(name), &self.charset);
        if opt("filename").is_some() {
            self.files += 1;
            if self.files > MAX_FILES {
                return Err(FormError::Starlette(format!(
                    "Too many files. Maximum number of files is {MAX_FILES}."
                )));
            }
            self.part.is_file = true;
        } else {
            self.fields += 1;
            if self.fields > MAX_FIELDS {
                return Err(FormError::Starlette(format!(
                    "Too many fields. Maximum number of fields is {MAX_FIELDS}."
                )));
            }
            self.part.is_file = false;
        }
        Ok(())
    }
}

fn latin1_bytes(s: &str) -> Vec<u8> {
    s.chars().map(|c| c as u32 as u8).collect()
}

/// `MultiPartParser.parse()`: the form items, in order.
fn parse_form(content_type: &str, body: &[u8]) -> Result<Vec<(String, Item)>, FormError> {
    let (_, params) = parse_options_header(content_type);
    let param = |k: &str| {
        params
            .iter()
            .rev()
            .find(|(n, _)| n == k)
            .map(|(_, v)| v.clone())
    };
    let mut form = Form {
        charset: param("charset").unwrap_or_else(|| "utf-8".to_owned()),
        ..Form::default()
    };
    let Some(boundary) = param("boundary") else {
        return Err(FormError::Starlette(
            "Missing boundary in multipart.".to_owned(),
        ));
    };
    let mut b = b"\r\n--".to_vec();
    b.extend(latin1_bytes(&boundary));
    // The whole body as one chunk: python-multipart gives the same
    // result for any chunking of a well-formed body.
    write(&b, body, &mut form)?;
    Ok(form.items)
}

#[derive(Clone, Copy, PartialEq)]
enum State {
    Start,
    StartBoundary,
    HeaderFieldStart,
    HeaderField,
    HeaderValueStart,
    HeaderValue,
    HeaderValueAlmostDone,
    HeadersAlmostDone,
    PartDataStart,
    PartData,
    EndBoundary,
    End,
}

const FLAG_PART_BOUNDARY: u8 = 1;
const FLAG_LAST_BOUNDARY: u8 = 2;

fn is_token(c: u8) -> bool {
    c.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&c)
}

/// python-multipart's `MultipartParser._internal_write()` for a single
/// chunk, with Starlette's callbacks.
fn write(boundary: &[u8], data: &[u8], form: &mut Form) -> Result<(), FormError> {
    let length = data.len();
    let blen = boundary.len();
    let mut state = State::Start;
    let mut index = 0usize;
    let mut flags = 0u8;
    let mut marks: HashMap<&'static str, usize> = HashMap::new();
    // data_callback(): the marked data up to `end`, if any.
    fn take(
        marks: &mut HashMap<&'static str, usize>,
        name: &'static str,
        end: usize,
    ) -> Option<(usize, usize)> {
        let m = marks.remove(name)?;
        (end > m).then_some((m, end))
    }
    let mut i: isize = 0;
    while (i as usize) < length {
        let iu = i as usize;
        let mut c = data[iu];
        match state {
            State::Start => {
                if c == b'\r' || c == b'\n' {
                    i += 1;
                    continue;
                }
                index = 0;
                state = State::StartBoundary;
                i -= 1;
            }
            State::StartBoundary => {
                if index == blen - 2 {
                    if c == b'-' {
                        state = State::EndBoundary;
                    } else if c != b'\r' {
                        return Err(FormError::Value);
                    }
                    index += 1;
                } else if index == blen - 2 + 1 {
                    if c != b'\n' {
                        return Err(FormError::Value);
                    }
                    index = 0;
                    form.part_begin();
                    state = State::HeaderFieldStart;
                } else {
                    if c != boundary[index + 2] {
                        return Err(FormError::Value);
                    }
                    index += 1;
                }
            }
            State::HeaderFieldStart => {
                index = 0;
                marks.insert("header_field", iu);
                state = State::HeaderField;
                i -= 1;
            }
            State::HeaderField => {
                if c == b'\r' && index == 0 {
                    marks.remove("header_field");
                    state = State::HeadersAlmostDone;
                    i += 1;
                    continue;
                }
                index += 1;
                if c == b':' {
                    if index == 1 {
                        return Err(FormError::Value);
                    }
                    if let Some((a, b)) = take(&mut marks, "header_field", iu) {
                        form.header_name.extend_from_slice(&data[a..b]);
                    }
                    state = State::HeaderValueStart;
                } else if !is_token(c) {
                    return Err(FormError::Value);
                }
            }
            State::HeaderValueStart => {
                if c == b' ' {
                    i += 1;
                    continue;
                }
                marks.insert("header_value", iu);
                state = State::HeaderValue;
                i -= 1;
            }
            State::HeaderValue => {
                if c == b'\r' {
                    if let Some((a, b)) = take(&mut marks, "header_value", iu) {
                        form.header_value.extend_from_slice(&data[a..b]);
                    }
                    form.header_end();
                    state = State::HeaderValueAlmostDone;
                }
            }
            State::HeaderValueAlmostDone => {
                if c != b'\n' {
                    return Err(FormError::Value);
                }
                state = State::HeaderFieldStart;
            }
            State::HeadersAlmostDone => {
                if c != b'\n' {
                    return Err(FormError::Value);
                }
                form.headers_finished()?;
                state = State::PartDataStart;
            }
            State::PartDataStart => {
                marks.insert("part_data", iu);
                state = State::PartData;
                i -= 1;
            }
            State::PartData => {
                let prev_index = index;
                let mut iu = iu;
                if index == 0 {
                    match find(data, boundary, iu) {
                        Some(i0) => {
                            index = blen - 1;
                            iu = i0 + blen - 1;
                        }
                        None => {
                            iu = iu.max(length.saturating_sub(blen));
                            while iu < length - 1 && data[iu] != boundary[0] {
                                iu += 1;
                            }
                        }
                    }
                    c = data[iu];
                }
                if index < blen {
                    if boundary[index] == c {
                        index += 1;
                    } else {
                        index = 0;
                    }
                } else if index == blen {
                    index += 1;
                    if c == b'\r' {
                        flags |= FLAG_PART_BOUNDARY;
                    } else if c == b'-' {
                        flags |= FLAG_LAST_BOUNDARY;
                    } else {
                        index = 0;
                    }
                } else if index == blen + 1 {
                    if flags & FLAG_PART_BOUNDARY != 0 {
                        if c == b'\n' {
                            flags &= !FLAG_PART_BOUNDARY;
                            if let Some((a, b)) = take(&mut marks, "part_data", iu - index) {
                                form.part_data(&data[a..b])?;
                            }
                            form.part_end();
                            form.part_begin();
                            index = 0;
                            state = State::HeaderFieldStart;
                            i = iu as isize + 1;
                            continue;
                        }
                        index = 0;
                        flags &= !FLAG_PART_BOUNDARY;
                    } else if flags & FLAG_LAST_BOUNDARY != 0 {
                        if c == b'-' {
                            if let Some((a, b)) = take(&mut marks, "part_data", iu - index) {
                                form.part_data(&data[a..b])?;
                            }
                            form.part_end();
                            state = State::End;
                        } else {
                            index = 0;
                        }
                    }
                }
                i = iu as isize;
                if index == 0 && prev_index > 0 {
                    i -= 1;
                }
            }
            State::EndBoundary => {
                if index == blen - 2 + 1 {
                    if c != b'-' {
                        return Err(FormError::Value);
                    }
                    index += 1;
                    state = State::End;
                }
            }
            State::End => {
                if c == b'\r' && iu + 1 < length && data[iu + 1] == b'\n' {
                    i += 2;
                    continue;
                }
                break;
            }
        }
        i += 1;
    }
    // The data callbacks for what is still marked at the end of the chunk.
    if let Some((a, b)) = take(&mut marks, "header_field", length) {
        form.header_name.extend_from_slice(&data[a..b]);
    }
    if let Some((a, b)) = take(&mut marks, "header_value", length) {
        form.header_value.extend_from_slice(&data[a..b]);
    }
    if let Some((a, b)) = take(&mut marks, "part_data", length - index.min(length)) {
        form.part_data(&data[a..b])?;
    }
    Ok(())
}

/// `bytes.find(sub, start)`.
fn find(hay: &[u8], needle: &[u8], start: usize) -> Option<usize> {
    if start > hay.len() || needle.len() > hay.len() - start {
        return None;
    }
    hay[start..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| p + start)
}

// ---- python-multipart's parse_options_header ----

/// Python's `str.isspace()` for the Latin-1 range.
fn py_space(c: char) -> bool {
    matches!(
        c,
        '\t' | '\n' | '\x0b' | '\x0c' | '\r' | '\x1c'..='\x1f' | ' ' | '\u{85}' | '\u{a0}'
    )
}

fn py_strip(s: &str) -> &str {
    s.trim_matches(py_space)
}

/// `parse_options_header()` on a Latin-1 decoded header: the lower-cased
/// value without options, or the first parameter and the options in
/// order (a later duplicate wins when looked up from the end).
fn parse_options_header(value: &str) -> (String, Vec<(String, String)>) {
    if value.is_empty() {
        return (String::new(), Vec::new());
    }
    if !value.contains(';') {
        return (py_strip(&value.to_lowercase()).to_owned(), Vec::new());
    }
    let mut params = get_params(value);
    let ctype = params.remove(0).0;
    let options = params
        .into_iter()
        .map(|(k, v)| {
            let mut v = match v {
                Param::Plain(s) => s,
                Param::Rfc2231(_, _, s) => s,
            };
            if k == "filename" {
                let chars: Vec<char> = v.chars().collect();
                let ie = (chars.len() >= 3 && chars[1] == ':' && chars[2] == '\\')
                    || v.starts_with("\\\\");
                if ie {
                    v = v.rsplit('\\').next().unwrap_or_default().to_owned();
                }
            }
            (k, v)
        })
        .collect();
    (ctype, options)
}

enum Param {
    Plain(String),
    Rfc2231(Option<String>, Option<String>, String),
}

/// Python's index normalisation for `str.count()` and `str.find()`.
fn py_index(i: isize, len: usize) -> usize {
    if i < 0 {
        (i + len as isize).max(0) as usize
    } else {
        (i as usize).min(len)
    }
}

fn py_count(s: &[char], sub: &[char], start: isize, end: isize) -> isize {
    let (a, b) = (py_index(start, s.len()), py_index(end, s.len()));
    if a > b || b - a < sub.len() {
        return 0;
    }
    let mut n = 0;
    let mut i = a;
    while i + sub.len() <= b {
        if s[i..i + sub.len()] == *sub {
            n += 1;
            i += sub.len();
        } else {
            i += 1;
        }
    }
    n
}

fn py_find(s: &[char], c: char, start: isize, end: Option<isize>) -> isize {
    let a = py_index(start, s.len());
    let b = end.map_or(s.len(), |e| py_index(e, s.len()));
    if a > b {
        return -1;
    }
    s[a..b]
        .iter()
        .position(|&x| x == c)
        .map_or(-1, |p| (p + a) as isize)
}

/// `email.message._parseparam()`, quirks included.
fn parseparam(value: &str) -> Vec<String> {
    let s: Vec<char> = std::iter::once(';').chain(value.chars()).collect();
    let len = s.len() as isize;
    let text = |a: isize, b: isize| -> String {
        s[py_index(a, s.len())..py_index(b, s.len()).max(py_index(a, s.len()))]
            .iter()
            .collect()
    };
    let mut plist = Vec::new();
    let mut start: isize = 0;
    let mut guard = 0;
    while py_find(&s, ';', start, None) == start {
        start += 1;
        let mut end = py_find(&s, ';', start, None);
        let (mut ind, mut diff) = (start, 0isize);
        while end > 0 {
            diff += py_count(&s, &['"'], ind, end) - py_count(&s, &['\\', '"'], ind, end);
            if diff % 2 == 0 {
                break;
            }
            let next = py_find(&s, ';', end + 1, None);
            end = ind;
            ind = next;
            guard += 1;
            if guard > 100_000 {
                break;
            }
        }
        if end < 0 {
            end = len;
        }
        let i = py_find(&s, '=', start, Some(end));
        let f = if i == -1 {
            text(start, end)
        } else {
            format!(
                "{}={}",
                text(start, i).trim_end_matches(py_space).to_lowercase(),
                text(i + 1, end).trim_start_matches(py_space)
            )
        };
        plist.push(py_strip(&f).to_owned());
        start = end;
    }
    plist
}

/// `email.utils.unquote()`.
fn unquote(s: &str) -> String {
    if s.chars().count() > 1 {
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

/// `email.utils.quote()`.
fn quote(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// `urllib.parse.unquote(s, encoding="latin-1")`.
fn percent_unquote_latin1(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let hex = |c: char| c.to_digit(16);
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '%'
            && i + 2 < chars.len()
            && let (Some(a), Some(b)) = (hex(chars[i + 1]), hex(chars[i + 2]))
        {
            out.push(char::from_u32(a * 16 + b).unwrap_or('\u{fffd}'));
            i += 3;
        } else {
            out.push(chars[i]);
            i += 1;
        }
    }
    out
}

/// `Message.get_params()` (unquoted) for one header value.
fn get_params(value: &str) -> Vec<(String, Param)> {
    // _get_params_preserve()
    let raw: Vec<(String, String)> = parseparam(value)
        .into_iter()
        .map(|p| match p.split_once('=') {
            Some((n, v)) => (py_strip(n).to_owned(), py_strip(v).to_owned()),
            None => (py_strip(&p).to_owned(), String::new()),
        })
        .collect();
    // utils.decode_params()
    let mut out: Vec<(String, Param)> = Vec::new();
    let mut iter = raw.into_iter();
    if let Some((n, v)) = iter.next() {
        out.push((n, Param::Plain(v)));
    }
    type Cont = (Option<u128>, String, bool);
    let mut rfc: Vec<(String, Vec<Cont>)> = Vec::new();
    for (name, value) in iter {
        let encoded = name.ends_with('*');
        let value = unquote(&value);
        match rfc2231_continuation(&name) {
            Some((base, num)) => match rfc.iter_mut().find(|(n, _)| *n == base) {
                Some((_, v)) => v.push((num, value, encoded)),
                None => rfc.push((base, vec![(num, value, encoded)])),
            },
            None => out.push((name, Param::Plain(format!("\"{}\"", quote(&value))))),
        }
    }
    for (name, conts) in rfc {
        let has_zero = conts.iter().any(|c| c.0 == Some(0));
        let mut conts: Vec<(u128, String, bool)> = if has_zero {
            conts
                .into_iter()
                .filter_map(|(n, s, e)| n.map(|n| (n, s, e)))
                .collect()
        } else {
            conts
                .into_iter()
                .map(|(n, s, e)| (n.unwrap_or(0), s, e))
                .collect()
        };
        conts.sort_by_key(|c| c.0);
        let mut extended = false;
        let mut joined = String::new();
        for (_, s, enc) in conts {
            if enc {
                joined.push_str(&percent_unquote_latin1(&s));
                extended = true;
            } else {
                joined.push_str(&s);
            }
        }
        let v = quote(&joined);
        if extended {
            let parts: Vec<&str> = v.splitn(3, '\'').collect();
            if parts.len() <= 2 {
                out.push((name, Param::Rfc2231(None, None, format!("\"{v}\""))));
            } else {
                out.push((
                    name,
                    Param::Rfc2231(
                        Some(parts[0].to_owned()),
                        Some(parts[1].to_owned()),
                        format!("\"{}\"", parts[2]),
                    ),
                ));
            }
        } else {
            out.push((name, Param::Plain(format!("\"{v}\""))));
        }
    }
    // get_params(unquote=True)
    out.into_iter()
        .map(|(k, v)| {
            let v = match v {
                Param::Plain(s) => Param::Plain(unquote(&s)),
                Param::Rfc2231(c, l, s) => Param::Rfc2231(c, l, unquote(&s)),
            };
            (k, v)
        })
        .collect()
}

/// `rfc2231_continuation.match(name)`: `^(\w+)\*(([0-9]+)\*?)?$` (ASCII).
fn rfc2231_continuation(name: &str) -> Option<(String, Option<u128>)> {
    let (base, rest) = name.split_once('*')?;
    if base.is_empty() || !base.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        return None;
    }
    if rest.is_empty() {
        return Some((base.to_owned(), None));
    }
    let digits = rest.strip_suffix('*').unwrap_or(rest);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some((base.to_owned(), Some(digits.parse().unwrap_or(u128::MAX))))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts(h: &[u8]) -> (String, Vec<(String, String)>) {
        let s: String = h.iter().map(|&b| b as char).collect();
        let (c, o) = parse_options_header(&s);
        // A dict: the last value of a key wins, at the key's first place.
        let mut d: Vec<(String, String)> = Vec::new();
        for (k, v) in o {
            match d.iter_mut().find(|(n, _)| *n == k) {
                Some(slot) => slot.1 = v,
                None => d.push((k, v)),
            }
        }
        (c, d)
    }

    fn o(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(a, b)| ((*a).to_owned(), (*b).to_owned()))
            .collect()
    }

    /// Answers recorded from python-multipart 0.0.22 on Python 3.13.
    #[test]
    fn options_header_like_python_multipart() {
        let fd = "form-data".to_owned();
        assert_eq!(
            opts(b"form-data; name=\"a\nb\""),
            (fd.clone(), o(&[("name", "a\nb")]))
        );
        assert_eq!(
            opts(b"form-data; name=a"),
            (fd.clone(), o(&[("name", "a")]))
        );
        assert_eq!(
            opts(b"form-data; NAME = \"x\\\"y\" ; filename"),
            (fd.clone(), o(&[("name", "x\"y"), ("filename", "")]))
        );
        assert_eq!(
            opts(b"form-data; name*=utf-8%27%27%C3%A9"),
            (fd.clone(), o(&[("name", "\u{c3}\u{a9}")]))
        );
        assert_eq!(
            opts(b"form-data; name*=utf-8''%C3%A9; name=b"),
            (fd.clone(), o(&[("name", "\u{c3}\u{a9}")]))
        );
        assert_eq!(
            opts(b"form-data; name*0=a; name*1=b; name=c"),
            (fd.clone(), o(&[("name", "ab")]))
        );
        assert_eq!(
            opts(b"form-data;name=\"a;b\";filename=\"C:\\\\x\\\\y.txt\""),
            (fd.clone(), o(&[("name", "a;b"), ("filename", "y.txt")]))
        );
        assert_eq!(
            opts(b"form-data; name=\"a\"; name=\"b\""),
            (fd.clone(), o(&[("name", "b")]))
        );
        assert_eq!(
            opts(b"form-data; name=<x>"),
            (fd.clone(), o(&[("name", "x")]))
        );
        assert_eq!(opts(b";name=x"), (String::new(), o(&[("name", "x")])));
        assert_eq!(
            opts(b"form-data; =x; name"),
            (fd.clone(), o(&[("", "x"), ("name", "")]))
        );
        assert_eq!(
            opts(b"form-data; name=\"x"),
            (fd.clone(), o(&[("name", "\"x")]))
        );
        assert_eq!(
            opts(b"form-data; a=\"b;c; name=z"),
            (fd.clone(), o(&[("a", "\"b;c; name=z")]))
        );
        assert_eq!(
            opts(b"multipart/form-data; boundary=\"XX\"; charset=latin-1"),
            (
                "multipart/form-data".to_owned(),
                o(&[("boundary", "XX"), ("charset", "latin-1")])
            )
        );
        assert_eq!(
            opts(b" multipart/form-data ;boundary=XX"),
            ("multipart/form-data".to_owned(), o(&[("boundary", "XX")]))
        );
        assert_eq!(
            opts(b"form-data; name=\xe9"),
            (fd.clone(), o(&[("name", "\u{e9}")]))
        );
        assert_eq!(
            opts(b"form-data; name*=\"%41%zz\""),
            (fd.clone(), o(&[("name", "A%zz")]))
        );
        assert_eq!(
            opts(b"form-data; name*0*=x%41; name*1=%42"),
            (fd, o(&[("name", "xA%42")]))
        );
    }

    fn body(parts: &[&str]) -> Vec<u8> {
        parts.join("\r\n").into_bytes()
    }

    #[test]
    fn form_items_like_starlette() {
        let b = body(&[
            "--XX",
            "Content-Disposition: form-data; name=\"operations\"",
            "",
            "{\"query\": \"{ a }\"}",
            "--XX",
            "content-disposition: form-data; name=\"0\"; filename=\"a.txt\"",
            "Content-Type: text/plain",
            "",
            "hello",
            "--XX--",
            "",
        ]);
        let items = parse_form("multipart/form-data; boundary=XX", &b).expect("form");
        assert_eq!(
            items,
            vec![
                (
                    "operations".to_owned(),
                    Item::Field("{\"query\": \"{ a }\"}".to_owned())
                ),
                ("0".to_owned(), Item::File),
            ]
        );
        assert_eq!(
            parse_form("multipart/form-data", &b),
            Err(FormError::Starlette(
                "Missing boundary in multipart.".into()
            ))
        );
        assert_eq!(
            parse_form("multipart/form-data; boundary=YY", &b),
            Err(FormError::Value)
        );
        let unnamed = body(&["--XX", "Content-Type: text/plain", "", "x", "--XX--"]);
        assert_eq!(
            parse_form("multipart/form-data; boundary=XX", &unnamed),
            Err(FormError::Starlette(
                "The Content-Disposition header field \"name\" must be provided.".into()
            ))
        );
        // An unterminated part is dropped; a truncated body is no error.
        let open = body(&[
            "--XX",
            "Content-Disposition: form-data; name=\"a\"",
            "",
            "x",
        ]);
        assert_eq!(
            parse_form("multipart/form-data; boundary=XX", &open),
            Ok(vec![])
        );
    }

    #[test]
    fn ariadne_errors() {
        let ct = "multipart/form-data; boundary=XX";
        let mk = |ops: &str, map: &str| {
            body(&[
                "--XX",
                "Content-Disposition: form-data; name=\"operations\"",
                "",
                ops,
                "--XX",
                "Content-Disposition: form-data; name=\"map\"",
                "",
                map,
                "--XX--",
            ])
        };
        let bad = |s: &str| Extracted::BadRequest(s.to_owned());
        assert_eq!(
            extract(ct, &mk("{", "{}")),
            bad("Request 'operations' multipart field is not a valid JSON")
        );
        assert_eq!(
            extract(ct, &mk("{}", "")),
            bad("Request 'map' multipart field is not a valid JSON")
        );
        assert_eq!(
            extract(ct, &mk("1", "{}")),
            bad(&format!(
                "Invalid type for the 'operations' multipart field ({SPEC_URL})."
            ))
        );
        assert_eq!(
            extract(ct, &mk("{}", "[]")),
            bad(&format!(
                "Invalid type for the 'map' multipart field ({SPEC_URL})."
            ))
        );
        assert_eq!(
            extract(ct, &mk("{}", "{\"0\": \"x\"}")),
            bad(&format!(
                "Invalid type for the 'map' multipart field entry key '0' array ({SPEC_URL})."
            ))
        );
        assert_eq!(
            extract(ct, &mk("{}", "{\"0\": [1]}")),
            bad(&format!(
                "Invalid type for the 'map' multipart field entry key '0' array index '0' value ({SPEC_URL})."
            ))
        );
        assert_eq!(
            extract(ct, &mk("{}", "{\"0\": [\"variables.f\"]}")),
            bad(&format!(
                "File data was missing for entry key '0' ({SPEC_URL})."
            ))
        );
        assert!(matches!(
            extract(ct, &mk("{}", "{\"0\": []}")),
            Extracted::Crash(_)
        ));
    }
}
