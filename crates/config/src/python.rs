//! Just enough of Python's object model to evaluate v4's checks faithfully.
//!
//! v4 validates `irrd.yaml` by poking at whatever `yaml.safe_load` returned,
//! with Python's own truthiness, equality, `str()` and `repr()` rules, and
//! those rules leak straight into the error strings (`Invalid log.level: 5.`,
//! the list `repr()` in the startup message). This module reproduces them for
//! every type PyYAML's safe loader can produce.

use std::fmt::Write as _;

use num_bigint::BigInt;
use num_traits::Zero;
use unicode_general_category::{GeneralCategory, get_general_category};

/// A Python exception that v4 does not catch.
///
/// v4 crashes with a traceback in these cases. irrd-ng refuses the
/// configuration instead and reports the exception v4 would have raised.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PyException {
    /// The exception class name, e.g. `TypeError`.
    pub kind: &'static str,
    /// `str()` of the exception.
    pub message: String,
}

impl PyException {
    pub(crate) fn new(kind: &'static str, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    pub(crate) fn type_error(message: impl Into<String>) -> Self {
        Self::new("TypeError", message)
    }

    pub(crate) fn value_error(message: impl Into<String>) -> Self {
        Self::new("ValueError", message)
    }

    pub(crate) fn attribute_error(value: &Value, attribute: &str) -> Self {
        if let Value::Dict(_) = value {
            // DottedDict's __getattr__ is its __getitem__.
            return Self::new("KeyError", str_repr(attribute));
        }
        Self::new(
            "AttributeError",
            format!(
                "'{}' object has no attribute '{attribute}'",
                value.type_name()
            ),
        )
    }

    pub(crate) fn not_iterable(value: &Value) -> Self {
        Self::type_error(format!("'{}' object is not iterable", value.type_name()))
    }

    pub(crate) fn unhashable(value: &Value) -> Self {
        Self::type_error(format!("unhashable type: '{}'", value.type_name()))
    }
}

impl std::fmt::Display for PyException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.kind, self.message)
    }
}

impl std::error::Error for PyException {}

/// A `datetime.datetime` as PyYAML builds it from a timestamp.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DateTime {
    pub year: i32,
    pub month: u32,
    pub day: u32,
    pub hour: u32,
    pub minute: u32,
    pub second: u32,
    pub microsecond: u32,
    /// UTC offset in seconds, `None` for a naive datetime.
    pub utc_offset: Option<i32>,
}

/// A Python object as produced by PyYAML's `SafeLoader`.
#[derive(Clone, Debug)]
pub enum Value {
    None,
    Bool(bool),
    Int(BigInt),
    Float(f64),
    Str(String),
    Bytes(Vec<u8>),
    Date {
        year: i32,
        month: u32,
        day: u32,
    },
    DateTime(DateTime),
    List(Vec<Value>),
    Tuple(Vec<Value>),
    /// A `set` from `!!set`. Python orders sets by hash; irrd-ng keeps the
    /// document order.
    Set(Vec<Value>),
    Dict(Dict),
    /// A collection that contains itself, at the point where it recurs
    /// (YAML anchors allow this). Python prints it as `{...}` or `[...]`.
    Recursive {
        mapping: bool,
    },
}

/// A Python `dict`: insertion ordered, keys compared with Python equality.
#[derive(Clone, Debug, Default)]
pub struct Dict {
    entries: Vec<(Value, Value)>,
}

impl Dict {
    pub fn new() -> Self {
        Self::default()
    }

    /// `d[key] = value`: replaces the value in place if an equal key exists.
    pub fn insert(&mut self, key: Value, value: Value) {
        if let Some(entry) = self.entries.iter_mut().find(|(k, _)| k.py_eq(&key)) {
            entry.1 = value;
        } else {
            self.entries.push((key, value));
        }
    }

    pub fn get(&self, key: &Value) -> Option<&Value> {
        self.entries
            .iter()
            .find(|(k, _)| k.py_eq(key))
            .map(|(_, v)| v)
    }

    /// Lookup by a string key, the common case after DottedDict validation.
    pub fn get_str(&self, key: &str) -> Option<&Value> {
        self.entries
            .iter()
            .find(|(k, _)| matches!(k, Value::Str(s) if s == key))
            .map(|(_, v)| v)
    }

    pub fn contains_key(&self, key: &Value) -> bool {
        self.get(key).is_some()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&Value, &Value)> {
        self.entries.iter().map(|(k, v)| (k, v))
    }

    pub fn keys(&self) -> impl Iterator<Item = &Value> {
        self.entries.iter().map(|(k, _)| k)
    }

    pub fn values(&self) -> impl Iterator<Item = &Value> {
        self.entries.iter().map(|(_, v)| v)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Value {
    pub fn str(s: impl Into<String>) -> Self {
        Value::Str(s.into())
    }

    pub fn int(i: i64) -> Self {
        Value::Int(BigInt::from(i))
    }

    /// The Python type name, as used in exception messages. Mappings and
    /// lists are named as v4 sees them inside the `irrd` mapping.
    pub fn type_name(&self) -> &'static str {
        match self {
            Value::None => "NoneType",
            Value::Bool(_) => "bool",
            Value::Int(_) => "int",
            Value::Float(_) => "float",
            Value::Str(_) => "str",
            Value::Bytes(_) => "bytes",
            Value::Date { .. } => "datetime.date",
            Value::DateTime(_) => "datetime.datetime",
            Value::List(_) => "DottedList",
            Value::Tuple(_) => "tuple",
            Value::Set(_) => "set",
            Value::Dict(_) | Value::Recursive { mapping: true } => "DottedDict",
            Value::Recursive { mapping: false } => "DottedList",
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_dict(&self) -> Option<&Dict> {
        match self {
            Value::Dict(d) => Some(d),
            _ => None,
        }
    }

    /// Python truthiness, `bool(value)`.
    pub fn truthy(&self) -> bool {
        match self {
            Value::None => false,
            Value::Bool(b) => *b,
            Value::Int(i) => !i.is_zero(),
            Value::Float(f) => *f != 0.0,
            Value::Str(s) => !s.is_empty(),
            Value::Bytes(b) => !b.is_empty(),
            Value::Date { .. } | Value::DateTime(_) => true,
            Value::List(l) | Value::Tuple(l) | Value::Set(l) => !l.is_empty(),
            Value::Dict(d) => !d.is_empty(),
            Value::Recursive { .. } => true,
        }
    }

    /// Whether `hash(value)` succeeds.
    pub fn is_hashable(&self) -> bool {
        match self {
            Value::List(_) | Value::Set(_) | Value::Dict(_) | Value::Recursive { .. } => false,
            Value::Tuple(items) => items.iter().all(Value::is_hashable),
            _ => true,
        }
    }

    /// Python `==`.
    pub fn py_eq(&self, other: &Value) -> bool {
        use Value::*;
        match (self, other) {
            (None, None) => true,
            (Str(a), Str(b)) => a == b,
            (Bytes(a), Bytes(b)) => a == b,
            (
                Date {
                    year: y1,
                    month: m1,
                    day: d1,
                },
                Date {
                    year: y2,
                    month: m2,
                    day: d2,
                },
            ) => (y1, m1, d1) == (y2, m2, d2),
            (DateTime(a), DateTime(b)) => {
                if a.utc_offset.is_some() != b.utc_offset.is_some() {
                    return false;
                }
                datetime_ordinal_seconds(a) == datetime_ordinal_seconds(b)
                    && a.microsecond == b.microsecond
            }
            (List(a), List(b)) | (Tuple(a), Tuple(b)) => {
                a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x.py_eq(y))
            }
            (Set(a), Set(b)) => {
                a.len() == b.len() && a.iter().all(|x| b.iter().any(|y| x.py_eq(y)))
            }
            (Dict(a), Dict(b)) => {
                a.len() == b.len()
                    && a.iter()
                        .all(|(k, v)| b.get(k).is_some_and(|v2| v.py_eq(v2)))
            }
            _ => match (self.as_number(), other.as_number()) {
                (Some(a), Some(b)) => a.eq(&b),
                _ => false,
            },
        }
    }

    fn as_number(&self) -> Option<Number> {
        match self {
            Value::Bool(b) => Some(Number::Int(BigInt::from(u8::from(*b)))),
            Value::Int(i) => Some(Number::Int(i.clone())),
            Value::Float(f) => Some(Number::Float(*f)),
            _ => None,
        }
    }

    /// `str(value)`.
    pub fn py_str(&self) -> String {
        match self {
            Value::Str(s) => s.clone(),
            Value::Date { year, month, day } => format!("{year:04}-{month:02}-{day:02}"),
            Value::DateTime(dt) => datetime_str(dt),
            _ => self.py_repr(),
        }
    }

    /// `repr(value)`.
    pub fn py_repr(&self) -> String {
        let mut out = String::new();
        self.write_repr(&mut out);
        out
    }

    fn write_repr(&self, out: &mut String) {
        match self {
            Value::None => out.push_str("None"),
            Value::Bool(true) => out.push_str("True"),
            Value::Bool(false) => out.push_str("False"),
            Value::Int(i) => {
                let _ = write!(out, "{i}");
            }
            Value::Float(f) => out.push_str(&float_repr(*f)),
            Value::Str(s) => out.push_str(&str_repr(s)),
            Value::Bytes(b) => out.push_str(&bytes_repr(b)),
            Value::Date { year, month, day } => {
                let _ = write!(out, "datetime.date({year}, {month}, {day})");
            }
            Value::DateTime(dt) => out.push_str(&datetime_repr(dt)),
            Value::List(items) => write_seq(out, "[", "]", items),
            Value::Tuple(items) => {
                if items.len() == 1 {
                    out.push('(');
                    items[0].write_repr(out);
                    out.push_str(",)");
                } else {
                    write_seq(out, "(", ")", items);
                }
            }
            Value::Set(items) => {
                if items.is_empty() {
                    out.push_str("set()");
                } else {
                    write_seq(out, "{", "}", items);
                }
            }
            Value::Recursive { mapping: true } => out.push_str("{...}"),
            Value::Recursive { mapping: false } => out.push_str("[...]"),
            Value::Dict(d) => {
                out.push('{');
                for (i, (k, v)) in d.iter().enumerate() {
                    if i > 0 {
                        out.push_str(", ");
                    }
                    k.write_repr(out);
                    out.push_str(": ");
                    v.write_repr(out);
                }
                out.push('}');
            }
        }
    }

    /// Iterate the way a Python `for` loop does.
    pub fn py_iter(&self) -> Result<Vec<Value>, PyException> {
        match self {
            Value::List(items) | Value::Tuple(items) | Value::Set(items) => Ok(items.clone()),
            Value::Dict(d) => Ok(d.keys().cloned().collect()),
            Value::Str(s) => Ok(s.chars().map(|c| Value::Str(c.to_string())).collect()),
            Value::Bytes(b) => Ok(b.iter().map(|x| Value::int(i64::from(*x))).collect()),
            other => Err(PyException::not_iterable(other)),
        }
    }

    /// Python `needle in self`.
    pub fn py_contains(&self, needle: &Value) -> Result<bool, PyException> {
        match (self, needle) {
            (Value::Str(hay), Value::Str(n)) => Ok(hay.contains(n.as_str())),
            (Value::Str(_), other) => Err(PyException::type_error(format!(
                "'in <string>' requires string as left operand, not {}",
                other.type_name()
            ))),
            (Value::Dict(d), n) => {
                if !n.is_hashable() {
                    return Err(PyException::unhashable(n));
                }
                Ok(d.contains_key(n))
            }
            (Value::List(items) | Value::Tuple(items), n) => Ok(items.iter().any(|i| i.py_eq(n))),
            (Value::Set(items), n) => {
                if !n.is_hashable() {
                    return Err(PyException::unhashable(n));
                }
                Ok(items.iter().any(|i| i.py_eq(n)))
            }
            (other, _) => Err(PyException::type_error(format!(
                "argument of type '{}' is not iterable",
                other.type_name()
            ))),
        }
    }
}

#[derive(Debug)]
enum Number {
    Int(BigInt),
    Float(f64),
}

impl Number {
    fn eq(&self, other: &Number) -> bool {
        match (self, other) {
            (Number::Int(a), Number::Int(b)) => a == b,
            (Number::Float(a), Number::Float(b)) => a == b,
            (Number::Int(i), Number::Float(f)) | (Number::Float(f), Number::Int(i)) => {
                f.is_finite() && f.fract() == 0.0 && float_to_bigint(*f).is_some_and(|x| &x == i)
            }
        }
    }
}

/// Exact conversion of an integral, finite float to an integer.
pub(crate) fn float_to_bigint(f: f64) -> Option<BigInt> {
    if !f.is_finite() {
        return None;
    }
    let t = f.trunc();
    if t.abs() < 9.0e15 {
        // Exactly representable as i64.
        #[allow(clippy::cast_possible_truncation)]
        return Some(BigInt::from(t as i64));
    }
    // Decompose: t = mantissa * 2^exp with an exact integer mantissa.
    let bits = t.to_bits();
    let negative = bits >> 63 == 1;
    let exponent = i64::try_from((bits >> 52) & 0x7ff).ok()? - 1075;
    let mantissa = (bits & 0x000f_ffff_ffff_ffff) | 0x0010_0000_0000_0000;
    let mut value = BigInt::from(mantissa);
    if exponent >= 0 {
        value <<= usize::try_from(exponent).ok()?;
    } else {
        value >>= usize::try_from(-exponent).ok()?;
    }
    Some(if negative { -value } else { value })
}

fn write_seq(out: &mut String, open: &str, close: &str, items: &[Value]) {
    out.push_str(open);
    for (i, item) in items.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        item.write_repr(out);
    }
    out.push_str(close);
}

/// Python's `str.isprintable()` for one character.
pub(crate) fn is_printable(c: char) -> bool {
    if c == ' ' {
        return true;
    }
    !matches!(
        get_general_category(c),
        GeneralCategory::Control
            | GeneralCategory::Format
            | GeneralCategory::Surrogate
            | GeneralCategory::PrivateUse
            | GeneralCategory::Unassigned
            | GeneralCategory::LineSeparator
            | GeneralCategory::ParagraphSeparator
            | GeneralCategory::SpaceSeparator
    )
}

/// Python's `repr()` of a `str`.
pub fn str_repr(s: &str) -> String {
    let quote = if s.contains('\'') && !s.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::with_capacity(s.len() + 2);
    out.push(quote);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if is_printable(c) => out.push(c),
            c => {
                let cp = u32::from(c);
                if cp < 0x100 {
                    let _ = write!(out, "\\x{cp:02x}");
                } else if cp < 0x10000 {
                    let _ = write!(out, "\\u{cp:04x}");
                } else {
                    let _ = write!(out, "\\U{cp:08x}");
                }
            }
        }
    }
    out.push(quote);
    out
}

/// Python's `repr()` of a `bytes`.
pub fn bytes_repr(b: &[u8]) -> String {
    let quote = if b.contains(&b'\'') && !b.contains(&b'"') {
        b'"'
    } else {
        b'\''
    };
    let mut out = String::from("b");
    out.push(char::from(quote));
    for &c in b {
        match c {
            b'\\' => out.push_str("\\\\"),
            b'\t' => out.push_str("\\t"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            c if c == quote => {
                out.push('\\');
                out.push(char::from(c));
            }
            0x20..=0x7e => out.push(char::from(c)),
            c => {
                let _ = write!(out, "\\x{c:02x}");
            }
        }
    }
    out.push(char::from(quote));
    out
}

/// Python's `repr()` of a list of strings, as v4's startup error uses it.
pub fn str_list_repr(items: &[String]) -> String {
    let mut out = String::from("[");
    for (i, item) in items.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        out.push_str(&str_repr(item));
    }
    out.push(']');
    out
}

/// Python's `repr()` of a float (`float_repr_style == 'short'`).
pub(crate) fn float_repr(f: f64) -> String {
    if f.is_nan() {
        return "nan".to_owned();
    }
    if f.is_infinite() {
        return if f > 0.0 { "inf" } else { "-inf" }.to_owned();
    }
    // `{:e}` gives the shortest round-tripping digits, e.g. `-1.5e-5`.
    let sci = format!("{f:e}");
    let (mantissa, exp) = sci.split_once('e').unwrap_or((&sci, "0"));
    let exp: i32 = exp.parse().unwrap_or(0);
    let (negative, mantissa) = match mantissa.strip_prefix('-') {
        Some(m) => (true, m),
        None => (false, mantissa),
    };
    let digits: String = mantissa.chars().filter(char::is_ascii_digit).collect();
    let decpt = exp + 1;
    let mut out = String::new();
    if negative {
        out.push('-');
    }
    if (-4 < decpt) && (decpt <= 16) {
        let ndigits = i32::try_from(digits.len()).unwrap_or(i32::MAX);
        if decpt <= 0 {
            out.push_str("0.");
            for _ in 0..(-decpt) {
                out.push('0');
            }
            out.push_str(&digits);
        } else if decpt >= ndigits {
            out.push_str(&digits);
            for _ in 0..(decpt - ndigits) {
                out.push('0');
            }
            out.push_str(".0");
        } else {
            let split = usize::try_from(decpt).unwrap_or(0);
            out.push_str(&digits[..split]);
            out.push('.');
            out.push_str(&digits[split..]);
        }
    } else {
        out.push_str(&digits[..1]);
        if digits.len() > 1 {
            out.push('.');
            out.push_str(&digits[1..]);
        }
        let e = decpt - 1;
        let _ = write!(out, "e{}{:02}", if e < 0 { '-' } else { '+' }, e.abs());
    }
    out
}

fn utc_offset_str(offset: i32) -> String {
    let sign = if offset < 0 { '-' } else { '+' };
    let abs = offset.abs();
    let (h, m, s) = (abs / 3600, (abs % 3600) / 60, abs % 60);
    if s != 0 {
        format!("{sign}{h:02}:{m:02}:{s:02}")
    } else {
        format!("{sign}{h:02}:{m:02}")
    }
}

fn datetime_str(dt: &DateTime) -> String {
    let mut out = format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second
    );
    if dt.microsecond != 0 {
        let _ = write!(out, ".{:06}", dt.microsecond);
    }
    if let Some(offset) = dt.utc_offset {
        out.push_str(&utc_offset_str(offset));
    }
    out
}

fn timedelta_repr(seconds: i32) -> String {
    if seconds == 0 {
        return "datetime.timedelta(0)".to_owned();
    }
    let days = seconds.div_euclid(86400);
    let secs = seconds.rem_euclid(86400);
    let mut parts = Vec::new();
    if days != 0 {
        parts.push(format!("days={days}"));
    }
    if secs != 0 {
        parts.push(format!("seconds={secs}"));
    }
    format!("datetime.timedelta({})", parts.join(", "))
}

fn datetime_repr(dt: &DateTime) -> String {
    let mut fields = vec![
        i64::from(dt.year),
        i64::from(dt.month),
        i64::from(dt.day),
        i64::from(dt.hour),
        i64::from(dt.minute),
        i64::from(dt.second),
        i64::from(dt.microsecond),
    ];
    for _ in 0..2 {
        if fields.last() == Some(&0) {
            fields.pop();
        }
    }
    let fields: Vec<String> = fields.iter().map(i64::to_string).collect();
    let mut out = format!("datetime.datetime({}", fields.join(", "));
    match dt.utc_offset {
        Some(0) => out.push_str(", tzinfo=datetime.timezone.utc"),
        Some(offset) => {
            let _ = write!(
                out,
                ", tzinfo=datetime.timezone({})",
                timedelta_repr(offset)
            );
        }
        None => {}
    }
    out.push(')');
    out
}

fn datetime_ordinal_seconds(dt: &DateTime) -> i64 {
    // Days from civil, then seconds, adjusted to UTC when aware.
    let y = i64::from(dt.year) - i64::from(dt.month <= 2);
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let m = i64::from(dt.month);
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + i64::from(dt.day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe;
    days * 86400 + i64::from(dt.hour) * 3600 + i64::from(dt.minute) * 60 + i64::from(dt.second)
        - i64::from(dt.utc_offset.unwrap_or(0))
}

/// Python's `str.isspace()` for one character.
pub(crate) fn is_space(c: char) -> bool {
    matches!(
        c,
        '\t' | '\n'
            | '\x0b'
            | '\x0c'
            | '\r'
            | '\x1c'..='\x1f'
            | ' '
            | '\u{85}'
            | '\u{a0}'
            | '\u{1680}'
            | '\u{2000}'..='\u{200a}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{202f}'
            | '\u{205f}'
            | '\u{3000}'
    )
}

/// Python's `str.isnumeric()`.
///
/// Rust knows the Nd, Nl and No categories, which covers every character an
/// operator could plausibly type; Python additionally counts CJK ideographs
/// with a numeric value (e.g. `一`).
pub(crate) fn str_isnumeric(s: &str) -> bool {
    !s.is_empty() && s.chars().all(char::is_numeric)
}

/// The decimal value of a Unicode `Nd` character, as Python's `int()` uses it.
pub(crate) fn decimal_value(c: char) -> Option<u32> {
    if c.is_ascii_digit() {
        return c.to_digit(10);
    }
    if get_general_category(c) != GeneralCategory::DecimalNumber {
        return None;
    }
    // Nd characters come in contiguous runs of ten, 0 to 9.
    let mut start = u32::from(c);
    while start > 0 {
        let prev = char::from_u32(start - 1)?;
        if get_general_category(prev) != GeneralCategory::DecimalNumber {
            break;
        }
        start -= 1;
    }
    Some((u32::from(c) - start) % 10)
}

/// Python's `int(text, base)` for a `str` argument.
pub(crate) fn int_from_str(text: &str, base: u32) -> Result<BigInt, PyException> {
    let invalid = || {
        let mut shown = str_repr(text);
        if shown.chars().count() > 200 {
            shown = shown.chars().take(200).collect();
        }
        PyException::value_error(format!(
            "invalid literal for int() with base {base}: {shown}"
        ))
    };
    let s = text.trim_matches(is_space);
    let (negative, s) = if let Some(rest) = s.strip_prefix('-') {
        (true, rest)
    } else if let Some(rest) = s.strip_prefix('+') {
        (false, rest)
    } else {
        (false, s)
    };
    let mut body = s;
    let mut prefixed = false;
    let lower: String = s.chars().take(2).collect::<String>().to_ascii_lowercase();
    let prefix = match base {
        16 => Some("0x"),
        8 => Some("0o"),
        2 => Some("0b"),
        _ => None,
    };
    if let Some(p) = prefix
        && lower == p
    {
        body = &s[2..];
        prefixed = true;
    }
    if body.is_empty() {
        return Err(invalid());
    }
    let mut value = BigInt::zero();
    let mut prev_underscore = !prefixed;
    let mut any_digit = false;
    for c in body.chars() {
        if c == '_' {
            if prev_underscore {
                return Err(invalid());
            }
            prev_underscore = true;
            continue;
        }
        let digit = if base == 10 {
            decimal_value(c)
        } else {
            c.to_digit(base).or_else(|| {
                // Python also accepts non-ASCII decimal digits in any base.
                decimal_value(c).filter(|d| *d < base)
            })
        };
        let Some(d) = digit else {
            return Err(invalid());
        };
        value = value * base + d;
        prev_underscore = false;
        any_digit = true;
    }
    if prev_underscore || !any_digit {
        return Err(invalid());
    }
    // Python rejects base-10 literals with leading zeros only in source code,
    // not in int(), so nothing else to check.
    Ok(if negative { -value } else { value })
}

/// Python's `int(value)` with no base.
pub(crate) fn int_of(value: &Value) -> Result<BigInt, PyException> {
    match value {
        Value::Bool(b) => Ok(BigInt::from(u8::from(*b))),
        Value::Int(i) => Ok(i.clone()),
        Value::Float(f) => {
            if f.is_nan() {
                Err(PyException::value_error(
                    "cannot convert float NaN to integer",
                ))
            } else if f.is_infinite() {
                Err(PyException::new(
                    "OverflowError",
                    "cannot convert float infinity to integer",
                ))
            } else {
                float_to_bigint(*f).ok_or_else(|| PyException::value_error("bad float"))
            }
        }
        Value::Str(s) => int_from_str(s, 10),
        Value::Bytes(b) => match std::str::from_utf8(b) {
            Ok(s) if s.is_ascii() => int_from_str(s, 10).map_err(|_| {
                PyException::value_error(format!(
                    "invalid literal for int() with base 10: {}",
                    bytes_repr(b)
                ))
            }),
            _ => Err(PyException::value_error(format!(
                "invalid literal for int() with base 10: {}",
                bytes_repr(b)
            ))),
        },
        other => Err(PyException::type_error(format!(
            "int() argument must be a string, a bytes-like object or a real number, not '{}'",
            other.type_name()
        ))),
    }
}

/// Python's `float(text)` for a `str` argument.
pub(crate) fn float_from_str(text: &str) -> Result<f64, PyException> {
    let s = text.trim_matches(is_space);
    let ok_chars = s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '+' | '-' | '_'));
    let cleaned = s.replace('_', "");
    let valid_underscores = !s.starts_with('_')
        && !s.ends_with('_')
        && !s.contains("__")
        && s.char_indices().all(|(i, c)| {
            c != '_' || {
                let before = s[..i].chars().next_back();
                let after = s[i + 1..].chars().next();
                before.is_some_and(|b| b.is_ascii_digit())
                    && after.is_some_and(|a| a.is_ascii_digit())
            }
        });
    let lower = cleaned.to_ascii_lowercase();
    let unsigned = lower.trim_start_matches(['+', '-']);
    let named = matches!(unsigned, "inf" | "infinity" | "nan");
    if ok_chars
        && valid_underscores
        && !s.is_empty()
        && (named
            || !unsigned
                .chars()
                .any(|c| c.is_ascii_alphabetic() && c != 'e'))
        && let Ok(f) = cleaned.parse::<f64>()
    {
        return Ok(f);
    }
    Err(PyException::value_error(format!(
        "could not convert string to float: {}",
        str_repr(text)
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn str_repr_matches_python() {
        // Expected values produced by CPython 3.13 repr().
        let cases: &[(&str, &str)] = &[
            ("abc", "'abc'"),
            ("it's", "\"it's\""),
            ("it's \"q\"", "'it\\'s \"q\"'"),
            ("say \"hi\"", "'say \"hi\"'"),
            ("a\\b", "'a\\\\b'"),
            ("tab\there", "'tab\\there'"),
            ("nl\n", "'nl\\n'"),
            ("cr\r", "'cr\\r'"),
            ("\x00\x07\x1b\x7f", "'\\x00\\x07\\x1b\\x7f'"),
            ("\u{85}\u{a0}", "'\\x85\\xa0'"),
            ("caf\u{e9}", "'caf\u{e9}'"),
            ("\u{2028}\u{200b}\u{feff}", "'\\u2028\\u200b\\ufeff'"),
            ("\u{1f4a9}", "'\u{1f4a9}'"),
            ("\u{e000}", "'\\ue000'"),
            ("\u{10ffff}", "'\\U0010ffff'"),
            ("\u{3000}", "'\\u3000'"),
            ("", "''"),
        ];
        for (input, expected) in cases {
            assert_eq!(&str_repr(input), expected, "repr of {input:?}");
        }
    }

    #[test]
    fn list_repr_matches_python() {
        let items = vec!["a".to_owned(), "it's".to_owned(), "x\ny".to_owned()];
        assert_eq!(str_list_repr(&items), "['a', \"it's\", 'x\\ny']");
        assert_eq!(str_list_repr(&[]), "[]");
    }

    #[test]
    fn float_repr_matches_python() {
        let cases: &[(f64, &str)] = &[
            (1.5, "1.5"),
            (1.0, "1.0"),
            (0.1, "0.1"),
            (-0.0, "-0.0"),
            (1e16, "1e+16"),
            (1e15, "1000000000000000.0"),
            (123456789012345680.0, "1.2345678901234568e+17"),
            (0.0001, "0.0001"),
            (0.00001, "1e-05"),
            (1.5e-7, "1.5e-07"),
            (1e300 * 1e10, "inf"),
            (3600.0, "3600.0"),
            (1e100, "1e+100"),
        ];
        for (input, expected) in cases {
            assert_eq!(&float_repr(*input), expected, "repr of {input}");
        }
    }

    #[test]
    fn value_repr_and_str() {
        let mut d = Dict::new();
        d.insert(Value::str("a"), Value::int(1));
        d.insert(
            Value::str("b"),
            Value::List(vec![Value::None, Value::Bool(true), Value::Float(2.0)]),
        );
        let v = Value::Dict(d);
        assert_eq!(v.py_repr(), "{'a': 1, 'b': [None, True, 2.0]}");
        assert_eq!(v.py_str(), v.py_repr());
        assert_eq!(Value::str("x'").py_str(), "x'");
        let date = Value::Date {
            year: 2020,
            month: 1,
            day: 2,
        };
        assert_eq!(date.py_str(), "2020-01-02");
        assert_eq!(date.py_repr(), "datetime.date(2020, 1, 2)");
        let dt = Value::DateTime(DateTime {
            year: 2001,
            month: 12,
            day: 14,
            hour: 21,
            minute: 59,
            second: 43,
            microsecond: 100_000,
            utc_offset: Some(-5 * 3600),
        });
        assert_eq!(dt.py_str(), "2001-12-14 21:59:43.100000-05:00");
        assert_eq!(
            dt.py_repr(),
            "datetime.datetime(2001, 12, 14, 21, 59, 43, 100000, \
             tzinfo=datetime.timezone(datetime.timedelta(days=-1, seconds=68400)))"
        );
        assert_eq!(Value::Tuple(vec![Value::int(1)]).py_repr(), "(1,)");
        assert_eq!(Value::Bytes(b"a'\x00".to_vec()).py_repr(), "b\"a'\\x00\"");
    }

    #[test]
    fn dict_uses_python_key_equality() {
        let mut d = Dict::new();
        d.insert(Value::int(1), Value::str("int"));
        d.insert(Value::Bool(true), Value::str("bool"));
        d.insert(Value::Float(1.0), Value::str("float"));
        assert_eq!(d.len(), 1);
        assert_eq!(Value::Dict(d).py_repr(), "{1: 'float'}");
    }

    #[test]
    fn int_parsing_matches_python() {
        assert_eq!(int_from_str(" 42 ", 10), Ok(BigInt::from(42)));
        assert_eq!(int_from_str("-1_000", 10), Ok(BigInt::from(-1000)));
        assert_eq!(int_from_str("0x1f", 16), Ok(BigInt::from(31)));
        assert_eq!(int_from_str("1f", 16), Ok(BigInt::from(31)));
        assert_eq!(int_from_str("\u{0663}", 10), Ok(BigInt::from(3)));
        assert_eq!(
            int_from_str("", 10).map_err(|e| e.message),
            Err("invalid literal for int() with base 10: ''".to_owned())
        );
        assert_eq!(
            int_from_str("1__0", 10).map_err(|e| e.message),
            Err("invalid literal for int() with base 10: '1__0'".to_owned())
        );
        assert_eq!(
            int_from_str("g", 16).map_err(|e| e.message),
            Err("invalid literal for int() with base 16: 'g'".to_owned())
        );
    }

    #[test]
    fn float_parsing() {
        assert_eq!(float_from_str("1.5"), Ok(1.5));
        assert_eq!(float_from_str("1."), Ok(1.0));
        assert_eq!(float_from_str(".5"), Ok(0.5));
        assert!(float_from_str("inf").is_ok_and(f64::is_infinite));
        assert!(float_from_str("abc").is_err());
    }
}
