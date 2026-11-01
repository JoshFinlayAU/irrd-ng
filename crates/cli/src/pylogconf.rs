//! `log.logging_config_path`: v4 imports a Python file and passes its
//! `LOGGING` dictionary to `logging.config.dictConfig()`. irrd-ng cannot
//! run Python, so it reads the file as data: module-level assignments of
//! literals (dicts, lists, tuples, strings, numbers, `True`, `False`,
//! `None`, `dict(...)` with keyword arguments, `+` between strings, names
//! bound earlier in the file and the `logging` level constants), with
//! `import` lines skipped. That covers the configurations v4's
//! documentation shows and the common shapes: file, watched file, stream
//! and syslog handlers, formatters, and levels, handlers and propagation
//! per logger. Anything else is reported in [`LogConfig::notices`] and left
//! out, which is a proposed divergence.

use std::collections::HashMap;

/// A Python literal.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Py {
    Str(String),
    Int(i64),
    Float(f64),
    Bool(bool),
    None,
    List(Vec<Py>),
    Dict(Vec<(Py, Py)>),
}

impl Py {
    fn get(&self, key: &str) -> Option<&Py> {
        match self {
            Py::Dict(items) => items
                .iter()
                .rev()
                .find(|(k, _)| matches!(k, Py::Str(s) if s == key))
                .map(|(_, v)| v),
            _ => None,
        }
    }

    fn as_str(&self) -> Option<&str> {
        match self {
            Py::Str(s) => Some(s),
            _ => None,
        }
    }

    fn truthy(&self) -> bool {
        match self {
            Py::Str(s) => !s.is_empty(),
            Py::Int(i) => *i != 0,
            Py::Float(f) => *f != 0.0,
            Py::Bool(b) => *b,
            Py::None => false,
            Py::List(l) => !l.is_empty(),
            Py::Dict(d) => !d.is_empty(),
        }
    }

    fn items(&self) -> &[(Py, Py)] {
        match self {
            Py::Dict(d) => d,
            _ => &[],
        }
    }

    fn describe(&self) -> String {
        match self {
            Py::Str(s) => config::str_repr(s),
            Py::Int(i) => i.to_string(),
            Py::Float(f) => f.to_string(),
            Py::Bool(true) => "True".into(),
            Py::Bool(false) => "False".into(),
            Py::None => "None".into(),
            Py::List(_) => "a list".into(),
            Py::Dict(_) => "a dict".into(),
        }
    }
}

// ---------------------------------------------------------------------
// Reading the file
// ---------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Name(String),
    Str(String),
    Int(i64),
    Float(f64),
    Punct(char),
    Newline,
}

fn tokenize(src: &str) -> Result<Vec<Tok>, String> {
    let chars: Vec<char> = src.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    let mut depth = 0i32;
    while i < chars.len() {
        let c = chars[i];
        match c {
            '#' => {
                while i < chars.len() && chars[i] != '\n' {
                    i += 1;
                }
            }
            '\\' if chars.get(i + 1) == Some(&'\n') => i += 2,
            '\n' => {
                if depth == 0 && out.last() != Some(&Tok::Newline) {
                    out.push(Tok::Newline);
                }
                i += 1;
            }
            ' ' | '\t' | '\r' | '\x0c' => i += 1,
            '{' | '[' | '(' => {
                depth += 1;
                out.push(Tok::Punct(c));
                i += 1;
            }
            '}' | ']' | ')' => {
                depth -= 1;
                out.push(Tok::Punct(c));
                i += 1;
            }
            ':' | ',' | '=' | '+' | '-' | '.' | ';' | '*' => {
                out.push(Tok::Punct(c));
                i += 1;
            }
            '0'..='9' => {
                let start = i;
                while i < chars.len()
                    && (chars[i].is_ascii_alphanumeric() || chars[i] == '_' || chars[i] == '.')
                {
                    i += 1;
                }
                let text: String = chars[start..i].iter().filter(|c| **c != '_').collect();
                if let Ok(v) = text.parse::<i64>() {
                    out.push(Tok::Int(v));
                } else if let Some(hex) = text.strip_prefix("0x").or(text.strip_prefix("0X")) {
                    out.push(Tok::Int(
                        i64::from_str_radix(hex, 16).map_err(|_| format!("number {text}"))?,
                    ));
                } else if let Some(oct) = text.strip_prefix("0o").or(text.strip_prefix("0O")) {
                    out.push(Tok::Int(
                        i64::from_str_radix(oct, 8).map_err(|_| format!("number {text}"))?,
                    ));
                } else {
                    out.push(Tok::Float(
                        text.parse().map_err(|_| format!("number {text}"))?,
                    ));
                }
            }
            c if c.is_alphabetic() || c == '_' => {
                let start = i;
                while i < chars.len() && (chars[i].is_alphanumeric() || chars[i] == '_') {
                    i += 1;
                }
                let word: String = chars[start..i].iter().collect();
                let lower = word.to_ascii_lowercase();
                let is_prefix = matches!(
                    lower.as_str(),
                    "r" | "u" | "b" | "br" | "rb" | "f" | "rf" | "fr"
                );
                if is_prefix && matches!(chars.get(i), Some('\'' | '"')) {
                    if lower.contains('f') {
                        return Err("f-strings".into());
                    }
                    let (s, next) = string(&chars, i, lower.contains('r'))?;
                    out.push(Tok::Str(s));
                    i = next;
                } else {
                    out.push(Tok::Name(word));
                }
            }
            '\'' | '"' => {
                let (s, next) = string(&chars, i, false)?;
                out.push(Tok::Str(s));
                i = next;
            }
            other => return Err(format!("the character {other:?}")),
        }
    }
    out.push(Tok::Newline);
    Ok(out)
}

/// A string literal starting at `chars[i]` (the quote).
fn string(chars: &[char], mut i: usize, raw: bool) -> Result<(String, usize), String> {
    let q = chars[i];
    let triple = chars.get(i + 1) == Some(&q) && chars.get(i + 2) == Some(&q);
    i += if triple { 3 } else { 1 };
    let mut s = String::new();
    loop {
        let Some(&c) = chars.get(i) else {
            return Err("an unterminated string".into());
        };
        if c == q {
            if !triple {
                return Ok((s, i + 1));
            }
            if chars.get(i + 1) == Some(&q) && chars.get(i + 2) == Some(&q) {
                return Ok((s, i + 3));
            }
        }
        if c == '\n' && !triple {
            return Err("an unterminated string".into());
        }
        if c == '\\' && !raw {
            let Some(&e) = chars.get(i + 1) else {
                return Err("an unterminated string".into());
            };
            i += 2;
            match e {
                'n' => s.push('\n'),
                't' => s.push('\t'),
                'r' => s.push('\r'),
                '0' => s.push('\0'),
                '\\' => s.push('\\'),
                '\'' => s.push('\''),
                '"' => s.push('"'),
                '\n' => {}
                'x' | 'u' | 'U' => {
                    let n = match e {
                        'x' => 2,
                        'u' => 4,
                        _ => 8,
                    };
                    let hex: String = chars.get(i..i + n).unwrap_or_default().iter().collect();
                    let v = u32::from_str_radix(&hex, 16).map_err(|_| "a bad escape".to_owned())?;
                    s.push(char::from_u32(v).ok_or("a bad escape")?);
                    i += n;
                }
                other => {
                    s.push('\\');
                    s.push(other);
                }
            }
            continue;
        }
        if c == '\\' && raw && chars.get(i + 1) == Some(&q) {
            s.push('\\');
            s.push(q);
            i += 2;
            continue;
        }
        s.push(c);
        i += 1;
    }
}

struct Parser<'a> {
    toks: &'a [Tok],
    pos: usize,
    names: HashMap<String, Py>,
}

/// `logging` module constants a configuration may name.
fn constant(name: &str) -> Option<Py> {
    let level = |n: i64| Some(Py::Int(n));
    match name {
        "True" => Some(Py::Bool(true)),
        "False" => Some(Py::Bool(false)),
        "None" => Some(Py::None),
        "logging.CRITICAL" | "logging.FATAL" => level(50),
        "logging.ERROR" => level(40),
        "logging.WARNING" | "logging.WARN" => level(30),
        "logging.INFO" => level(20),
        "logging.DEBUG" => level(10),
        "logging.NOTSET" => level(0),
        _ => name
            .strip_prefix("logging.handlers.SysLogHandler.LOG_")
            .and_then(|f| facility(&f.to_ascii_lowercase()))
            .map(Py::Int),
    }
}

impl Parser<'_> {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }

    fn next(&mut self) -> Option<Tok> {
        let t = self.toks.get(self.pos).cloned();
        self.pos += 1;
        t
    }

    fn eat(&mut self, c: char) -> bool {
        if self.peek() == Some(&Tok::Punct(c)) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn expect(&mut self, c: char) -> Result<(), String> {
        if self.eat(c) {
            Ok(())
        } else {
            Err(format!("expected '{c}'"))
        }
    }

    fn dotted_name(&mut self, first: String) -> String {
        let mut name = first;
        while self.peek() == Some(&Tok::Punct('.')) {
            if let Some(Tok::Name(n)) = self.toks.get(self.pos + 1) {
                name.push('.');
                name.push_str(n);
                self.pos += 2;
            } else {
                break;
            }
        }
        name
    }

    fn module(&mut self) -> Result<(), String> {
        while let Some(t) = self.next() {
            match t {
                Tok::Newline | Tok::Punct(';') => {}
                Tok::Name(n) if n == "import" || n == "from" => {
                    while !matches!(self.next(), Some(Tok::Newline) | None) {}
                }
                Tok::Name(n) => {
                    let target = self.dotted_name(n);
                    if !self.eat('=') || target.contains('.') {
                        return Err(format!("a statement starting with {target}"));
                    }
                    let v = self.expr()?;
                    self.names.insert(target, v);
                }
                other => return Err(format!("a statement starting with {other:?}")),
            }
        }
        Ok(())
    }

    fn expr(&mut self) -> Result<Py, String> {
        let mut v = self.unary()?;
        while self.eat('+') {
            let rhs = self.unary()?;
            v = match (v, rhs) {
                (Py::Str(a), Py::Str(b)) => Py::Str(a + &b),
                (Py::Int(a), Py::Int(b)) => Py::Int(a + b),
                (Py::List(mut a), Py::List(b)) => {
                    a.extend(b);
                    Py::List(a)
                }
                _ => return Err("'+' between these values".into()),
            };
        }
        Ok(v)
    }

    fn unary(&mut self) -> Result<Py, String> {
        if self.eat('-') {
            return match self.unary()? {
                Py::Int(i) => Ok(Py::Int(-i)),
                Py::Float(f) => Ok(Py::Float(-f)),
                _ => Err("'-' before a non-number".into()),
            };
        }
        self.atom()
    }

    fn atom(&mut self) -> Result<Py, String> {
        match self.next() {
            Some(Tok::Str(s)) => {
                let mut s = s;
                while let Some(Tok::Str(more)) = self.peek().cloned() {
                    self.pos += 1;
                    s.push_str(&more);
                }
                Ok(Py::Str(s))
            }
            Some(Tok::Int(i)) => Ok(Py::Int(i)),
            Some(Tok::Float(f)) => Ok(Py::Float(f)),
            Some(Tok::Punct('{')) => {
                let mut items = Vec::new();
                while !self.eat('}') {
                    let k = self.expr()?;
                    self.expect(':')?;
                    let v = self.expr()?;
                    items.push((k, v));
                    if !self.eat(',') {
                        self.expect('}')?;
                        break;
                    }
                }
                Ok(Py::Dict(items))
            }
            Some(Tok::Punct(open @ ('[' | '('))) => {
                let close = if open == '[' { ']' } else { ')' };
                let mut items = Vec::new();
                let mut trailing_comma = false;
                while !self.eat(close) {
                    items.push(self.expr()?);
                    trailing_comma = self.eat(',');
                    if !trailing_comma {
                        self.expect(close)?;
                        break;
                    }
                }
                if open == '(' && items.len() == 1 && !trailing_comma {
                    return Ok(items.remove(0));
                }
                Ok(Py::List(items))
            }
            Some(Tok::Name(n)) => {
                let name = self.dotted_name(n);
                if name == "dict" && self.eat('(') {
                    let mut items = Vec::new();
                    while !self.eat(')') {
                        let Some(Tok::Name(k)) = self.next() else {
                            return Err("dict() with positional arguments".into());
                        };
                        self.expect('=')?;
                        items.push((Py::Str(k), self.expr()?));
                        if !self.eat(',') {
                            self.expect(')')?;
                            break;
                        }
                    }
                    return Ok(Py::Dict(items));
                }
                if self.peek() == Some(&Tok::Punct('(')) {
                    return Err(format!("a call to {name}()"));
                }
                if let Some(v) = self.names.get(&name) {
                    return Ok(v.clone());
                }
                constant(&name).ok_or_else(|| format!("the name {name}"))
            }
            other => Err(format!("unexpected {other:?}")),
        }
    }
}

/// The `LOGGING` value of a logging configuration file.
pub(crate) fn read_logging_dict(src: &str) -> Result<Py, String> {
    let toks = tokenize(src)?;
    let mut p = Parser {
        toks: &toks,
        pos: 0,
        names: HashMap::new(),
    };
    p.module()?;
    p.names
        .remove("LOGGING")
        .ok_or_else(|| "no LOGGING assignment".to_owned())
}

// ---------------------------------------------------------------------
// dictConfig
// ---------------------------------------------------------------------

/// Where a handler writes.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum HandlerKind {
    Stderr,
    Stdout,
    /// `FileHandler`, or `WatchedFileHandler` (`watched`), which reopens
    /// the file when it is moved or removed (log rotation).
    File {
        path: String,
        truncate: bool,
        watched: bool,
    },
    /// `SysLogHandler` to a Unix socket.
    SyslogUnix {
        path: String,
        facility: i64,
    },
    /// `SysLogHandler` to a UDP address.
    SyslogUdp {
        host: String,
        port: u16,
        facility: i64,
    },
    Null,
}

/// One configured handler.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct HandlerConfig {
    pub(crate) kind: HandlerKind,
    pub(crate) level: u8,
    pub(crate) format: String,
    pub(crate) datefmt: Option<String>,
}

/// One configured logger.
#[derive(Debug, Clone, PartialEq, Default)]
pub(crate) struct LoggerConfig {
    pub(crate) level: Option<u8>,
    pub(crate) handlers: Vec<usize>,
    pub(crate) propagate: bool,
}

/// What irrd-ng makes of a `LOGGING` dictionary.
#[derive(Debug, Clone, PartialEq, Default)]
pub(crate) struct LogConfig {
    pub(crate) handlers: Vec<HandlerConfig>,
    pub(crate) root: LoggerConfig,
    pub(crate) loggers: Vec<(String, LoggerConfig)>,
    /// What was left out, for the startup notice.
    pub(crate) notices: Vec<String>,
}

/// Python's default `Formatter` format.
const DEFAULT_FORMAT: &str = "%(message)s";

/// `logging._checkLevel`.
pub(crate) fn check_level(v: &Py) -> Result<u8, String> {
    match v {
        Py::Int(i) => {
            u8::try_from(*i).map_err(|_| format!("Level not an integer or a valid string: {i}"))
        }
        Py::Str(s) => match s.as_str() {
            "CRITICAL" | "FATAL" => Ok(50),
            "ERROR" => Ok(40),
            "WARNING" | "WARN" => Ok(30),
            "INFO" => Ok(20),
            "DEBUG" => Ok(10),
            "NOTSET" => Ok(0),
            _ => Err(format!("Unknown level: {}", config::str_repr(s))),
        },
        other => Err(format!(
            "Level not an integer or a valid string: {}",
            other.describe()
        )),
    }
}

/// `SysLogHandler.facility_names`.
pub(crate) fn facility(name: &str) -> Option<i64> {
    Some(match name {
        "kern" => 0,
        "user" => 1,
        "mail" => 2,
        "daemon" => 3,
        "auth" | "security" => 4,
        "syslog" => 5,
        "lpr" => 6,
        "news" => 7,
        "uucp" => 8,
        "cron" => 9,
        "authpriv" => 10,
        "ftp" => 11,
        "ntp" => 12,
        "audit" => 13,
        "console" => 14,
        "solaris-cron" => 15,
        "local0" => 16,
        "local1" => 17,
        "local2" => 18,
        "local3" => 19,
        "local4" => 20,
        "local5" => 21,
        "local6" => 22,
        "local7" => 23,
        _ => return None,
    })
}

/// Interpret a `LOGGING` dictionary as `dictConfig` would. `Err` is the
/// `ValueError` dictConfig raises, which stops v4 from starting.
pub(crate) fn interpret(d: &Py) -> Result<LogConfig, String> {
    let mut cfg = LogConfig::default();
    if !matches!(d, Py::Dict(_)) {
        return Err("dictionary doesn't specify a version".into());
    }
    match d.get("version") {
        Some(Py::Int(1)) => {}
        None => return Err("dictionary doesn't specify a version".into()),
        Some(v) => return Err(format!("Unsupported version: {}", v.describe())),
    }
    if d.get("incremental").is_some_and(Py::truthy) {
        cfg.notices
            .push("incremental configuration is not supported".into());
    }
    if d.get("disable_existing_loggers").is_none_or(Py::truthy) {
        cfg.notices
            .push("disable_existing_loggers is not reproduced: every logger stays enabled".into());
    }
    if d.get("filters").is_some_and(Py::truthy) {
        cfg.notices
            .push("filters are not supported and are ignored".into());
    }

    let mut formatters: HashMap<String, (String, Option<String>)> = HashMap::new();
    for (name, f) in d.get("formatters").map(Py::items).unwrap_or_default() {
        let name = name.as_str().unwrap_or_default().to_owned();
        if f.get("()").is_some()
            || f.get("class")
                .is_some_and(|c| c.as_str() != Some("logging.Formatter"))
        {
            cfg.notices.push(format!("formatter {name}: custom formatter classes are not supported, using the default format"));
            formatters.insert(name, (DEFAULT_FORMAT.into(), None));
            continue;
        }
        let style = f.get("style").and_then(Py::as_str).unwrap_or("%");
        let format = f
            .get("format")
            .or(f.get("fmt"))
            .and_then(Py::as_str)
            .unwrap_or(DEFAULT_FORMAT)
            .to_owned();
        let format = if style == "%" {
            format
        } else {
            cfg.notices.push(format!(
                "formatter {name}: style {} is not supported, using the default format",
                config::str_repr(style)
            ));
            DEFAULT_FORMAT.into()
        };
        let datefmt = f.get("datefmt").and_then(Py::as_str).map(str::to_owned);
        formatters.insert(name, (format, datefmt));
    }

    let mut handler_index: HashMap<String, usize> = HashMap::new();
    for (name, h) in d.get("handlers").map(Py::items).unwrap_or_default() {
        let name = name.as_str().unwrap_or_default().to_owned();
        let fail = |why: String| {
            format!(
                "Unable to configure handler {}: {why}",
                config::str_repr(&name)
            )
        };
        let level = match h.get("level") {
            Some(l) => check_level(l).map_err(fail)?,
            None => 0,
        };
        let (format, datefmt) = match h.get("formatter").and_then(Py::as_str) {
            Some(f) => formatters
                .get(f)
                .cloned()
                .ok_or_else(|| fail(format!("Unable to set formatter {}", config::str_repr(f))))?,
            None => (DEFAULT_FORMAT.into(), None),
        };
        if h.get("filters").is_some_and(Py::truthy) {
            cfg.notices.push(format!(
                "handler {name}: filters are not supported and are ignored"
            ));
        }
        let class = h.get("class").and_then(Py::as_str).unwrap_or_default();
        let kind = match class {
            "logging.StreamHandler" => match h.get("stream").and_then(Py::as_str) {
                Some("ext://sys.stdout") => HandlerKind::Stdout,
                None | Some("ext://sys.stderr") => HandlerKind::Stderr,
                Some(other) => {
                    cfg.notices.push(format!(
                        "handler {name}: stream {} is not supported, writing to stderr",
                        config::str_repr(other)
                    ));
                    HandlerKind::Stderr
                }
            },
            "logging.FileHandler"
            | "logging.handlers.WatchedFileHandler"
            | "logging.handlers.RotatingFileHandler"
            | "logging.handlers.TimedRotatingFileHandler" => {
                let path = h
                    .get("filename")
                    .and_then(Py::as_str)
                    .ok_or_else(|| fail("no filename".into()))?
                    .to_owned();
                if class.contains("Rotating") {
                    cfg.notices.push(format!(
                        "handler {name}: {class} does not rotate in irrd-ng; it writes like WatchedFileHandler, so rotate with an external tool"
                    ));
                }
                HandlerKind::File {
                    path,
                    truncate: h
                        .get("mode")
                        .and_then(Py::as_str)
                        .is_some_and(|m| m.starts_with('w')),
                    watched: class != "logging.FileHandler",
                }
            }
            "logging.handlers.SysLogHandler" => {
                let facility = match h.get("facility") {
                    None => 1,
                    Some(Py::Int(i)) => *i,
                    Some(Py::Str(s)) => {
                        match s.strip_prefix("ext://logging.handlers.SysLogHandler.LOG_") {
                            Some(f) => facility(&f.to_ascii_lowercase()),
                            None => facility(s),
                        }
                        .ok_or_else(|| fail(format!("unknown facility {}", config::str_repr(s))))?
                    }
                    Some(other) => {
                        return Err(fail(format!("unknown facility {}", other.describe())));
                    }
                };
                if h.get("socktype").is_some() {
                    cfg.notices.push(format!(
                        "handler {name}: socktype is not supported, using datagrams"
                    ));
                }
                match h.get("address") {
                    Some(Py::Str(path)) => HandlerKind::SyslogUnix {
                        path: path.clone(),
                        facility,
                    },
                    None => HandlerKind::SyslogUdp {
                        host: "localhost".into(),
                        port: 514,
                        facility,
                    },
                    Some(Py::List(a)) if a.len() == 2 => match (&a[0], &a[1]) {
                        (Py::Str(host), Py::Int(port)) => HandlerKind::SyslogUdp {
                            host: host.clone(),
                            port: u16::try_from(*port).map_err(|_| fail("bad port".into()))?,
                            facility,
                        },
                        _ => return Err(fail("bad address".into())),
                    },
                    Some(_) => return Err(fail("bad address".into())),
                }
            }
            "logging.NullHandler" => HandlerKind::Null,
            other => {
                cfg.notices.push(format!(
                    "handler {name}: class {} is not supported and is ignored",
                    config::str_repr(other)
                ));
                HandlerKind::Null
            }
        };
        handler_index.insert(name, cfg.handlers.len());
        cfg.handlers.push(HandlerConfig {
            kind,
            level,
            format,
            datefmt,
        });
    }

    let logger = |name: &str, l: &Py, notices: &mut Vec<String>| -> Result<LoggerConfig, String> {
        let fail = |why: String| {
            format!(
                "Unable to configure logger {}: {why}",
                config::str_repr(name)
            )
        };
        let mut out = LoggerConfig {
            level: l.get("level").map(check_level).transpose().map_err(fail)?,
            propagate: l.get("propagate").is_none_or(Py::truthy),
            handlers: Vec::new(),
        };
        if let Some(Py::List(hs)) = l.get("handlers") {
            for h in hs {
                let h = h.as_str().unwrap_or_default();
                let idx = handler_index.get(h).ok_or_else(|| {
                    fail(format!("Unable to add handler {}", config::str_repr(h)))
                })?;
                out.handlers.push(*idx);
            }
        }
        if l.get("filters").is_some_and(Py::truthy) {
            notices.push(format!(
                "logger {name}: filters are not supported and are ignored"
            ));
        }
        Ok(out)
    };
    let mut root = None;
    for (name, l) in d.get("loggers").map(Py::items).unwrap_or_default() {
        let name = name.as_str().unwrap_or_default();
        let lc = logger(name, l, &mut cfg.notices)?;
        if name.is_empty() {
            root = Some(lc);
        } else {
            cfg.loggers.push((name.to_owned(), lc));
        }
    }
    if let Some(r) = d.get("root") {
        root = Some(logger("root", r, &mut cfg.notices)?);
    }
    cfg.root = root.unwrap_or_default();
    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The second example from v4's `docs/admins/configuration.rst`.
    const V4_DOCS_EXAMPLE: &str = r#"
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '%(asctime)s irrd[%(process)d]: [%(name)s#%(levelname)s] %(message)s'
        },
    },
    'handlers': {
        'file-regular': {
            'class': 'logging.handlers.WatchedFileHandler',
            'filename': '/var/log/irrd.log',
            'formatter': 'verbose',
        },
        'file-mirroring': {
            'class': 'logging.handlers.WatchedFileHandler',
            'filename': '/var/log/irrd-mirroring.log',
            'formatter': 'verbose',
        },
    },
    'loggers': {
        'passlib.registry': {
            'level': 'INFO',
        },
        'irrd.mirroring': {
            'handlers': ['file-mirroring'],
            'level': 'DEBUG',
            'propagate': False,
        },
        '': {
            'handlers': ['file-regular'],
            'level': 'INFO',
        },
    }
}
"#;

    #[test]
    fn reads_v4s_documented_example() {
        let d = read_logging_dict(V4_DOCS_EXAMPLE).expect("read");
        let c = interpret(&d).expect("interpret");
        assert!(c.notices.is_empty(), "{:?}", c.notices);
        assert_eq!(c.handlers.len(), 2);
        assert_eq!(
            c.handlers[1].kind,
            HandlerKind::File {
                path: "/var/log/irrd-mirroring.log".into(),
                truncate: false,
                watched: true
            }
        );
        assert_eq!(
            c.handlers[0].format,
            "%(asctime)s irrd[%(process)d]: [%(name)s#%(levelname)s] %(message)s"
        );
        assert_eq!(c.root.handlers, vec![0]);
        assert_eq!(c.root.level, Some(20));
        let m = &c
            .loggers
            .iter()
            .find(|(n, _)| n == "irrd.mirroring")
            .expect("m")
            .1;
        assert_eq!(
            (m.level, m.propagate, m.handlers.clone()),
            (Some(10), false, vec![1])
        );
    }

    #[test]
    fn reads_common_python_shapes() {
        let src = r#"
import logging
from logging import handlers  # not needed

LOG_DIR = "/var/log/"
LEVEL = logging.WARNING
LOGGING = dict(
    version=1,
    disable_existing_loggers=False,
    formatters={"short": {"format": "%(levelname)s %(message)s", "datefmt": "%H:%M"}},
    handlers={
        "syslog": {
            "class": "logging.handlers.SysLogHandler",
            "address": "/dev/log",
            "facility": "local3",
            "formatter": "short",
            "level": LEVEL,
        },
        "udp": {"class": "logging.handlers.SysLogHandler", "address": ("192.0.2.1", 514),
                "facility": "ext://logging.handlers.SysLogHandler.LOG_DAEMON"},
        "file": {"class": "logging.FileHandler", "filename": LOG_DIR + 'irrd.log', "mode": "w"},
        "out": {"class": "logging.StreamHandler", "stream": "ext://sys.stdout"},
        "mail": {"class": "logging.handlers.SMTPHandler", "mailhost": "localhost"},
    },
    root={"handlers": ["syslog", "udp", "file", "out"], "level": "DEBUG"},
)
"#;
        let c = interpret(&read_logging_dict(src).expect("read")).expect("interpret");
        assert_eq!(
            c.handlers[0].kind,
            HandlerKind::SyslogUnix {
                path: "/dev/log".into(),
                facility: 19
            }
        );
        assert_eq!(c.handlers[0].level, 30);
        assert_eq!(c.handlers[0].datefmt.as_deref(), Some("%H:%M"));
        assert_eq!(
            c.handlers[1].kind,
            HandlerKind::SyslogUdp {
                host: "192.0.2.1".into(),
                port: 514,
                facility: 3
            }
        );
        assert_eq!(
            c.handlers[2].kind,
            HandlerKind::File {
                path: "/var/log/irrd.log".into(),
                truncate: true,
                watched: false
            }
        );
        assert_eq!(c.handlers[3].kind, HandlerKind::Stdout);
        assert_eq!(c.handlers[4].kind, HandlerKind::Null);
        assert_eq!(c.notices.len(), 1, "{:?}", c.notices);
        assert!(c.notices[0].contains("SMTPHandler"));
        assert_eq!(c.root.handlers, vec![0, 1, 2, 3]);
    }

    #[test]
    fn reports_what_dictconfig_would_refuse() {
        let read = |s: &str| interpret(&read_logging_dict(s).expect("read"));
        assert_eq!(
            read("LOGGING = {'version': 2}").expect_err("refused"),
            "Unsupported version: 2"
        );
        assert_eq!(
            read("LOGGING = {'version': 1, 'loggers': {'x': {'level': 'info'}}}")
                .expect_err("refused"),
            "Unable to configure logger 'x': Unknown level: 'info'"
        );
        assert_eq!(
            read("LOGGING = {'version': 1, 'root': {'handlers': ['nope']}}").expect_err("refused"),
            "Unable to configure logger 'root': Unable to add handler 'nope'"
        );
        assert!(read_logging_dict("import os\nLOGGING = {'a': os.getenv('X')}").is_err());
        assert!(read_logging_dict("X = 1").is_err());
    }
}
