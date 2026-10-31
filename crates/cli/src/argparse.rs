//! Just enough of Python's `argparse` to reproduce v4's command lines:
//! usage and help text (pre-rendered from v4, as argparse wraps them),
//! long options with one value (`--opt value`, `--opt=value`, unique
//! prefixes), `-h`/`--help`, positionals, `int` values, and argparse's
//! error messages and exit status 2.

use std::collections::HashMap;
use std::ffi::OsString;

/// One option taking a value.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Opt {
    /// `--name`
    pub(crate) flag: &'static str,
    /// The `dest`, used as the key in the result.
    pub(crate) dest: &'static str,
    /// `required=True`
    pub(crate) required: bool,
    /// `type=int`
    pub(crate) int: bool,
}

/// A parser definition.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Parser {
    pub(crate) prog: &'static str,
    /// argparse's usage block, ending in a newline.
    pub(crate) usage: &'static str,
    /// The full `-h` output.
    pub(crate) help: &'static str,
    pub(crate) options: &'static [Opt],
    /// Positional names, in order.
    pub(crate) positionals: &'static [&'static str],
}

/// What parsing produced.
#[derive(Debug)]
pub(crate) enum Parsed {
    Args(HashMap<&'static str, String>),
    /// Help was printed; exit 0.
    Help,
    /// An error was printed; exit 2.
    Error,
}

fn is_negative_number(s: &str) -> bool {
    // argparse's _negative_number_matcher: '^-\d+$|^-\d*\.\d+$'
    let rest = &s[1..];
    !rest.is_empty()
        && (rest.bytes().all(|b| b.is_ascii_digit())
            || rest.split_once('.').is_some_and(|(a, b)| {
                a.bytes().all(|c| c.is_ascii_digit())
                    && !b.is_empty()
                    && b.bytes().all(|c| c.is_ascii_digit())
            }))
}

fn looks_like_option(s: &str) -> bool {
    s.starts_with('-') && s != "-" && !is_negative_number(s)
}

/// Python's `int(str)` for ASCII input.
pub(crate) fn py_int(s: &str) -> Option<i64> {
    let t = s.trim_matches(|c: char| c.is_whitespace());
    let (neg, digits) = match t.as_bytes().first() {
        Some(b'-') => (true, &t[1..]),
        Some(b'+') => (false, &t[1..]),
        _ => (false, t),
    };
    if digits.is_empty()
        || digits.starts_with('_')
        || digits.ends_with('_')
        || digits.contains("__")
        || !digits.bytes().all(|b| b.is_ascii_digit() || b == b'_')
    {
        return None;
    }
    let v: i64 = digits.replace('_', "").parse().ok()?;
    Some(if neg { -v } else { v })
}

impl Parser {
    fn error(&self, msg: &str) -> Parsed {
        eprint!("{}", self.usage);
        eprintln!("{}: error: {msg}", self.prog);
        Parsed::Error
    }

    pub(crate) fn parse(&self, args: &[OsString]) -> Parsed {
        let args: Vec<String> = args
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        let mut values: HashMap<&'static str, String> = HashMap::new();
        let mut positionals: Vec<String> = Vec::new();
        let mut extras: Vec<String> = Vec::new();
        let mut i = 0;
        let mut only_positional = false;
        while i < args.len() {
            let a = &args[i];
            i += 1;
            if only_positional || !looks_like_option(a) {
                positionals.push(a.clone());
                continue;
            }
            if a == "--" {
                only_positional = true;
                continue;
            }
            let (name, inline) = match a.split_once('=') {
                Some((n, v)) if a.starts_with("--") => (n.to_owned(), Some(v.to_owned())),
                _ => (a.clone(), None),
            };
            let opt = if name == "-h" || name == "--help" {
                print!("{}", self.help);
                return Parsed::Help;
            } else if let Some(o) = self.options.iter().find(|o| o.flag == name) {
                *o
            } else if name.starts_with("--") {
                let mut names: Vec<&str> = Vec::new();
                if "--help".starts_with(name.as_str()) {
                    names.push("--help");
                }
                names.extend(
                    self.options
                        .iter()
                        .filter(|o| o.flag.starts_with(name.as_str()))
                        .map(|o| o.flag),
                );
                match names.as_slice() {
                    [] => {
                        extras.push(a.clone());
                        continue;
                    }
                    ["--help"] => {
                        print!("{}", self.help);
                        return Parsed::Help;
                    }
                    [one] => match self.options.iter().find(|o| o.flag == *one) {
                        Some(o) => *o,
                        None => unreachable!(),
                    },
                    _ => {
                        return self.error(&format!(
                            "ambiguous option: {name} could match {}",
                            names.join(", ")
                        ));
                    }
                }
            } else {
                extras.push(a.clone());
                continue;
            };
            let value = match inline {
                Some(v) => v,
                None => {
                    if i < args.len() && !looks_like_option(&args[i]) {
                        i += 1;
                        args[i - 1].clone()
                    } else {
                        return self.error(&format!(
                            "argument {}: expected one argument",
                            self.display(&opt)
                        ));
                    }
                }
            };
            if opt.int && py_int(&value).is_none() {
                return self.error(&format!(
                    "argument {}: invalid int value: {}",
                    self.display(&opt),
                    config::str_repr(&value)
                ));
            }
            values.insert(opt.dest, value);
        }
        // Positionals are consumed in order; extras are unrecognised.
        let mut pos_iter = positionals.into_iter();
        for name in self.positionals {
            if let Some(v) = pos_iter.next() {
                values.insert(name, v);
            }
        }
        let leftover: Vec<String> = pos_iter.collect();
        let mut missing: Vec<&str> = Vec::new();
        for o in self.options {
            if o.required && !values.contains_key(o.dest) {
                missing.push(o.flag);
            }
        }
        for p in self.positionals {
            if !values.contains_key(p) {
                missing.push(p);
            }
        }
        if !missing.is_empty() {
            return self.error(&format!(
                "the following arguments are required: {}",
                missing.join(", ")
            ));
        }
        let mut unrecognised = extras;
        unrecognised.extend(leftover);
        if !unrecognised.is_empty() {
            return self.error(&format!(
                "unrecognized arguments: {}",
                unrecognised.join(" ")
            ));
        }
        Parsed::Args(values)
    }

    fn display(&self, o: &Opt) -> String {
        o.flag.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn python_int() {
        assert_eq!(py_int(" 5 "), Some(5));
        assert_eq!(py_int("+5"), Some(5));
        assert_eq!(py_int("-5"), Some(-5));
        assert_eq!(py_int("1_000"), Some(1000));
        assert_eq!(py_int("x"), None);
        assert_eq!(py_int("1__0"), None);
        assert_eq!(py_int(""), None);
    }
}
