//! `irr_rpsl_submit` (`irrd/scripts/irr_rpsl_submit.py`): read RPSL from
//! stdin, submit it to an IRRd's `/v1/submit/` and report the result.
//!
//! A client: it never opens the store or reads `irrd.yaml`. Arguments,
//! messages, output formats and exit codes are v4's, including its quirks
//! (the literal `{error.message}` after argument errors, `""[` in the text
//! report).

use std::ffi::OsString;
use std::io::Read as _;
use std::process::ExitCode;
use std::time::Duration;

use auth::json::PyJson;

const USAGE: &str = "usage: irr_rpsl_submit [-d] [--help] [-m METADATA] (-h HOST | -u URL)\n                       [-c CRYPT_PASSWD] [-D] [-E DB_ADMIN_EMAIL] [-f PATH]\n                       [-F FOOTER] [-l DIR] [-M] [-N] [-O STR] [-p PORT]\n                       [-r PGP_DIR] [-R] [-s SOURCE] [-x] [-j | -t]\n";

const HELP: &str = "\nRead RPSL submissions from stdin and return a response on stdout. Errors or\ndebug info are printed to stderr. This program accepts the arguments for\nirrdv3's version of irr_rpsl_submit but ignores most of them.\n\nYou can also set three environment variables:\n\n    IRR_RPSL_SUBMIT_DEBUG - turn on debugging\n    IRR_RPSL_SUBMIT_URL   - used if both -u and -h are unspecified\n    IRR_RPSL_SUBMIT_HOST  - used if both -u and -h are unspecified\n                            and IRR_RPSL_SUBMIT_URL is not set\n\nThe input format must be plain RPSL objects, separated by double newlines, as\nused in emails documented on\nhttps://irrd.readthedocs.io/en/stable/users/database-changes/#submitting-over-\ne-mail .\n\nThe exit code is tells you what happened:\n\n     0 - complete success\n     1 - at least one change was rejected\n     2 - usage error\n     4 - input error\n     8 - network error\n    16 - unexpected response\n    32 - an unidentified error\n\noptions:\n  -d, -v             set logging level to DEBUG (also set by\n                     IRR_RPSL_SUBMIT_DEBUG)\n  --help             show this help message and exit\n  -m METADATA        metadata sent in X-irrd-metadata header, in key=value\n                     format, separated by comma\n  -h HOST            IRRd host\n  -u URL             IRRd submission API URL, e.g.\n                     https://rr.example.net/v1/submit/ (also set by\n                     IRR_RPSL_SUBMIT_URL)\n  -j                 output JSON summary of operation (default)\n  -t                 output a text summary of operation (default off)\n\nirrdv3 compatibility:\n  these arguments are ignored and exist only to accept legacy calls\n\n  -c CRYPT_PASSWD    (IRRdv3 no-op) <crypted password> (default 'foo')\n  -D                 (IRRdv3 no-op) Inetd mode, read/write to STDIN/STDOUT\n  -E DB_ADMIN_EMAIL  (IRRdv3 no-op) DB admin address for new maintainer\n                     requests\n  -f PATH            (IRRdv3 no-op) IRRd config file location\n  -F FOOTER          (IRRdv3 no-op) \" enclosed response footer string\n  -l DIR             (IRRdv3 no-op) log directory\n  -M                 (IRRdv3 no-op) allow MAIL-FROM auth\n  -N                 (IRRdv3 no-op) permit inetnum/domain objects\n  -O STR             (IRRdv3 no-op) \" enclosed host/IP web origin string\n  -p PORT            IRRd port\n  -r PGP_DIR         (IRRdv3 no-op) pgp directory\n  -R                 (IRRdv3 no-op) RPS Dist mode\n  -s SOURCE          (IRRdv3 no-op) <DB source> source is authoritative\n  -x                 (IRRdv3 no-op) do not send notifications\n";

/// Short options taking a value.
const VALUE_OPTS: &[char] = &['m', 'h', 'u', 'c', 'E', 'f', 'F', 'l', 'O', 'p', 'r', 's'];
/// Short flags.
const FLAG_OPTS: &[char] = &['d', 'v', 'D', 'M', 'N', 'R', 'x', 'j', 't'];

fn metavar(c: char) -> &'static str {
    match c {
        'm' => "METADATA",
        'h' => "HOST",
        'u' => "URL",
        _ => "",
    }
}

#[derive(Debug, Default)]
struct Args {
    metadata: Option<Vec<(String, String)>>,
    host: Option<String>,
    url: Option<String>,
    port: Option<String>,
    json: bool,
    text: bool,
}

enum Failure {
    /// An `XBasic`: message to stderr, exit code.
    X(String, u8),
    /// argparse already printed; `XArgumentError`.
    Argparse,
    /// `--help`
    Help,
}

const EXIT_REJECTED: u8 = 1;
const EXIT_ARGUMENTS: u8 = 2;
const EXIT_INPUT: u8 = 4;
const EXIT_NETWORK: u8 = 8;
const EXIT_RESPONSE: u8 = 16;
const EXIT_GENERAL: u8 = 32;

/// `metadata(value)`: `key=value` pairs separated by commas.
fn parse_metadata(v: &str) -> Option<Vec<(String, String)>> {
    let mut out: Vec<(String, String)> = Vec::new();
    for item in v.split(',') {
        let (k, val) = item.split_once('=')?;
        let k = k.to_owned();
        match out.iter_mut().find(|(ek, _)| *ek == k) {
            Some(e) => e.1 = val.to_owned(),
            None => out.push((k, val.to_owned())),
        }
    }
    Some(out)
}

fn parse_args(mut options: Vec<String>) -> Result<Args, Failure> {
    // preprocess_args
    let has_u_or_h = options.iter().any(|o| o == "-u" || o == "-h");
    let env = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
    if let (Some(u), false) = (env("IRR_RPSL_SUBMIT_URL"), has_u_or_h) {
        options.extend(["-u".to_owned(), u]);
    } else if let (Some(h), false) = (env("IRR_RPSL_SUBMIT_HOST"), has_u_or_h) {
        options.extend(["-h".to_owned(), h]);
    }
    if env("IRR_RPSL_SUBMIT_DEBUG").is_some() && !options.iter().any(|o| o == "-d") {
        options.push("-d".to_owned());
    }

    let error = |msg: String| -> Failure {
        eprintln!("{USAGE}irr_rpsl_submit: error: {msg}");
        Failure::Argparse
    };
    if options.iter().any(|o| o == "--help") {
        print!("{USAGE}{HELP}");
        return Err(Failure::Help);
    }
    let mut a = Args::default();
    let mut unrecognized: Vec<String> = Vec::new();
    let mut seen_group: Option<char> = None;
    let mut seen_output: Option<char> = None;
    let mut i = 0;
    while i < options.len() {
        let o = &options[i];
        i += 1;
        let Some(rest) = o
            .strip_prefix('-')
            .filter(|r| !r.is_empty() && !r.starts_with('-'))
        else {
            unrecognized.push(o.clone());
            continue;
        };
        let mut chars = rest.chars();
        while let Some(c) = chars.next() {
            if VALUE_OPTS.contains(&c) {
                let attached: String = chars.by_ref().collect();
                let value = if !attached.is_empty() {
                    attached
                } else if i < options.len() && !options[i].starts_with('-') {
                    i += 1;
                    options[i - 1].clone()
                } else {
                    return Err(error(format!("argument -{c}: expected one argument")));
                };
                match c {
                    'm' => match parse_metadata(&value) {
                        Some(m) => a.metadata = Some(m),
                        None => {
                            return Err(error(format!(
                                "argument -m: invalid metadata value: {}",
                                auth::json::py_str_repr(&value)
                            )));
                        }
                    },
                    'h' | 'u' => {
                        if let Some(prev) = seen_group.filter(|p| *p != c) {
                            return Err(error(format!(
                                "argument -{c}: not allowed with argument -{prev}"
                            )));
                        }
                        seen_group = Some(c);
                        if c == 'h' {
                            a.host = Some(value);
                        } else {
                            a.url = Some(value);
                        }
                    }
                    'p' => a.port = Some(value),
                    _ => {}
                }
                let _ = metavar(c);
                break;
            } else if FLAG_OPTS.contains(&c) {
                if matches!(c, 'j' | 't') {
                    if let Some(prev) = seen_output.filter(|p| *p != c) {
                        return Err(error(format!(
                            "argument -{c}: not allowed with argument -{prev}"
                        )));
                    }
                    seen_output = Some(c);
                    if c == 'j' {
                        a.json = true;
                    } else {
                        a.text = true;
                    }
                }
            } else {
                unrecognized.push(o.clone());
                break;
            }
        }
    }
    if seen_group.is_none() {
        return Err(error("one of the arguments -h -u is required".to_owned()));
    }
    if !unrecognized.is_empty() {
        return Err(error(format!(
            "unrecognized arguments: {}",
            unrecognized.join(" ")
        )));
    }
    // choose_url
    if let Some(host) = &a.host {
        let mut hostport = host.clone();
        if let Some(port) = &a.port {
            if let Some(idx) = hostport.find(':') {
                hostport.truncate(idx);
            }
            hostport.push(':');
            hostport.push_str(port);
        }
        a.url = Some(format!("http://{hostport}/v1/submit/"));
    }
    Ok(a)
}

/// `create_request_body(rpsl)`: the JSON body and whether it is a delete.
fn create_request_body(rpsl: &str) -> Result<(String, bool, usize, Vec<String>), Failure> {
    let mut passwords: Vec<String> = Vec::new();
    let mut override_: Option<String> = None;
    let mut texts: Vec<String> = Vec::new();
    let mut delete_reason = String::new();
    let mut delete_count = 0;
    let rpsl = rpsl.replace('\r', "");
    for object_text in rpsl.split("\n\n") {
        let object_text = rpsl::python::strip(object_text);
        if object_text.is_empty() {
            continue;
        }
        if object_text.split('\n').any(|l| l.starts_with("delete:")) {
            delete_count += 1;
        }
        let mut rpsl_text = String::new();
        for line in object_text.trim_matches('\n').split('\n') {
            let value =
                || rpsl::python::strip(line.split_once(':').map_or("", |(_, v)| v)).to_owned();
            if line.starts_with("password:") {
                passwords.push(value());
            } else if line.starts_with("override:") {
                let v = value();
                if override_.as_ref().is_some_and(|o| *o != v) {
                    return Err(Failure::X(
                        "override encountered twice with different values".to_owned(),
                        EXIT_INPUT,
                    ));
                }
                override_ = Some(v);
            } else if line.starts_with("delete:") {
                delete_reason = value();
            } else {
                rpsl_text.push_str(line);
                rpsl_text.push('\n');
            }
        }
        if !rpsl_text.is_empty() {
            texts.push(rpsl_text);
        }
    }
    if delete_count > 0 && delete_count != texts.len() {
        return Err(Failure::X(
            "At least one object in the delete query did not have a delete: line".to_owned(),
            EXIT_INPUT,
        ));
    }
    // json.dumps(request_body): ensure_ascii, ", " and ": ".
    let objects: Vec<String> = texts
        .iter()
        .map(|t| format!("{{\"object_text\": {}}}", py_json_ascii(t)))
        .collect();
    let body = format!(
        "{{\"objects\": [{}], \"passwords\": [{}], \"override\": {}, \"delete_reason\": {}}}",
        objects.join(", "),
        passwords
            .iter()
            .map(|p| py_json_ascii(p))
            .collect::<Vec<_>>()
            .join(", "),
        override_
            .as_deref()
            .map_or("null".to_owned(), py_json_ascii),
        py_json_ascii(&delete_reason)
    );
    Ok((body, !delete_reason.is_empty(), texts.len(), passwords))
}

/// A JSON string as `json.dumps` writes it by default (`ensure_ascii`).
fn py_json_ascii(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 || (c as u32) > 0x7e => {
                let mut buf = [0u16; 2];
                for u in c.encode_utf16(&mut buf) {
                    out.push_str(&format!("\\u{u:04x}"));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// `json.dumps(value)` with Python's defaults.
fn py_dumps(v: &PyJson) -> String {
    match v {
        PyJson::Null => "null".to_owned(),
        PyJson::Bool(b) => if *b { "true" } else { "false" }.to_owned(),
        PyJson::Number(n) => n.to_string(),
        PyJson::Str(s) => py_json_ascii(s),
        PyJson::List(l) => format!(
            "[{}]",
            l.iter().map(py_dumps).collect::<Vec<_>>().join(", ")
        ),
        PyJson::Dict(d) => format!(
            "{{{}}}",
            d.iter()
                .map(|(k, v)| format!("{}: {}", py_json_ascii(k), py_dumps(v)))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

fn get<'a>(v: &'a PyJson, k: &str) -> Option<&'a PyJson> {
    match v {
        PyJson::Dict(d) => d.iter().find(|(key, _)| key == k).map(|(_, v)| v),
        _ => None,
    }
}

fn int3(v: Option<&PyJson>) -> String {
    match v {
        Some(PyJson::Number(n)) => format!("{:>3}", n.to_string()),
        Some(other) => other.py_str(),
        None => String::new(),
    }
}

/// `format_as_text(response)`
fn format_as_text(r: &PyJson) -> Result<String, String> {
    let s = get(r, "summary").ok_or_else(|| "KeyError • 'summary'".to_owned())?;
    let mut out = format!(
        "\nSUMMARY OF UPDATE:\n\nNumber of objects found:                  {}\nNumber of objects processed successfully: {}\n    Create:      {}\n    Modify:      {}\n    Delete:      {}\nNumber of objects processed with errors:  {}\n    Create:      {}\n    Modify:      {}\n    Delete:      {}\n\nDETAILED EXPLANATION:\n\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n",
        int3(get(s, "objects_found")),
        int3(get(s, "successful")),
        int3(get(s, "successful_create")),
        int3(get(s, "successful_modify")),
        int3(get(s, "successful_delete")),
        int3(get(s, "failed")),
        int3(get(s, "failed_create")),
        int3(get(s, "failed_modify")),
        int3(get(s, "failed_delete")),
    );
    if let Some(PyJson::List(objects)) = get(r, "objects") {
        for o in objects {
            out.push_str("---\n");
            let str_of = |k: &str| get(o, k).map(PyJson::py_str).unwrap_or_default();
            let ok = get(o, "successful").is_some_and(PyJson::truthy);
            out.push_str(&format!(
                "{} {}: \"\"[{}] {}\n",
                str_of("type"),
                if ok { "succeeded" } else { "FAILED" },
                str_of("object_class"),
                str_of("rpsl_pk")
            ));
            let list = |k: &str| match get(o, k) {
                Some(PyJson::List(l)) => l.iter().map(PyJson::py_str).collect::<Vec<_>>(),
                _ => Vec::new(),
            };
            let (errors, infos) = (list("error_messages"), list("info_messages"));
            if !errors.is_empty() || !infos.is_empty() {
                if !errors.is_empty() {
                    out.push('\n');
                    out.push_str(&str_of("submitted_object_text"));
                    out.push('\n');
                }
                for e in &errors {
                    out.push_str(&format!("ERROR: {e}\n"));
                }
                for i in &infos {
                    out.push_str(&format!("INFO: {i}\n"));
                }
            }
            out.push('\n');
        }
    }
    out.push_str("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
    Ok(out)
}

/// The reason text urllib's `HTTPError` carries for a status.
fn http_reason(status: u16) -> String {
    reqwest::StatusCode::from_u16(status)
        .ok()
        .and_then(|s| s.canonical_reason())
        .unwrap_or("")
        .to_owned()
}

fn send(
    url: &str,
    body: String,
    delete: bool,
    metadata: Option<&[(String, String)]>,
) -> Result<PyJson, Failure> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| Failure::X(format!("Some other error: OSError • {e}"), EXIT_GENERAL))?;
    rt.block_on(async {
        let parsed = reqwest::Url::parse(url).map_err(|_| {
            Failure::X(
                format!(
                    "Some other error: ValueError • unknown url type: {}",
                    auth::json::py_str_repr(url)
                ),
                EXIT_GENERAL,
            )
        })?;
        let client = nrtm::mirror::net::http_client_builder(Duration::from_secs(20))
            .and_then(|b| {
                b.redirect(reqwest::redirect::Policy::none())
                    .build()
                    .map_err(|e| nrtm::mirror::pyerr::PyErr::Other(e.to_string()))
            })
            .map_err(|e| Failure::X(format!("Some other error: OSError • {e:?}"), EXIT_GENERAL))?;
        let mut req = client
            .request(
                if delete {
                    reqwest::Method::DELETE
                } else {
                    reqwest::Method::POST
                },
                parsed.clone(),
            )
            .header("User-Agent", "irr_rpsl_submit_v4")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(body);
        if let Some(m) = metadata {
            let dict = PyJson::Dict(
                m.iter()
                    .map(|(k, v)| (k.clone(), PyJson::Str(v.clone())))
                    .collect(),
            );
            req = req.header("X-irrd-metadata", py_dumps(&dict));
        }
        let resp = match req.send().await {
            Ok(r) => r,
            Err(e) => {
                let mut cause = e.to_string();
                let mut src: Option<&dyn std::error::Error> = std::error::Error::source(&e);
                while let Some(s) = src {
                    cause = s.to_string();
                    src = s.source();
                }
                if e.is_connect() && (cause.contains("refused") || cause.contains("timed out")) {
                    return Err(Failure::X(
                        format!("Connection refused: {url}"),
                        EXIT_NETWORK,
                    ));
                }
                if cause.contains("dns") || cause.contains("resolve") || cause.contains("lookup") {
                    return Err(Failure::X(
                        format!("Could not resolve host: {url}"),
                        EXIT_NETWORK,
                    ));
                }
                return Err(Failure::X(
                    format!("Network error: {url} = {cause}"),
                    EXIT_NETWORK,
                ));
            }
        };
        let status = resp.status().as_u16();
        if status >= 300 {
            return Err(Failure::X(
                format!("Network error: {url} = {}", http_reason(status)),
                EXIT_NETWORK,
            ));
        }
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| Failure::X(format!("Network error: {url} = {e}"), EXIT_NETWORK))?;
        match auth::api::json_loads(&bytes) {
            Ok(v) => Ok(v),
            Err(auth::api::BodyError::BadRequest(m)) => Err(Failure::X(
                format!("Response error: HTTP response error decoding JSON: {m}"),
                EXIT_RESPONSE,
            )),
            Err(auth::api::BodyError::Internal(m)) => Err(Failure::X(
                format!("Some other error: UnicodeDecodeError • {m}"),
                EXIT_GENERAL,
            )),
        }
    })
}

/// `irr_rpsl_submit`
pub(crate) fn run(args: &[OsString]) -> ExitCode {
    let options: Vec<String> = args
        .iter()
        .skip(1)
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    let a = match parse_args(options) {
        Ok(a) => a,
        Err(Failure::Help) => return ExitCode::SUCCESS,
        Err(Failure::Argparse) => {
            eprintln!("Error processing command-line arguments: {{error.message}}");
            return ExitCode::from(EXIT_ARGUMENTS);
        }
        Err(Failure::X(m, c)) => {
            eprintln!("{m}");
            return ExitCode::from(c);
        }
    };
    let result = (|| -> Result<PyJson, Failure> {
        let mut raw = Vec::new();
        let _ = std::io::stdin().read_to_end(&mut raw);
        let input = auth::email_parser::decode_input(&raw);
        let rpsl = rpsl::python::strip(&input).to_owned();
        if rpsl.is_empty() {
            return Err(Failure::X(
                "Empty input! Specify at least on RPSL object.".to_owned(),
                EXIT_INPUT,
            ));
        }
        let (body, delete, count, passwords) = create_request_body(&rpsl)?;
        if count == 0 {
            return Err(Failure::X(
                "No RPSL objects were found after processing input.".to_owned(),
                EXIT_INPUT,
            ));
        }
        if !passwords.is_empty() {
            // v4 4.5.4 filters passwords out of its debug log with
            // bytes.replace(str, bytes), which raises before any request
            // is made whenever the input has a password: line.
            return Err(Failure::X(
                "Some other error: TypeError • a bytes-like object is required, not 'str'"
                    .to_owned(),
                EXIT_GENERAL,
            ));
        }
        let url = a.url.clone().unwrap_or_default();
        send(&url, body, delete, a.metadata.as_deref())
    })();
    let response = match result {
        Ok(r) => r,
        Err(Failure::X(m, c)) => {
            eprintln!("{m}");
            return ExitCode::from(c);
        }
        Err(_) => return ExitCode::from(EXIT_GENERAL),
    };
    let output = if a.json {
        Ok(py_dumps(&response))
    } else {
        format_as_text(&response)
    };
    match output {
        Ok(o) => println!("{o}"),
        Err(m) => {
            eprintln!("Some other error: {m}");
            return ExitCode::from(EXIT_GENERAL);
        }
    }
    let failed = get(&response, "summary")
        .and_then(|s| get(s, "failed"))
        .and_then(|f| match f {
            PyJson::Number(n) => n.as_f64(),
            _ => None,
        })
        .unwrap_or(0.0);
    if failed > 0.0 {
        ExitCode::from(EXIT_REJECTED)
    } else {
        ExitCode::SUCCESS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_body_like_v4() {
        let Ok((body, delete, n, pw)) = create_request_body(
            "person: A\ndelete: first\noverride: o\n\nroute: x\ndelete: gone\n",
        ) else {
            panic!("body");
        };
        assert!(delete);
        assert_eq!(n, 2);
        assert!(pw.is_empty());
        assert_eq!(
            body,
            "{\"objects\": [{\"object_text\": \"person: A\\n\"}, {\"object_text\": \"route: x\\n\"}], \"passwords\": [], \"override\": \"o\", \"delete_reason\": \"gone\"}"
        );
    }

    #[test]
    fn json_escapes_like_python() {
        assert_eq!(
            py_json_ascii("é\u{1F308}\""),
            "\"\\u00e9\\ud83c\\udf08\\\"\""
        );
    }

    #[test]
    fn text_report_pads_counts() {
        let r = auth::api::json_loads(br#"{"summary":{"objects_found":1,"successful":1,"successful_create":0,"successful_modify":1,"successful_delete":0,"failed":0,"failed_create":0,"failed_modify":0,"failed_delete":0},"objects":[]}"#)
            .unwrap_or(PyJson::Null);
        let t = format_as_text(&r).unwrap_or_default();
        assert!(t.contains("Number of objects found:                    1\nNumber"));
        assert!(t.contains("    Modify:        1\n"));
    }

    #[test]
    fn metadata_pairs() {
        assert_eq!(
            parse_metadata("a=b,c=d=e"),
            Some(vec![("a".into(), "b".into()), ("c".into(), "d=e".into())])
        );
        assert_eq!(parse_metadata("bad"), None);
    }
}
