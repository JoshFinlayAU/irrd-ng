//! `irrd_mirror_force_reload` (`irrd/scripts/mirror_force_reload.py`) and
//! `irrdctl` (`irrd/scripts/irrd_control.py`, a click application).

use std::ffi::OsString;
use std::process::ExitCode;

use config::Configuration;
use store::{Store, StoreOptions};

use crate::argparse::{Opt, Parsed, Parser};
use crate::{logging, messages, settings};

const FORCE_RELOAD: Parser = Parser {
    prog: "irrd_mirror_force_reload",
    usage: "usage: irrd_mirror_force_reload [-h] [--config CONFIG_FILE_PATH] source\n",
    help: "usage: irrd_mirror_force_reload [-h] [--config CONFIG_FILE_PATH] source\n\nForce a full reload for a mirror.\n\npositional arguments:\n  source                the name of the source to reload\n\noptions:\n  -h, --help            show this help message and exit\n  --config CONFIG_FILE_PATH\n                        use a different IRRd config file (default:\n                        /etc/irrd.yaml)\n",
    options: &[Opt {
        flag: "--config",
        dest: "config_file_path",
        required: false,
        int: false,
        store_true: false,
    }],
    positionals: &["source"],
};

/// v4's logger for the control tool.
const CTL_LOG_TARGET: &str = "irrd.scripts.irrd_control";

pub(crate) fn open_store(cfg: &Configuration) -> Result<Store, ExitCode> {
    Store::open(
        &StoreOptions::new(settings::store_path()),
        settings::store_settings(cfg),
    )
    .map_err(|e| {
        eprintln!("{e}");
        ExitCode::from(1)
    })
}

/// `irrd_mirror_force_reload`
pub(crate) fn force_reload(args: &[OsString]) -> ExitCode {
    let a = match FORCE_RELOAD.parse(args.get(1..).unwrap_or_default()) {
        Parsed::Args(a) => a,
        Parsed::Help => return ExitCode::SUCCESS,
        Parsed::Error => return ExitCode::from(2),
    };
    let cfg = match Configuration::load(a.get("config_file_path").map(String::as_str)) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{}", messages::configuration_error(&e.to_string()));
            return ExitCode::from(1);
        }
    };
    logging::init(&cfg);
    if settings::truthy(&cfg, "readonly_standby") {
        println!("{}", messages::READONLY_STANDBY);
        return ExitCode::from(255);
    }
    let source = a.get("source").cloned().unwrap_or_default();
    let k = |key: &str| format!("sources.{source}.{key}");
    if !(settings::truthy(&cfg, &k("nrtm4_client_notification_file_url"))
        || settings::truthy(&cfg, &k("nrtm_host"))
        || settings::truthy(&cfg, &k("import_source")))
    {
        println!("{}", messages::force_reload_not_mirror(&source));
        return ExitCode::SUCCESS;
    }
    if settings::truthy(&cfg, &k("nrtm4_client_initial_public_key")) {
        println!("{}", messages::force_reload_nrtm4_note(&source));
    }
    let store = match open_store(&cfg) {
        Ok(s) => s,
        Err(c) => return c,
    };
    match store.write(move |tx| tx.set_force_reload(&source)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::from(1)
        }
    }
}

// ---------------------------------------------------------------------
// irrdctl: click's parsing, help and errors for v4's command tree.
// ---------------------------------------------------------------------

/// A click command or group.
struct Command {
    /// The path, e.g. `irrdctl nrtm4`.
    path: &'static str,
    /// `[OPTIONS] COMMAND [ARGS]...` or `[OPTIONS] SOURCE`.
    usage_tail: &'static str,
    /// `--help` output.
    help: &'static str,
    /// Subcommands, for a group.
    subcommands: &'static [&'static str],
    /// Positional argument names, for a command.
    arguments: &'static [&'static str],
    /// Boolean flags the command accepts besides `--help`.
    flags: &'static [&'static str],
}

const TOP: Command = Command {
    path: "irrdctl",
    usage_tail: "[OPTIONS] COMMAND [ARGS]...",
    help: "Usage: irrdctl [OPTIONS] COMMAND [ARGS]...\n\nOptions:\n  --config FILE  use a different IRRd config file  [default: /etc/irrd.yaml]\n  --help         Show this message and exit.\n\nCommands:\n  nrtm4                 Manage NRTMv4 status.\n  user-change-override  Change the override permission for user EMAIL.\n  user-mfa-clear        Remove two-factor authentication for user EMAIL.\n",
    subcommands: &["nrtm4", "user-change-override", "user-mfa-clear"],
    arguments: &[],
    flags: &[],
};

const NRTM4: Command = Command {
    path: "irrdctl nrtm4",
    usage_tail: "[OPTIONS] COMMAND [ARGS]...",
    help: "Usage: irrdctl nrtm4 [OPTIONS] COMMAND [ARGS]...\n\n  Manage NRTMv4 status.\n\nOptions:\n  --help  Show this message and exit.\n\nCommands:\n  client-clear-known-keys  Remove the known keys from the database for...\n  generate-private-key     Generate a new private key for an NRTMv4 server.\n  server-show-public-key   Show the public key(s) matching the currently...\n",
    subcommands: &[
        "client-clear-known-keys",
        "generate-private-key",
        "server-show-public-key",
    ],
    arguments: &[],
    flags: &[],
};

const CLIENT_CLEAR_KNOWN_KEYS: Command = Command {
    path: "irrdctl nrtm4 client-clear-known-keys",
    usage_tail: "[OPTIONS] SOURCE",
    help: "Usage: irrdctl nrtm4 client-clear-known-keys [OPTIONS] SOURCE\n\n  Remove the known keys from the database for SOURCE.\n\n  IRRD stores these known keys in the DB as part of NRTMv4 key rotation, to\n  reflect the key currently used for signature validation. Explicit clearing\n  is required when missing a key rotation window or switching to a different\n  NRTMv4 server for the same source.\n\n  After clearing, NRTMv4 client signature validation will revert to the key in\n  sources.{source}.nrtm4_client_initial_public_key for the next NRTMv4 update,\n  and again store the current key after the first successful update.\n\nOptions:\n  --help  Show this message and exit.\n",
    subcommands: &[],
    arguments: &["SOURCE"],
    flags: &[],
};

const GENERATE_PRIVATE_KEY: Command = Command {
    path: "irrdctl nrtm4 generate-private-key",
    usage_tail: "[OPTIONS]",
    help: "Usage: irrdctl nrtm4 generate-private-key [OPTIONS]\n\n  Generate a new private key for an NRTMv4 server.\n\nOptions:\n  --help  Show this message and exit.\n",
    subcommands: &[],
    arguments: &[],
    flags: &[],
};

const SERVER_SHOW_PUBLIC_KEY: Command = Command {
    path: "irrdctl nrtm4 server-show-public-key",
    usage_tail: "[OPTIONS] SOURCE",
    help: "Usage: irrdctl nrtm4 server-show-public-key [OPTIONS] SOURCE\n\n  Show the public key(s) matching the currently configured private keys.\n\nOptions:\n  --help  Show this message and exit.\n",
    subcommands: &[],
    arguments: &["SOURCE"],
    flags: &[],
};

const USER_MFA_CLEAR: Command = Command {
    path: "irrdctl user-mfa-clear",
    usage_tail: "[OPTIONS] EMAIL",
    help: "Usage: irrdctl user-mfa-clear [OPTIONS] EMAIL\n\n  Remove two-factor authentication for user EMAIL.\n\nOptions:\n  --help  Show this message and exit.\n",
    subcommands: &[],
    arguments: &["EMAIL"],
    flags: &[],
};

const USER_CHANGE_OVERRIDE: Command = Command {
    path: "irrdctl user-change-override",
    usage_tail: "[OPTIONS] EMAIL",
    help: "Usage: irrdctl user-change-override [OPTIONS] EMAIL\n\n  Change the override permission for user EMAIL.\n\nOptions:\n  --enable / --disable\n  --help                Show this message and exit.\n",
    subcommands: &[],
    arguments: &["EMAIL"],
    flags: &["--enable", "--disable"],
};

/// click's `UsageError`: usage, hint, error; exit 2.
fn usage_error(cmd: &Command, msg: &str) -> ExitCode {
    eprint!(
        "Usage: {} {}\nTry '{} --help' for help.\n\nError: {msg}\n",
        cmd.path, cmd.usage_tail, cmd.path
    );
    ExitCode::from(2)
}

/// click's `ClickException`: `Error: ...`; exit 1.
pub(crate) fn click_exception(msg: &str) -> ExitCode {
    eprintln!("Error: {msg}");
    ExitCode::from(1)
}

/// `difflib.SequenceMatcher(None, a, b).ratio()`.
fn sequence_ratio(a: &str, b: &str) -> f64 {
    fn matches(a: &[char], b: &[char]) -> usize {
        if a.is_empty() || b.is_empty() {
            return 0;
        }
        let (mut best, mut bi, mut bj) = (0, 0, 0);
        for i in 0..a.len() {
            for j in 0..b.len() {
                let mut k = 0;
                while i + k < a.len() && j + k < b.len() && a[i + k] == b[j + k] {
                    k += 1;
                }
                if k > best {
                    (best, bi, bj) = (k, i, j);
                }
            }
        }
        if best == 0 {
            return 0;
        }
        best + matches(&a[..bi], &b[..bj]) + matches(&a[bi + best..], &b[bj + best..])
    }
    let (a, b): (Vec<char>, Vec<char>) = (a.chars().collect(), b.chars().collect());
    let total = a.len() + b.len();
    if total == 0 {
        return 1.0;
    }
    2.0 * matches(&a, &b) as f64 / total as f64
}

/// click's "No such option" message, with its suggestions.
fn no_such_option(opt: &str, possibilities: &[&str]) -> String {
    let mut close: Vec<(&str, f64)> = possibilities
        .iter()
        .map(|p| (*p, sequence_ratio(opt, p)))
        .filter(|(_, r)| *r >= 0.6)
        .collect();
    close.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    let mut msg = format!("No such option: {opt}");
    match close.as_slice() {
        [] => {}
        [(one, _)] => msg.push_str(&format!(" Did you mean {one}?")),
        many => msg.push_str(&format!(
            " (Possible options: {})",
            many.iter().map(|(p, _)| *p).collect::<Vec<_>>().join(", ")
        )),
    }
    msg
}

/// The name click reports for an unknown option token.
fn option_name(arg: &str) -> &str {
    let name = arg.split_once('=').map_or(arg, |(n, _)| n);
    if name.starts_with("--") || name.chars().count() <= 2 {
        name
    } else {
        let end = name.char_indices().nth(2).map_or(name.len(), |(i, _)| i);
        &name[..end]
    }
}

enum Leaf {
    Help,
    Args(Vec<String>),
}

/// Parse a leaf command's arguments: options anywhere, `--` ends them.
fn parse_leaf(cmd: &Command, args: &[String]) -> Result<Leaf, ExitCode> {
    let mut positional = Vec::new();
    let mut only_args = false;
    for a in args {
        if only_args || !a.starts_with('-') || a == "-" {
            positional.push(a.clone());
        } else if a == "--" {
            only_args = true;
        } else if a == "--help" {
            print!("{}", cmd.help);
            return Ok(Leaf::Help);
        } else if cmd.flags.contains(&a.as_str()) {
            // --enable/--disable: read when user-change-override lands.
        } else {
            let mut possible: Vec<&str> = cmd.flags.to_vec();
            possible.push("--help");
            return Err(usage_error(cmd, &no_such_option(option_name(a), &possible)));
        }
    }
    if positional.len() < cmd.arguments.len() {
        return Err(usage_error(
            cmd,
            &format!("Missing argument '{}'.", cmd.arguments[positional.len()]),
        ));
    }
    if positional.len() > cmd.arguments.len() {
        let extra = &positional[cmd.arguments.len()..];
        let s = if extra.len() == 1 { "" } else { "s" };
        return Err(usage_error(
            cmd,
            &format!("Got unexpected extra argument{s} ({})", extra.join(" ")),
        ));
    }
    Ok(Leaf::Args(positional))
}

enum GroupParse {
    Done(ExitCode),
    Invoke {
        config: Option<String>,
        name: String,
        rest: Vec<String>,
    },
}

/// Parse a group's options up to its subcommand name.
fn parse_group(cmd: &Command, args: &[String], top: bool) -> GroupParse {
    if args.is_empty() {
        // no_args_is_help: the help, on standard error, exit 2.
        eprint!("{}", cmd.help);
        return GroupParse::Done(ExitCode::from(2));
    }
    let mut config: Option<String> = None;
    let mut i = 0;
    let mut help = false;
    while i < args.len() {
        let a = &args[i];
        if !a.starts_with('-') || a == "-" {
            break;
        }
        if a == "--" {
            i += 1;
            break;
        }
        if a == "--help" {
            help = true;
        } else if top && (a == "--config" || a.starts_with("--config=")) {
            match a.strip_prefix("--config=") {
                Some(v) => config = Some(v.to_owned()),
                None => {
                    i += 1;
                    match args.get(i) {
                        Some(v) => config = Some(v.clone()),
                        None => {
                            eprintln!("Error: Option '--config' requires an argument.");
                            return GroupParse::Done(ExitCode::from(2));
                        }
                    }
                }
            }
        } else {
            let possible: &[&str] = if top {
                &["--config", "--help"]
            } else {
                &["--help"]
            };
            return GroupParse::Done(usage_error(cmd, &no_such_option(option_name(a), possible)));
        }
        i += 1;
    }
    if help {
        print!("{}", cmd.help);
        return GroupParse::Done(ExitCode::SUCCESS);
    }
    if top {
        // click.Path(exists=True, dir_okay=False) on the value or default.
        let path = config.clone().unwrap_or_else(|| "/etc/irrd.yaml".into());
        let p = std::path::Path::new(&path);
        let err = if !p.exists() {
            Some(format!("File '{path}' does not exist."))
        } else if p.is_dir() {
            Some(format!("File '{path}' is a directory."))
        } else {
            None
        };
        if let Some(e) = err {
            return GroupParse::Done(usage_error(
                cmd,
                &format!("Invalid value for '--config': {e}"),
            ));
        }
        config = Some(path);
    }
    let Some(name) = args.get(i) else {
        return GroupParse::Done(usage_error(cmd, "Missing command."));
    };
    if !cmd.subcommands.contains(&name.as_str()) {
        return GroupParse::Done(usage_error(cmd, &format!("No such command '{name}'.")));
    }
    GroupParse::Invoke {
        config,
        name: name.clone(),
        rest: args[i + 1..].to_vec(),
    }
}

/// `irrdctl`
pub(crate) fn irrdctl(args: &[OsString]) -> ExitCode {
    let args: Vec<String> = args
        .iter()
        .skip(1)
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    let (config, name, rest) = match parse_group(&TOP, &args, true) {
        GroupParse::Done(c) => return c,
        GroupParse::Invoke { config, name, rest } => (config, name, rest),
    };
    // The group callback: config_init(config).
    let cfg = match Configuration::load(config.as_deref()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{}", messages::configuration_error(&e.to_string()));
            return ExitCode::from(1);
        }
    };
    logging::init(&cfg);
    match name.as_str() {
        "nrtm4" => {
            let (sub, rest) = match parse_group(&NRTM4, &rest, false) {
                GroupParse::Done(c) => return c,
                GroupParse::Invoke { name, rest, .. } => (name, rest),
            };
            let cmd = match sub.as_str() {
                "client-clear-known-keys" => &CLIENT_CLEAR_KNOWN_KEYS,
                "generate-private-key" => &GENERATE_PRIVATE_KEY,
                _ => &SERVER_SHOW_PUBLIC_KEY,
            };
            let positional = match parse_leaf(cmd, &rest) {
                Ok(Leaf::Help) => return ExitCode::SUCCESS,
                Ok(Leaf::Args(p)) => p,
                Err(c) => return c,
            };
            match sub.as_str() {
                "client-clear-known-keys" => client_clear_known_keys(&cfg, &positional[0]),
                "generate-private-key" => crate::serving_tools::generate_private_key(),
                _ => crate::serving_tools::server_show_public_key(&cfg, &positional[0]),
            }
        }
        other => {
            let cmd = if other == "user-mfa-clear" {
                &USER_MFA_CLEAR
            } else {
                &USER_CHANGE_OVERRIDE
            };
            match parse_leaf(cmd, &rest) {
                Ok(Leaf::Help) => ExitCode::SUCCESS,
                Ok(Leaf::Args(_)) => not_implemented(cmd.path),
                Err(c) => c,
            }
        }
    }
}

fn not_implemented(path: &str) -> ExitCode {
    eprintln!("{}", messages::not_implemented(path));
    ExitCode::from(1)
}

/// `irrdctl nrtm4 client-clear-known-keys SOURCE`
fn client_clear_known_keys(cfg: &Configuration, source: &str) -> ExitCode {
    if settings::truthy(cfg, "readonly_standby") {
        return click_exception(messages::CTL_READONLY_STANDBY);
    }
    if !settings::truthy(
        cfg,
        &format!("sources.{source}.nrtm4_client_initial_public_key"),
    ) {
        return click_exception(&messages::ctl_not_nrtm4_client(source));
    }
    let store = match open_store(cfg) {
        Ok(s) => s,
        Err(c) => return c,
    };
    let src = source.to_owned();
    let found = store.write(move |tx| {
        let Some(mut st) = tx.read()?.database_status(&src)? else {
            return Ok(false);
        };
        // The ORM writes (and bumps `updated`) only when a value changes.
        if st.nrtm4_client_current_key.is_some() || st.nrtm4_client_next_key.is_some() {
            st.nrtm4_client_current_key = None;
            st.nrtm4_client_next_key = None;
            st.updated = tx.transaction_time();
            tx.put_database_status(&st)?;
        }
        Ok(true)
    });
    match found {
        Ok(true) => {
            println!("{}", messages::ctl_known_keys_removed(source));
            tracing::info!(target: CTL_LOG_TARGET, "{}", messages::ctl_known_keys_removed_log(source));
            ExitCode::SUCCESS
        }
        Ok(false) => click_exception(&messages::ctl_no_known_keys(source)),
        Err(e) => {
            eprintln!("{e}");
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn difflib_ratio() {
        assert!((sequence_ratio("--conf", "--config") - 12.0 / 14.0).abs() < 1e-9);
        assert_eq!(
            no_such_option("--conf", &["--config", "--help"]),
            "No such option: --conf Did you mean --config?"
        );
        assert_eq!(
            no_such_option("-h", &["--config", "--help"]),
            "No such option: -h"
        );
        assert_eq!(
            no_such_option("--bogus", &["--config", "--help"]),
            "No such option: --bogus"
        );
    }
}
