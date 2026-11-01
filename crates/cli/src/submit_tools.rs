//! The submission tools: `irrd_submit_email` (`irrd/scripts/
//! submit_email.py`), `irrd_load_pgp_keys` (`load_pgp_keys.py`),
//! `irrd_set_last_modified_auth` (`set_last_modified_auth.py`) and the
//! web UI user commands of `irrdctl` (`irrd_control.py`).

use std::ffi::OsString;
use std::io::{BufRead as _, Read as _, Write as _};
use std::process::ExitCode;
use std::sync::Arc;

use config::Configuration;
use store::{AuthTable, Store};

use crate::argparse::{Opt, Parsed, Parser};
use crate::mirror_tools::{click_exception, open_store};
use crate::{logging, messages, settings};

const CONFIG_OPT: Opt = Opt {
    flag: "--config",
    dest: "config_file_path",
    required: false,
    int: false,
    store_true: false,
};

const SUBMIT_EMAIL: Parser = Parser {
    prog: "irrd_submit_email",
    usage: "usage: irrd_submit_email [-h] [--config CONFIG_FILE_PATH]\n",
    help: "usage: irrd_submit_email [-h] [--config CONFIG_FILE_PATH]\n\nProcess a raw email message with requested changes. Authentication is checked,\nmessage is always read from stdin. A report is sent to the user by email,\nalong with any notifications to mntners and others.\n\noptions:\n  -h, --help            show this help message and exit\n  --config CONFIG_FILE_PATH\n                        use a different IRRd config file (default:\n                        /etc/irrd.yaml)\n",
    options: &[CONFIG_OPT],
    positionals: &[],
};

const LOAD_PGP_KEYS: Parser = Parser {
    prog: "irrd_load_pgp_keys",
    usage: "usage: irrd_load_pgp_keys [-h] [--config CONFIG_FILE_PATH] source\n",
    help: "usage: irrd_load_pgp_keys [-h] [--config CONFIG_FILE_PATH] source\n\nLoad all PGP keys from key-cert objects for a specific source into the GnuPG\nkeychain.\n\npositional arguments:\n  source                the name of the source for which to load PGP keys\n\noptions:\n  -h, --help            show this help message and exit\n  --config CONFIG_FILE_PATH\n                        use a different IRRd config file (default:\n                        /etc/irrd.yaml)\n",
    options: &[CONFIG_OPT],
    positionals: &["source"],
};

const SET_LAST_MODIFIED: Parser = Parser {
    prog: "irrd_set_last_modified_auth",
    usage: "usage: irrd_set_last_modified_auth [-h] [--config CONFIG_FILE_PATH]\n",
    help: "usage: irrd_set_last_modified_auth [-h] [--config CONFIG_FILE_PATH]\n\nSet last-modified attribute on all authoritative objects.\n\noptions:\n  -h, --help            show this help message and exit\n  --config CONFIG_FILE_PATH\n                        use a different IRRd config file (default:\n                        /etc/irrd.yaml)\n",
    options: &[CONFIG_OPT],
    positionals: &[],
};

fn load(parser: &Parser, args: &[OsString]) -> Result<(Configuration, std::collections::HashMap<&'static str, String>), ExitCode> {
    let a = match parser.parse(args.get(1..).unwrap_or_default()) {
        Parsed::Args(a) => a,
        Parsed::Help => return Err(ExitCode::SUCCESS),
        Parsed::Error => return Err(ExitCode::from(2)),
    };
    let cfg = match Configuration::load(a.get("config_file_path").map(String::as_str)) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{}", messages::configuration_error(&e.to_string()));
            return Err(ExitCode::from(1));
        }
    };
    logging::init(&cfg);
    Ok((cfg, a))
}

fn writable_store(cfg: &Configuration) -> Result<Store, ExitCode> {
    let store = open_store(cfg)?;
    store.set_route_preference_hook(Some(rpki::route_preference_hook));
    Ok(store)
}

/// `irrd_submit_email`: process one e-mail from stdin.
pub(crate) fn submit_email(args: &[OsString]) -> ExitCode {
    let (cfg, _) = match load(&SUBMIT_EMAIL, args) {
        Ok(v) => v,
        Err(c) => return c,
    };
    let mut raw = Vec::new();
    let _ = std::io::stdin().read_to_end(&mut raw);
    let data = auth::email_parser::decode_input(&raw);
    let store = match writable_store(&cfg) {
        Ok(s) => s,
        Err(_) => {
            tracing::error!(
                target: "irrd.scripts.submit_email",
                critical = true,
                "An exception occurred while attempting to process the following email: {data}"
            );
            println!("{}", auth::messages::SUBMIT_EMAIL_INTERNAL_ERROR);
            return ExitCode::SUCCESS;
        }
    };
    let submit = Arc::new(settings::submit_settings(&cfg));
    let mail_settings = submit.mail.clone();
    let mut send = |r: &str, s: &str, b: &str| auth::send_email(&mail_settings, r, s, b);
    auth::email::handle_email_submission(&store, submit, &data, &mut send);
    ExitCode::SUCCESS
}

/// `irrd_load_pgp_keys SOURCE`: strictly parse every key-cert of a source,
/// which imports its key into the keyring.
pub(crate) fn load_pgp_keys(args: &[OsString]) -> ExitCode {
    let (cfg, a) = match load(&LOAD_PGP_KEYS, args) {
        Ok(v) => v,
        Err(c) => return c,
    };
    let source = rpsl::python::upper(rpsl::python::strip(
        a.get("source").map(String::as_str).unwrap_or_default(),
    ))
    .into_owned();
    let store = match open_store(&cfg) {
        Ok(s) => s,
        Err(c) => return c,
    };
    let rpsl_settings = match cfg.rpsl_settings() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };
    let keycerts: Vec<(String, String)> = {
        let r = match store.read() {
            Ok(r) => r,
            Err(e) => {
                eprintln!("{e}");
                return ExitCode::from(1);
            }
        };
        let v = r.view();
        let mut rows: Vec<(u64, store::RpslObjectRef<'_>)> = Vec::new();
        match v.objects(Some(&source), Some("key-cert")) {
            Ok(it) => {
                for item in it {
                    match item {
                        Ok(row) => rows.push(row),
                        Err(e) => {
                            eprintln!("{e}");
                            return ExitCode::from(1);
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("{e}");
                return ExitCode::from(1);
            }
        }
        rows.sort_by(query::order::object_cmp);
        rows.iter()
            .map(|(_, o)| (o.rpsl_pk.to_owned(), o.object_text.to_owned()))
            .collect()
    };
    let keyring = nrtm::keyring::load_keyring(&store);
    let mut out = std::io::stdout().lock();
    for (pk, text) in keycerts {
        let _ = writeln!(out, "Loading key-cert {pk}");
        let parsed = rpsl::rpsl_object_from_text(
            &text,
            &rpsl::ParseOptions {
                strict: true,
                default_source: None,
                settings: &rpsl_settings,
                keyring: &keyring,
            },
        );
        match parsed {
            Ok(obj) => {
                let errors: Vec<String> = obj.messages().errors().map(str::to_owned).collect();
                if !errors.is_empty() {
                    let _ = writeln!(
                        out,
                        "Errors in PGP key {pk}: {}",
                        config::str_list_repr(&errors)
                    );
                }
            }
            Err(e) => {
                let _ = out.flush();
                nrtm::keyring::save_keyring(&store, &keyring);
                eprintln!("{e}");
                return ExitCode::from(1);
            }
        }
    }
    let _ = writeln!(out, "All valid key-certs loaded into the GnuPG keychain.");
    nrtm::keyring::save_keyring(&store, &keyring);
    ExitCode::SUCCESS
}

/// `irrd_set_last_modified_auth`: rewrite the `last-modified` of every
/// object in an authoritative source from its `updated` time, without
/// journal entries.
pub(crate) fn set_last_modified_auth(args: &[OsString]) -> ExitCode {
    let (cfg, _) = match load(&SET_LAST_MODIFIED, args) {
        Ok(v) => v,
        Err(c) => return c,
    };
    if settings::truthy(&cfg, "readonly_standby") {
        println!("Unable to run, because readonly_standby is set");
        return ExitCode::from(255);
    }
    let auth_sources: Vec<String> = settings::configured_sources(&cfg)
        .into_iter()
        .filter(|s| settings::truthy(&cfg, &format!("sources.{s}.authoritative")))
        .collect();
    let store = match open_store(&cfg) {
        Ok(s) => s,
        Err(c) => return c,
    };
    let rpsl_settings = cfg.rpsl_settings().unwrap_or_default();
    let sources = auth_sources.clone();
    let result = store.write(move |tx| {
        let mut rows = Vec::new();
        {
            let v = tx.read()?;
            for s in &sources {
                for item in v.objects(Some(s), None)? {
                    rows.push(item?.1.to_row());
                }
            }
        }
        let mut lines = vec![format!(
            "Updating {} objects in sources {}",
            rows.len(),
            config::str_list_repr(&sources)
        )];
        let keyring = rpsl::Keyring::new();
        for mut row in rows {
            let obj = match rpsl::rpsl_object_from_text(
                &row.object_text,
                &rpsl::ParseOptions {
                    strict: false,
                    default_source: None,
                    settings: &rpsl_settings,
                    keyring: &keyring,
                },
            ) {
                Ok(o) => o,
                Err(e) => return Err(store::StoreError::ValueError(e.to_string())),
            };
            let errors: Vec<String> = obj.messages().errors().map(str::to_owned).collect();
            if !errors.is_empty() {
                lines.push(format!(
                    "Failed to process {obj}: {}",
                    config::str_list_repr(&errors)
                ));
                continue;
            }
            row.object_text =
                obj.render_rpsl_text_with_last_modified(row.updated.unix_seconds(), &rpsl_settings);
            tx.put_rpsl_object(&row)?;
        }
        Ok(lines)
    });
    match result {
        Ok(lines) => {
            for l in lines {
                println!("{l}");
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("{e}");
            ExitCode::from(1)
        }
    }
}

// ---------------------------------------------------------------------------
// irrdctl user-mfa-clear / user-change-override
// ---------------------------------------------------------------------------

/// `click.confirm(text, abort=True)`: `true` to go on. Prints click's
/// `Aborted!` when the answer is no.
fn confirm(text: &str) -> bool {
    let stdin = std::io::stdin();
    loop {
        print!("{text} [y/N]: ");
        let _ = std::io::stdout().flush();
        let mut line = String::new();
        match stdin.lock().read_line(&mut line) {
            Ok(0) | Err(_) => {
                println!();
                eprintln!("Aborted!");
                return false;
            }
            Ok(_) => {}
        }
        match line.trim().to_lowercase().as_str() {
            "y" | "yes" => return true,
            "n" | "no" | "" => {
                eprintln!("Aborted!");
                return false;
            }
            _ => eprintln!("Error: invalid input"),
        }
    }
}

/// `find_user(session_provider, email)`
fn find_user(store: &Store, email: &str) -> Result<Option<store::AuthUserRow>, ExitCode> {
    let r = store.read().map_err(|e| {
        eprintln!("{e}");
        ExitCode::from(1)
    })?;
    let users = r.view().auth_users().map_err(|e| {
        eprintln!("{e}");
        ExitCode::from(1)
    })?;
    Ok(users.into_iter().find(|u| u.email == email))
}

fn webauthns_of(store: &Store, user: &store::AuthUserRow) -> Vec<store::AuthWebAuthnRow> {
    let mut w: Vec<store::AuthWebAuthnRow> = store
        .read()
        .and_then(|r| r.view().auth_webauthns())
        .unwrap_or_default()
        .into_iter()
        .filter(|w| w.user_id == Some(user.pk))
        .collect();
    w.sort_by_key(|w| w.created);
    w
}

/// `datetime.strftime("%Y-%m-%d %H:%M")` of a UTC timestamp.
fn ui_datetime(t: store::Timestamp) -> String {
    let s = t.to_string();
    // Timestamp displays as ISO 8601: YYYY-MM-DDTHH:MM:SS...
    format!("{} {}", s.get(..10).unwrap_or(""), s.get(11..16).unwrap_or(""))
}

/// `send_authentication_change_mail(user, None, msg)`, rendering v4's
/// `authentication_change_mail` templates.
fn authentication_change_mail(cfg: &Configuration, user: &store::AuthUserRow, msg: &str) {
    let url = settings::str_setting(cfg, "server.http.url").unwrap_or_default();
    let esc = |s: &str| {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&#34;")
            .replace('\'', "&#39;")
    };
    let subject = format!("Account settings changed on {}", esc(&url));
    let body = format!(
        "There has been a change in the settings for your account\n{} on the IRRD instance on {}:\n\n{}\n\nIf you did not request this change, contact the operators\nof this instance immediately.",
        esc(&user.email),
        esc(&url),
        esc(msg)
    );
    let mail = settings::mail_settings(cfg);
    if let Err(e) = auth::send_email(&mail, &user.email, &subject, &body) {
        eprintln!("{e}");
    }
    tracing::info!(target: "irrd.webui.helpers", "email sent to {}: {subject}", user.email);
}

/// `irrdctl user-mfa-clear EMAIL`
pub(crate) fn user_mfa_clear(cfg: &Configuration, email: &str) -> ExitCode {
    if settings::truthy(cfg, "readonly_standby") {
        return click_exception(messages::CTL_READONLY_STANDBY);
    }
    let store = match open_store(cfg) {
        Ok(s) => s,
        Err(c) => return c,
    };
    let user = match find_user(&store, email) {
        Ok(Some(u)) => u,
        Ok(None) => return click_exception(&format!("No user found for {email}.")),
        Err(c) => return c,
    };
    let webauthns = webauthns_of(&store, &user);
    let has_totp = user.totp_secret.as_deref().is_some_and(|s| !s.is_empty());
    if webauthns.is_empty() && !has_totp {
        return click_exception("User has no two-factor methods enabled.");
    }
    let mut methods: Vec<String> = webauthns
        .iter()
        .map(|w| format!("WebAuthn '{}' (last use {})", w.name, ui_datetime(w.last_used)))
        .collect();
    if has_totp {
        methods.push("TOTP".to_owned());
    }
    println!(
        "\nYou are about to remove multi-factor authentication for user:\n{} ({})\n\nThe user currently has the following methods enabled:\n- {}\n\nAfter this, the user will be able to log in with their password.\n\nIt is your own responsibility to determine that the legitimate\nuser has lost access to their two-factor methods.\nThe user will be notified of this change.\n",
        user.name,
        user.email,
        methods.join("\n- ")
    );
    if !confirm(&format!(
        "Are you sure you want to remove two-factor authentication for {email}?"
    )) {
        return ExitCode::from(1);
    }
    let mut updated = user.clone();
    updated.totp_secret = None;
    updated.totp_last_used = None;
    let pks: Vec<store::Uuid> = webauthns.iter().map(|w| w.pk).collect();
    let result = store.write(move |tx| {
        for pk in &pks {
            tx.delete_auth_row_raw(AuthTable::Webauthn, pk)?;
        }
        tx.put_auth_user(&updated)
    });
    if let Err(e) = result {
        eprintln!("{e}");
        return ExitCode::from(1);
    }
    println!("Two-factor authentication has been removed.");
    tracing::info!(target: "irrd.scripts.irrd_control", "cleared two-factor authentication for user {} ({})", user.email, user.pk);
    authentication_change_mail(
        cfg,
        &user,
        "All two-factor authentication methods were removed by an IRRD administrator.",
    );
    ExitCode::SUCCESS
}

/// `irrdctl user-change-override EMAIL [--enable/--disable]`
pub(crate) fn user_change_override(cfg: &Configuration, email: &str, enable: bool) -> ExitCode {
    if settings::truthy(cfg, "readonly_standby") {
        return click_exception(messages::CTL_READONLY_STANDBY);
    }
    let store = match open_store(cfg) {
        Ok(s) => s,
        Err(c) => return c,
    };
    let user = match find_user(&store, email) {
        Ok(Some(u)) => u,
        Ok(None) => return click_exception(&format!("No user found for {email}.")),
        Err(c) => return c,
    };
    let has_totp = user.totp_secret.as_deref().is_some_and(|s| !s.is_empty());
    if webauthns_of(&store, &user).is_empty() && !has_totp {
        return click_exception(
            "User has no two-factor methods enabled, which is required to add override.",
        );
    }
    if enable && user.override_ {
        return click_exception("User already has override permission.");
    }
    if !enable && !user.override_ {
        return click_exception("User already has no override permission.");
    }
    if enable {
        println!(
            "\nYou are about to assign override permission for user:\n{} ({})\n\nThis will allow the user to edit any object in the database.\n",
            user.name, user.email
        );
        if !confirm(&format!(
            "Are you sure you want to assign this permission to {email}?"
        )) {
            return ExitCode::from(1);
        }
    }
    let mut updated = user.clone();
    updated.override_ = enable;
    if let Err(e) = store.write(move |tx| tx.put_auth_user(&updated)) {
        eprintln!("{e}");
        return ExitCode::from(1);
    }
    let s = if enable { "enabled" } else { "disabled" };
    println!("Override permission has been {s}.");
    tracing::info!(target: "irrd.scripts.irrd_control", "override {s} for user {} ({})", user.email, user.pk);
    ExitCode::SUCCESS
}
