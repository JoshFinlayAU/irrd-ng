//! `irrd`: the daemon. It runs in the foreground with the whois server,
//! `/v1/whois/` and the mirroring scheduler; daemonising, the PID file,
//! user switching and the other background processes come in Phase 9.

use std::ffi::OsString;
use std::net::{IpAddr, SocketAddr};
use std::process::ExitCode;
use std::sync::{Arc, RwLock};

use config::Configuration;
use store::{Store, StoreOptions};

use crate::argparse::{Opt, Parsed, Parser};
use crate::{logging, messages, settings, whois_server};

const IRRD: Parser = Parser {
    prog: "irrd",
    usage: "usage: irrd [-h] [--config CONFIG_FILE_PATH] [--foreground]\n",
    help: "usage: irrd [-h] [--config CONFIG_FILE_PATH] [--foreground]\n\nIRRd main process\n\noptions:\n  -h, --help            show this help message and exit\n  --config CONFIG_FILE_PATH\n                        use a different IRRd config file (default:\n                        /etc/irrd.yaml)\n  --foreground          run IRRd in the foreground, don't detach\n",
    options: &[
        Opt {
            flag: "--config",
            dest: "config_file_path",
            required: false,
            int: false,
            store_true: false,
        },
        Opt {
            flag: "--foreground",
            dest: "foreground",
            required: false,
            int: false,
            store_true: true,
        },
    ],
    positionals: &[],
};

const LOG_TARGET: &str = "irrd.daemon.main";

/// `urlparse(url).hostname`: the host of an `http(s)://` URL, lower case,
/// without user info, port or IPv6 brackets.
pub(crate) fn url_hostname(url: &str) -> Option<String> {
    let rest = url.split_once("://")?.1;
    let netloc = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let hostport = netloc.rsplit_once('@').map_or(netloc, |(_, h)| h);
    let host = if let Some(v6) = hostport.strip_prefix('[') {
        v6.split(']').next().unwrap_or_default()
    } else {
        hostport.split(':').next().unwrap_or_default()
    };
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

fn http_settings(cfg: &Configuration) -> http::HttpSettings {
    let url = settings::str_setting(cfg, "server.http.url").unwrap_or_default();
    let forwarded = match settings::setting(cfg, "server.http.forwarded_allowed_ips") {
        Some(config::Value::List(l)) => l.iter().map(config::Value::py_str).collect(),
        Some(config::Value::Str(s)) => s.split(',').map(|x| x.trim().to_owned()).collect(),
        _ => Vec::new(),
    };
    http::HttpSettings {
        server_header: format!("IRRd {}", crate::IRRD_VERSION),
        allowed_host: url_hostname(&url),
        https_only: url.starts_with("https://"),
        forwarded_allowed_ips: forwarded,
    }
}

fn bind(interface: &str, port: u16, backlog: i32) -> std::io::Result<tokio::net::TcpListener> {
    let ip: IpAddr = interface
        .parse()
        .map_err(|_| std::io::Error::other(format!("invalid interface {interface}")))?;
    let addr = SocketAddr::new(ip, port);
    let socket = socket2::Socket::new(
        socket2::Domain::for_address(addr),
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    socket.set_reuse_address(true)?;
    socket.bind(&addr.into())?;
    socket.listen(backlog)?;
    socket.set_nonblocking(true)?;
    tokio::net::TcpListener::from_std(socket.into())
}

/// Log panics with a backtrace instead of printing them. A panic in a
/// connection or request is contained by the caller; one in the store's
/// single writer thread leaves the daemon unable to write, so it stops.
pub(crate) fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        let thread = std::thread::current();
        let name = thread.name().unwrap_or("unnamed").to_owned();
        let backtrace = std::backtrace::Backtrace::force_capture();
        tracing::error!(target: LOG_TARGET, "{}", messages::panicked(&name, &info.to_string(), &backtrace.to_string()));
        if name == store::WRITER_THREAD_NAME {
            tracing::error!(target: LOG_TARGET, critical = true, "{}", messages::WRITER_PANICKED);
            std::process::exit(1);
        }
    }));
}

/// The `irrd` tool.
pub(crate) fn run(args: &[OsString]) -> ExitCode {
    let a = match IRRD.parse(args.get(1..).unwrap_or_default()) {
        Parsed::Args(a) => a,
        Parsed::Help => return ExitCode::SUCCESS,
        Parsed::Error => return ExitCode::from(2),
    };
    let mut cfg = match Configuration::load(a.get("config_file_path").map(String::as_str)) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{}", messages::configuration_error(&e.to_string()));
            return ExitCode::from(1);
        }
    };
    logging::init(&cfg);
    install_panic_hook();
    if !a.contains_key("foreground") {
        let has_log = settings::str_setting(&cfg, "log.logfile_path").is_some()
            || settings::str_setting(&cfg, "log.logging_config_path").is_some();
        if !has_log {
            tracing::error!(target: LOG_TARGET, critical = true, "{}", messages::DAEMON_NEEDS_LOGFILE);
            return ExitCode::SUCCESS;
        }
        tracing::warn!(target: LOG_TARGET, "{}", messages::DAEMON_FOREGROUND_ONLY);
    }
    if let Some(notice) = cfg.storage_notice() {
        tracing::info!(target: LOG_TARGET, "{notice}");
    }

    let store_path = settings::store_path();
    let store = match Store::open(
        &StoreOptions::new(&store_path),
        settings::store_settings(&cfg),
    ) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(target: LOG_TARGET, critical = true, "{e}");
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };
    tracing::info!(
        target: LOG_TARGET,
        "{}",
        messages::irrd_starting(crate::IRRD_VERSION, std::process::id(), &store_path)
    );

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("irrd")
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };
    let code = runtime.block_on(async move { serve(&mut cfg, store).await });
    // Running imports are abandoned, as v4 terminates its children: their
    // write transactions never commit.
    runtime.shutdown_timeout(std::time::Duration::from_secs(3));
    code
}

async fn serve(cfg: &mut Configuration, store: Store) -> ExitCode {
    let nrtm: Arc<dyn query::NrtmV3> = Arc::new(query::NrtmNotServed);
    let query_settings = Arc::new(settings::query_settings(cfg));

    let whois_interface =
        settings::str_setting(cfg, "server.whois.interface").unwrap_or_else(|| "::0".into());
    let whois_port = settings::int_setting(cfg, "server.whois.port").unwrap_or(43) as u16;
    let max_connections = settings::int_setting(cfg, "server.whois.max_connections")
        .unwrap_or(10)
        .max(1) as usize;
    let http_interface =
        settings::str_setting(cfg, "server.http.interface").unwrap_or_else(|| "::0".into());
    let http_port = settings::int_setting(cfg, "server.http.port").unwrap_or(8080) as u16;

    tracing::info!(
        target: whois_server::LOG_TARGET,
        "{}",
        query::messages::log_starting_whois(&whois_interface, whois_port)
    );
    // socketserver.TCPServer.request_queue_size
    let whois_listener = match bind(&whois_interface, whois_port, 50) {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(target: LOG_TARGET, critical = true, "{}", messages::bind_failed("whois", &whois_interface, whois_port, &e));
            return ExitCode::from(1);
        }
    };
    // uvicorn's default backlog.
    let http_listener = match bind(&http_interface, http_port, 2048) {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(target: LOG_TARGET, critical = true, "{}", messages::bind_failed("HTTP", &http_interface, http_port, &e));
            return ExitCode::from(1);
        }
    };

    let whois = Arc::new(whois_server::WhoisShared {
        store: store.clone(),
        settings: RwLock::new(query_settings.clone()),
        nrtm: nrtm.clone(),
    });
    let http_state = Arc::new(http::HttpState {
        store: store.clone(),
        query: RwLock::new(query_settings),
        http: RwLock::new(Arc::new(http_settings(cfg))),
        nrtm,
    });
    tokio::spawn(whois_server::serve(
        whois_listener,
        whois.clone(),
        max_connections,
    ));
    tokio::spawn(http::serve(http_listener, http_state.clone()));

    let (mirror_tx, mirror_rx) =
        tokio::sync::watch::channel(Arc::new(settings::mirror_settings(cfg)));
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let scheduler = tokio::spawn(nrtm::mirror::scheduler::run_scheduler(
        store.clone(),
        mirror_rx,
        shutdown_rx,
    ));

    use tokio::signal::unix::{SignalKind, signal};
    let (Ok(mut term), Ok(mut int), Ok(mut hup)) = (
        signal(SignalKind::terminate()),
        signal(SignalKind::interrupt()),
        signal(SignalKind::hangup()),
    ) else {
        return ExitCode::from(1);
    };
    loop {
        tokio::select! {
            _ = term.recv() => break,
            _ = int.recv() => break,
            _ = hup.recv() => {
                if cfg.reload().is_ok() {
                    let qs = Arc::new(settings::query_settings(cfg));
                    store.set_settings(settings::store_settings(cfg));
                    if let Ok(mut s) = whois.settings.write() {
                        *s = qs.clone();
                    }
                    if let Ok(mut s) = http_state.query.write() {
                        *s = qs;
                    }
                    if let Ok(mut s) = http_state.http.write() {
                        *s = Arc::new(http_settings(cfg));
                    }
                    let _ = mirror_tx.send(Arc::new(settings::mirror_settings(cfg)));
                }
            }
        }
    }
    let _ = shutdown_tx.send(true);
    let _ = tokio::time::timeout(std::time::Duration::from_secs(3), scheduler).await;
    tracing::info!(target: whois_server::LOG_TARGET, "{}", messages::WHOIS_SHUTTING_DOWN);
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostname_like_urlparse() {
        assert_eq!(
            url_hostname("http://localhost:9080/").as_deref(),
            Some("localhost")
        );
        assert_eq!(
            url_hostname("https://User@IRR.Example.net/x").as_deref(),
            Some("irr.example.net")
        );
        assert_eq!(
            url_hostname("http://[2001:db8::1]:80/").as_deref(),
            Some("2001:db8::1")
        );
        assert_eq!(url_hostname("localhost"), None);
    }
}
