//! `irrd`: the daemon (`irrd/daemon/main.py`). It validates the
//! configuration, detaches unless `--foreground` is given, holds the PID
//! file in `piddir`, binds the whois port and then drops to `user` and
//! `group`, and runs the whois server, the HTTP server, the mirroring
//! scheduler and, with `ng_replication`, standby replication, all in one
//! process. SIGHUP reloads the configuration with v4's per-key effects;
//! SIGTERM shuts down.

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
    let mut status_sources = std::collections::HashMap::new();
    let mut journaled_sources = Vec::new();
    for name in settings::configured_sources(cfg) {
        let k = |key: &str| format!("sources.{name}.{key}");
        if settings::truthy(cfg, &k("keep_journal")) {
            journaled_sources.push(name.clone());
        }
        status_sources.insert(
            name.clone(),
            http::StatusSourceSettings {
                nrtm_host: settings::str_setting(cfg, &k("nrtm_host")).filter(|h| !h.is_empty()),
                nrtm_port: settings::int_setting(cfg, &k("nrtm_port")).unwrap_or(43),
                nrtm4_client_notification_file_url: settings::str_setting(
                    cfg,
                    &k("nrtm4_client_notification_file_url"),
                )
                .filter(|u| !u.is_empty()),
            },
        );
    }
    http::HttpSettings {
        server_header: format!("IRRd {}", crate::IRRD_VERSION),
        allowed_host: url_hostname(&url),
        https_only: url.starts_with("https://"),
        forwarded_allowed_ips: forwarded,
        whois_interface: settings::str_setting(cfg, "server.whois.interface")
            .unwrap_or_else(|| "::0".into()),
        whois_port: settings::int_setting(cfg, "server.whois.port").unwrap_or(43),
        status_access_list: settings::str_setting(cfg, "server.http.status_access_list"),
        event_stream_access_list: settings::str_setting(
            cfg,
            "server.http.event_stream_access_list",
        ),
        status_sources,
        journaled_sources,
        hostname: hostname(),
    }
}

/// `socket.gethostname()`
fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .or_else(|_| std::fs::read_to_string("/etc/hostname"))
        .map(|h| h.trim().to_owned())
        .unwrap_or_default()
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

/// Set in the detached process, so it knows the launcher's checks are done.
const DAEMON_STAGE_ENV: &str = "IRRD_NG_DAEMON_STAGE";

/// A setting from the file alone, as v4's `user_config_staging.get()`
/// reads it before daemonising (no environment, no defaults).
fn staged(cfg: &Configuration, name: &str) -> Option<config::Value> {
    let mut v = None::<&config::Value>;
    let mut dict = Some(cfg.user_config());
    for part in name.split('.') {
        let d = dict?;
        v = d.get_str(part);
        dict = v.and_then(config::Value::as_dict);
    }
    v.filter(|v| !matches!(v, config::Value::None)).cloned()
}

type Owner = Option<(nix::unistd::User, nix::unistd::Gid)>;

/// `get_configured_owner()`: the user and gid of `user` and `group` when
/// both are set. `Err` is the last line of the traceback v4 prints for an
/// unknown name.
fn configured_owner(user: Option<String>, group: Option<String>) -> Result<Owner, String> {
    let (Some(user), Some(group)) = (
        user.filter(|u| !u.is_empty()),
        group.filter(|g| !g.is_empty()),
    ) else {
        return Ok(None);
    };
    let missing = |what: &str, name: &str| {
        format!(
            "KeyError: {}",
            config::str_repr(&format!(
                "{what}(): name not found: {}",
                config::str_repr(name)
            ))
        )
    };
    let u = nix::unistd::User::from_name(&user)
        .ok()
        .flatten()
        .ok_or_else(|| missing("getpwnam", &user))?;
    let g = nix::unistd::Group::from_name(&group)
        .ok()
        .flatten()
        .ok_or_else(|| missing("getgrnam", &group))?;
    Ok(Some((u, g.gid)))
}

/// `if uid and gid:` in v4: root (0) for either means no change.
fn drops_privileges(owner: &Owner) -> bool {
    owner
        .as_ref()
        .is_some_and(|(u, g)| !u.uid.is_root() && g.as_raw() != 0)
}

/// What `main()` does before `DaemonContext`: refuse to start without a
/// log destination in the background, check the log file is writable by
/// the configured user, and detach. `Some` ends the launcher with that
/// exit code.
fn launcher(cfg: &Configuration, args: &[OsString], foreground: bool) -> Option<ExitCode> {
    let logfile = staged(cfg, "log.logfile_path").filter(config::Value::truthy);
    let logging_config = staged(cfg, "log.logging_config_path").filter(config::Value::truthy);
    if logfile.is_none() && logging_config.is_none() && !foreground {
        tracing::error!(target: logging::ROOT_LOGGER, critical = true, "{}", messages::DAEMON_NEEDS_LOGFILE);
        return Some(ExitCode::SUCCESS);
    }
    let owner = match configured_owner(
        staged(cfg, "user").map(|v| v.py_str()),
        staged(cfg, "group").map(|v| v.py_str()),
    ) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("{e}");
            return Some(ExitCode::from(1));
        }
    };
    if drops_privileges(&owner)
        && let Some((user, gid)) = &owner
    {
        if let Err(e) = nix::unistd::setegid(*gid).and_then(|_| nix::unistd::seteuid(user.uid)) {
            eprintln!("PermissionError: {}", messages::errno(e));
            return Some(ExitCode::from(1));
        }
        if let Some(path) = logfile.as_ref().map(config::Value::py_str) {
            let writable = |p: &std::path::Path| {
                nix::unistd::faccessat(
                    nix::fcntl::AT_FDCWD,
                    p,
                    nix::unistd::AccessFlags::W_OK,
                    nix::fcntl::AtFlags::AT_EACCESS,
                )
                .is_ok()
            };
            let p = std::path::Path::new(&path);
            let parent = p
                .parent()
                .filter(|d| !d.as_os_str().is_empty())
                .unwrap_or(std::path::Path::new("."));
            if !writable(p) && !writable(parent) {
                tracing::error!(
                    target: logging::ROOT_LOGGER,
                    critical = true,
                    "{}",
                    messages::logfile_not_writable(&path, user.uid.as_raw(), gid.as_raw())
                );
                return Some(ExitCode::SUCCESS);
            }
        }
    }
    if foreground {
        return None;
    }
    // python-daemon forks twice and the launcher exits 0 at once. irrd-ng
    // starts itself again, detached, which needs no fork in a process that
    // may already have threads.
    use std::os::unix::process::CommandExt;
    let mut cmd = std::process::Command::new("/proc/self/exe");
    cmd.arg0(args.first().cloned().unwrap_or_else(|| "irrd".into()))
        .args(args.get(1..).unwrap_or_default())
        .env(DAEMON_STAGE_ENV, "1")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    match cmd.spawn() {
        Ok(_) => Some(ExitCode::SUCCESS),
        Err(e) => {
            eprintln!("{}", messages::detach_failed(&e));
            Some(ExitCode::from(1))
        }
    }
}

/// `DaemonContext.open()`: no core dumps, umask 022, working directory
/// `/`, the real user and group back (undoing the launcher's `seteuid`),
/// and in the detached process a session of its own.
fn daemon_context(detached: bool) -> Result<(), String> {
    use nix::sys::resource::{Resource, setrlimit};
    let _ = setrlimit(Resource::RLIMIT_CORE, 0, 0);
    nix::sys::stat::umask(nix::sys::stat::Mode::from_bits_truncate(0o022));
    std::env::set_current_dir("/").map_err(|e| messages::chdir_failed(&e))?;
    let (uid, gid) = (nix::unistd::getuid(), nix::unistd::getgid());
    if nix::unistd::geteuid() != uid || nix::unistd::getegid() != gid {
        nix::unistd::setgid(gid)
            .and_then(|_| nix::unistd::setuid(uid))
            .map_err(messages::owner_change_failed)?;
    }
    if detached {
        let _ = nix::unistd::setsid();
    }
    Ok(())
}

/// `change_process_owner(uid, gid, initgroups=True)` after the whois
/// listener is bound. v4 (through python-daemon) only calls
/// `initgroups()`, which leaves the primary group at root; irrd-ng also
/// sets the configured group (a proposed divergence).
fn drop_privileges(user: &nix::unistd::User, gid: nix::unistd::Gid) -> Result<(), String> {
    let name = std::ffi::CString::new(user.name.clone()).map_err(|e| e.to_string())?;
    nix::unistd::initgroups(&name, gid)
        .and_then(|_| nix::unistd::setgid(gid))
        .and_then(|_| nix::unistd::setuid(user.uid))
        .map_err(messages::owner_change_failed)
}

fn bind_std(interface: &str, port: u16, backlog: i32) -> std::io::Result<std::net::TcpListener> {
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
    Ok(socket.into())
}

/// Replication settings from `ng_replication` (irrd-ng only).
struct Replication {
    serve: Option<replication::ServerSettings>,
    follow: Option<replication::FollowerSettings>,
}

fn replication_settings(
    cfg: &Configuration,
    store_path: &std::path::Path,
) -> Result<Replication, String> {
    let secret = settings::str_setting(cfg, "ng_replication.secret").filter(|s| !s.is_empty());
    let port = settings::int_setting(cfg, "ng_replication.port");
    let active_host =
        settings::str_setting(cfg, "ng_replication.active_host").filter(|s| !s.is_empty());
    let readonly = settings::truthy(cfg, "readonly_standby");
    if (port.is_some() || (readonly && active_host.is_some())) && secret.is_none() {
        return Err(messages::REPLICATION_NEEDS_SECRET.to_owned());
    }
    let secret = secret.unwrap_or_default().into_bytes();
    let serve = port.map(|p| {
        replication::ServerSettings::new(
            settings::str_setting(cfg, "ng_replication.interface").unwrap_or_else(|| "::0".into()),
            p as u16,
            secret.clone(),
        )
    });
    let follow = match (readonly, active_host) {
        (true, Some(host)) => Some(replication::FollowerSettings::new(
            host,
            settings::int_setting(cfg, "ng_replication.active_port").unwrap_or(0) as u16,
            secret,
            store_path,
        )),
        _ => None,
    };
    Ok(Replication { serve, follow })
}

/// The `irrd` tool.
pub(crate) fn run(args: &[OsString]) -> ExitCode {
    let a = match IRRD.parse(args.get(1..).unwrap_or_default()) {
        Parsed::Args(a) => a,
        Parsed::Help => return ExitCode::SUCCESS,
        Parsed::Error => return ExitCode::from(2),
    };
    let config_path = a.get("config_file_path").cloned();
    let foreground = a.contains_key("foreground");
    let detached = std::env::var_os(DAEMON_STAGE_ENV).is_some();
    // config_init(..., commit=False): fail fast on a bad configuration.
    let staging = match Configuration::load(config_path.as_deref()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{}", messages::configuration_error(&e.to_string()));
            return ExitCode::from(1);
        }
    };
    logging::install();
    if !detached && let Some(code) = launcher(&staging, args, foreground) {
        return code;
    }
    drop(staging);
    // The store path is irrd-ng's own; resolve it before leaving the
    // working directory.
    let store_path =
        std::path::absolute(settings::store_path()).unwrap_or_else(|_| settings::store_path());
    if let Err(e) = daemon_context(detached) {
        eprintln!("{e}");
        return ExitCode::from(1);
    }

    // config_init(...) inside the daemon context: read again, now relative
    // to `/`, and set up logging.
    let mut cfg = match Configuration::load(config_path.as_deref()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{}", messages::configuration_error(&e.to_string()));
            return ExitCode::from(1);
        }
    };
    if let Err(e) = logging::apply(&cfg) {
        eprintln!("{}", e.0);
        return ExitCode::from(1);
    }
    install_panic_hook();

    let owner = match configured_owner(
        settings::str_setting(&cfg, "user"),
        settings::str_setting(&cfg, "group"),
    ) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };
    let ci = std::env::var_os("CI").is_some_and(|v| !v.is_empty());
    if !ci && !drops_privileges(&owner) && nix::unistd::geteuid().is_root() {
        tracing::error!(target: logging::ROOT_LOGGER, critical = true, "{}", messages::ROOT_NEEDS_USER);
        return ExitCode::SUCCESS;
    }

    let piddir = settings::str_setting(&cfg, "piddir").unwrap_or_default();
    tracing::info!(target: LOG_TARGET, "{}", messages::SECURING_PID);
    let pidfile = match crate::pidfile::create(&piddir) {
        Ok(p) => p,
        Err(crate::pidfile::PidError::Locked(e)) => {
            tracing::error!(target: LOG_TARGET, "{}", messages::pid_lock_failed(&piddir, &e));
            return ExitCode::SUCCESS;
        }
        Err(crate::pidfile::PidError::Other(e)) => {
            tracing::error!(target: LOG_TARGET, "{}", messages::MAIN_PROCESS_ERROR);
            tracing::error!(target: LOG_TARGET, "{e}");
            eprintln!("{}", messages::TERMINATING_ON_SIGTERM);
            return ExitCode::from(1);
        }
    };
    tracing::info!(
        target: LOG_TARGET,
        "{}",
        messages::irrd_starting(crate::IRRD_VERSION, std::process::id(), &piddir)
    );
    if let Some(notice) = cfg.storage_notice() {
        tracing::info!(target: LOG_TARGET, "{notice}");
    }
    let _ = startup_time();
    let code = run_irrd(&mut cfg, &store_path, owner);
    drop(pidfile);
    tracing::info!(target: logging::ROOT_LOGGER, "{}", messages::MAIN_PROCESS_EXITING);
    code
}

/// `run_irrd()`: bind the whois listener (as root, for port 43), drop
/// privileges, then open the store and start everything else as the
/// configured user, as v4's whois process and main process do.
fn run_irrd(cfg: &mut Configuration, store_path: &std::path::Path, owner: Owner) -> ExitCode {
    let whois_interface =
        settings::str_setting(cfg, "server.whois.interface").unwrap_or_else(|| "::0".into());
    let whois_port = settings::int_setting(cfg, "server.whois.port").unwrap_or(43) as u16;
    tracing::info!(
        target: whois_server::LOG_TARGET,
        "{}",
        query::messages::log_starting_whois(&whois_interface, whois_port)
    );
    // socketserver.TCPServer.request_queue_size
    let whois_listener = match bind_std(&whois_interface, whois_port, 50) {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(target: LOG_TARGET, critical = true, "{}", messages::bind_failed("whois", &whois_interface, whois_port, &e));
            return ExitCode::from(1);
        }
    };
    let repl = match replication_settings(cfg, store_path) {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(target: LOG_TARGET, critical = true, "{e}");
            return ExitCode::from(1);
        }
    };
    let repl_listener = match &repl.serve {
        Some(s) => match bind_std(&s.interface, s.port, 16) {
            Ok(l) => Some(l),
            Err(e) => {
                tracing::error!(target: replication::LOG_TARGET, critical = true, "{}", replication::messages::bind_failed(&s.interface, s.port, &e));
                return ExitCode::from(1);
            }
        },
        None => None,
    };
    if drops_privileges(&owner)
        && let Some((user, gid)) = &owner
        && let Err(e) = drop_privileges(user, *gid)
    {
        tracing::error!(target: LOG_TARGET, "{}", messages::MAIN_PROCESS_ERROR);
        tracing::error!(target: LOG_TARGET, "{e}");
        return ExitCode::from(1);
    }

    let store = match Store::open(
        &StoreOptions::new(store_path),
        settings::store_settings(cfg),
    ) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(target: LOG_TARGET, critical = true, "{e}");
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };
    store.set_route_preference_hook(Some(rpki::route_preference_hook));
    tracing::info!(target: LOG_TARGET, "{}", messages::store_in(store_path));
    let readonly = settings::truthy(cfg, "readonly_standby");
    if repl.serve.is_some() {
        match store.enable_replication_log() {
            Ok(id) => {
                tracing::info!(target: replication::LOG_TARGET, "{}", replication::messages::log_enabled(&id));
            }
            Err(e) => {
                tracing::error!(target: replication::LOG_TARGET, critical = true, "{e}");
                return ExitCode::from(1);
            }
        }
    } else if !readonly
        && store.replication_state().is_ok_and(|s| s.id.is_some())
        && store.disable_replication_log().is_ok()
    {
        tracing::info!(target: replication::LOG_TARGET, "{}", replication::messages::LOG_DISABLED);
    }
    if readonly && repl.follow.is_none() {
        tracing::warn!(target: replication::LOG_TARGET, "{}", messages::STANDBY_WITHOUT_ACTIVE);
    }

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
    let code = runtime
        .block_on(async move { serve(cfg, store, whois_listener, repl_listener, repl).await });
    // Running imports are abandoned, as v4 terminates its children: their
    // write transactions never commit.
    runtime.shutdown_timeout(std::time::Duration::from_secs(3));
    code
}

/// `IRRD_MAIN_STARTUP_TIME`: when this process started, in seconds since
/// the epoch.
pub(crate) fn startup_time() -> i64 {
    static START: std::sync::OnceLock<i64> = std::sync::OnceLock::new();
    *START.get_or_init(|| store::Timestamp::now().unix_seconds())
}

async fn serve(
    cfg: &mut Configuration,
    store: Store,
    whois_listener: std::net::TcpListener,
    repl_listener: Option<std::net::TcpListener>,
    repl: Replication,
) -> ExitCode {
    let nrtm: Arc<dyn query::NrtmV3> = Arc::new(query::NrtmServer);
    let query_settings = Arc::new(settings::query_settings(cfg));
    let max_connections = settings::int_setting(cfg, "server.whois.max_connections")
        .unwrap_or(10)
        .max(1) as usize;
    let http_interface =
        settings::str_setting(cfg, "server.http.interface").unwrap_or_else(|| "::0".into());
    let http_port = settings::int_setting(cfg, "server.http.port").unwrap_or(8080) as u16;

    let whois_listener = match tokio::net::TcpListener::from_std(whois_listener) {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(target: LOG_TARGET, critical = true, "{e}");
            return ExitCode::from(1);
        }
    };
    // v4 starts uvicorn after the main process dropped privileges, so the
    // HTTP port is bound as the configured user.
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
    let events = http::Events::new();
    store.set_event_listener(Some(events.store_listener()));
    events.spawn_watcher(store.clone());
    // uvicorn takes forwarded_allow_ips when it starts; a SIGHUP restarts
    // its workers but not that setting.
    let startup_http = http_settings(cfg);
    let forwarded_allowed_ips = startup_http.forwarded_allowed_ips.clone();
    let http_state = Arc::new(http::HttpState {
        store: store.clone(),
        query: RwLock::new(query_settings),
        http: RwLock::new(Arc::new(startup_http)),
        nrtm,
        submit: RwLock::new(Arc::new(settings::submit_settings(cfg))),
        startup_time: startup_time(),
        events,
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
        shutdown_rx.clone(),
    ));
    if let (Some(listener), Some(s)) = (repl_listener, repl.serve) {
        match tokio::net::TcpListener::from_std(listener) {
            Ok(l) => {
                tracing::info!(target: replication::LOG_TARGET, "{}", replication::messages::listening(&s.interface, s.port));
                tokio::spawn(replication::server::serve(
                    l,
                    store.clone(),
                    Arc::new(s),
                    shutdown_rx.clone(),
                ));
            }
            Err(e) => tracing::error!(target: replication::LOG_TARGET, "{e}"),
        }
    }
    // The standby's follower stops when a SIGHUP turns readonly_standby
    // off (promotion), so nothing replicated lands on a writable store.
    let (follow_stop_tx, follow_stop_rx) = tokio::sync::watch::channel(false);
    let mut follower = repl.follow.map(|f| {
        tokio::spawn(replication::follower::run(
            store.clone(),
            Arc::new(f),
            follow_stop_rx,
        ))
    });

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
                    // _commit_staging(): the root logger's level.
                    logging::reload_level(cfg);
                    if !settings::truthy(cfg, "readonly_standby")
                        && let Some(f) = follower.take()
                    {
                        let _ = follow_stop_tx.send(true);
                        let _ = f.await;
                        tracing::warn!(target: replication::LOG_TARGET, "{}", messages::STANDBY_PROMOTED);
                    }
                    let qs = Arc::new(settings::query_settings(cfg));
                    store.set_settings(settings::store_settings(cfg));
                    if let Ok(mut s) = whois.settings.write() {
                        *s = qs.clone();
                    }
                    if let Ok(mut s) = http_state.query.write() {
                        *s = qs;
                    }
                    if let Ok(mut s) = http_state.http.write() {
                        let mut h = http_settings(cfg);
                        h.forwarded_allowed_ips = forwarded_allowed_ips.clone();
                        *s = Arc::new(h);
                    }
                    if let Ok(mut s) = http_state.submit.write() {
                        *s = Arc::new(settings::submit_settings(cfg));
                    }
                    let _ = mirror_tx.send(Arc::new(settings::mirror_settings(cfg)));
                }
            }
        }
    }
    // v4's order: the scheduler terminates its runners ("MirrorScheduler
    // terminating children"), the whois process logs through the root
    // logger, then the main process waits for the rest.
    let _ = shutdown_tx.send(true);
    let _ = follow_stop_tx.send(true);
    let _ = tokio::time::timeout(std::time::Duration::from_secs(3), scheduler).await;
    tracing::info!(target: logging::ROOT_LOGGER, "{}", messages::WHOIS_SHUTTING_DOWN);
    tracing::debug!(target: logging::ROOT_LOGGER, "{}", messages::WAITING_FOR_CHILDREN);
    if let Some(f) = follower {
        let _ = tokio::time::timeout(std::time::Duration::from_secs(3), f).await;
    }
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
