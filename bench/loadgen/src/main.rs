//! Closed-loop whois load generator for `bench/load.sh`.
//!
//! ```text
//! loadgen --target HOST:PORT --mix FILE [--concurrency N] [--duration S]
//!         [--warmup S] [--timeout S] [--seed N] [--count N]
//! ```
//!
//! The mix file has one entry per line, `weight<TAB>class<TAB>mode<TAB>query`:
//!
//! - `mode` is `single` (a new connection per query, read to the server's
//!   close, the way most whois clients ask) or `keepalive` (one `!!`
//!   connection per worker, kept open, answers read by v4's framing:
//!   `A<len>`/`C`/`D`/`F` for IRRd style, up to `\n\n\n` for RIPE style).
//! - `class` groups results in the report.
//! - Several queries for one keepalive turn can be joined with ` ;; `; they
//!   are sent one after another and timed as one round trip each.
//!
//! Each worker thread picks entries by weight with its own seeded PRNG, so a
//! run is reproducible, sends one query, waits for the full answer, records
//! the latency, and repeats until the deadline. Latencies during `--warmup`
//! are discarded. With `--count N` each worker runs exactly N mix entries
//! instead of running until the deadline (for timing single commands). The report is one JSON object on stdout: per class and in
//! total, completed queries, errors, bytes, QPS and p50/p90/p99/max in
//! microseconds.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::process::ExitCode;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
struct Entry {
    weight: u32,
    class: String,
    keepalive: bool,
    queries: Vec<Vec<u8>>,
}

#[derive(Debug, Default)]
struct Stats {
    lat_us: Vec<u32>,
    errors: u64,
    bytes: u64,
}

#[derive(Debug)]
struct Args {
    target: SocketAddr,
    mix: Vec<Entry>,
    concurrency: usize,
    duration: Duration,
    warmup: Duration,
    timeout: Duration,
    seed: u64,
    count: Option<u64>,
}

fn usage() -> String {
    "usage: loadgen --target HOST:PORT --mix FILE [--concurrency N] [--duration S] [--warmup S] [--timeout S] [--seed N] [--count N]".to_string()
}

fn parse_mix(path: &str) -> Result<Vec<Entry>, String> {
    let file = std::fs::File::open(path).map_err(|e| format!("{path}: {e}"))?;
    let mut out = Vec::new();
    for (n, line) in BufReader::new(file).lines().enumerate() {
        let line = line.map_err(|e| format!("{path}: {e}"))?;
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.splitn(4, '\t').collect();
        let [weight, class, mode, query] = parts[..] else {
            return Err(format!(
                "{path}:{}: expected weight<TAB>class<TAB>mode<TAB>query",
                n + 1
            ));
        };
        let weight: u32 = weight
            .parse()
            .map_err(|_| format!("{path}:{}: bad weight", n + 1))?;
        let keepalive = match mode {
            "single" => false,
            "keepalive" => true,
            _ => {
                return Err(format!(
                    "{path}:{}: mode must be single or keepalive",
                    n + 1
                ));
            }
        };
        let queries = query
            .split(" ;; ")
            .map(|q| {
                let mut b = q.as_bytes().to_vec();
                b.push(b'\n');
                b
            })
            .collect();
        if weight > 0 {
            out.push(Entry {
                weight,
                class: class.to_string(),
                keepalive,
                queries,
            });
        }
    }
    if out.is_empty() {
        return Err(format!("{path}: no entries"));
    }
    Ok(out)
}

fn parse_args() -> Result<Args, String> {
    let mut target = None;
    let mut mix = None;
    let mut concurrency = 8usize;
    let mut duration = 30f64;
    let mut warmup = 5f64;
    let mut timeout = 120f64;
    let mut seed = 1u64;
    let mut count = None;
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        let mut val = || it.next().ok_or_else(usage);
        match a.as_str() {
            "--target" => {
                let v = val()?;
                target = v.to_socket_addrs().map_err(|e| format!("{v}: {e}"))?.next();
            }
            "--mix" => mix = Some(parse_mix(&val()?)?),
            "--concurrency" => concurrency = val()?.parse().map_err(|_| usage())?,
            "--duration" => duration = val()?.parse().map_err(|_| usage())?,
            "--warmup" => warmup = val()?.parse().map_err(|_| usage())?,
            "--timeout" => timeout = val()?.parse().map_err(|_| usage())?,
            "--seed" => seed = val()?.parse().map_err(|_| usage())?,
            "--count" => count = Some(val()?.parse().map_err(|_| usage())?),
            _ => return Err(usage()),
        }
    }
    Ok(Args {
        target: target.ok_or_else(usage)?,
        mix: mix.ok_or_else(usage)?,
        concurrency: concurrency.max(1),
        duration: Duration::from_secs_f64(duration),
        warmup: Duration::from_secs_f64(warmup),
        timeout: Duration::from_secs_f64(timeout),
        seed,
        count,
    })
}

/// xorshift64*: small, fast and good enough to pick mix entries.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
}

fn pick<'a>(mix: &'a [Entry], total: u64, rng: &mut Rng) -> &'a Entry {
    let mut r = rng.next() % total;
    for e in mix {
        if r < u64::from(e.weight) {
            return e;
        }
        r -= u64::from(e.weight);
    }
    &mix[mix.len() - 1]
}

/// True when `buf` holds one complete answer to `query` in keepalive mode.
fn complete(query: &[u8], buf: &[u8]) -> bool {
    let irrd = query.first() == Some(&b'!');
    if !irrd {
        return buf.windows(3).any(|w| w == b"\n\n\n");
    }
    match buf.first() {
        Some(b'A') => {
            let Some(nl) = buf.iter().position(|&c| c == b'\n') else {
                return false;
            };
            let len: usize = std::str::from_utf8(&buf[1..nl])
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            buf.len() >= nl + 1 + len + 2
        }
        Some(b'C' | b'D') => buf.len() >= 2,
        Some(_) => buf.contains(&b'\n'),
        None => false,
    }
}

struct Session {
    stream: TcpStream,
    buf: Vec<u8>,
}

fn open_keepalive(addr: &SocketAddr, timeout: Duration) -> std::io::Result<Session> {
    let stream = TcpStream::connect_timeout(addr, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_nodelay(true)?;
    let mut s = Session {
        stream,
        buf: Vec::with_capacity(1 << 16),
    };
    s.stream.write_all(b"!!\n")?;
    Ok(s)
}

fn ask_keepalive(s: &mut Session, query: &[u8]) -> std::io::Result<usize> {
    s.stream.write_all(query)?;
    s.buf.clear();
    let mut chunk = [0u8; 1 << 16];
    loop {
        let n = s.stream.read(&mut chunk)?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "closed",
            ));
        }
        s.buf.extend_from_slice(&chunk[..n]);
        if complete(query, &s.buf) {
            return Ok(s.buf.len());
        }
    }
}

fn ask_single(addr: &SocketAddr, query: &[u8], timeout: Duration) -> std::io::Result<usize> {
    let mut stream = TcpStream::connect_timeout(addr, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_nodelay(true)?;
    stream.write_all(query)?;
    let mut total = 0;
    let mut chunk = [0u8; 1 << 16];
    loop {
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            return Ok(total);
        }
        total += n;
    }
}

fn worker(args: Arc<Args>, id: usize, start: Instant) -> BTreeMap<String, Stats> {
    let mut stats: BTreeMap<String, Stats> = BTreeMap::new();
    let mut rng = Rng(args
        .seed
        .wrapping_mul(0x9e37_79b9_7f4a_7c15)
        .wrapping_add(id as u64 + 1)
        | 1);
    let total: u64 = args.mix.iter().map(|e| u64::from(e.weight)).sum();
    let mut session: Option<Session> = None;
    let deadline = start + args.warmup + args.duration;
    let mut done = 0u64;
    while match args.count {
        Some(n) => done < n,
        None => Instant::now() < deadline,
    } {
        done += 1;
        let entry = pick(&args.mix, total, &mut rng);
        for q in &entry.queries {
            let t0 = Instant::now();
            let res = if entry.keepalive {
                if session.is_none() {
                    session = open_keepalive(&args.target, args.timeout).ok();
                }
                match session.as_mut() {
                    Some(s) => ask_keepalive(s, q),
                    None => Err(std::io::Error::other("connect failed")),
                }
            } else {
                ask_single(&args.target, q, args.timeout)
            };
            let elapsed = t0.elapsed();
            let measuring = t0 >= start + args.warmup;
            let st = stats.entry(entry.class.clone()).or_default();
            match res {
                Ok(n) => {
                    if measuring {
                        st.lat_us
                            .push(u32::try_from(elapsed.as_micros()).unwrap_or(u32::MAX));
                        st.bytes += n as u64;
                    }
                }
                Err(_) => {
                    if measuring {
                        st.errors += 1;
                    }
                    if entry.keepalive {
                        session = None;
                    }
                }
            }
        }
    }
    stats
}

fn pct(sorted: &[u32], p: f64) -> u32 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((sorted.len() as f64 - 1.0) * p).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

fn report(name: &str, st: &mut Stats, secs: f64, out: &mut String) {
    st.lat_us.sort_unstable();
    let n = st.lat_us.len();
    let _ = write!(
        out,
        "\"{name}\": {{\"queries\": {n}, \"errors\": {}, \"bytes\": {}, \"qps\": {:.1}, \"p50_us\": {}, \"p90_us\": {}, \"p99_us\": {}, \"max_us\": {}}}",
        st.errors,
        st.bytes,
        n as f64 / secs,
        pct(&st.lat_us, 0.50),
        pct(&st.lat_us, 0.90),
        pct(&st.lat_us, 0.99),
        st.lat_us.last().copied().unwrap_or(0),
    );
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => Arc::new(a),
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    let start = Instant::now();
    let handles: Vec<_> = (0..args.concurrency)
        .map(|id| {
            let a = Arc::clone(&args);
            thread::spawn(move || worker(a, id, start))
        })
        .collect();
    let mut merged: BTreeMap<String, Stats> = BTreeMap::new();
    for h in handles {
        let Ok(per) = h.join() else {
            eprintln!("worker panicked");
            return ExitCode::from(1);
        };
        for (k, mut v) in per {
            let m = merged.entry(k).or_default();
            m.lat_us.append(&mut v.lat_us);
            m.errors += v.errors;
            m.bytes += v.bytes;
        }
    }
    let secs = args.duration.as_secs_f64();
    let mut all = Stats::default();
    let mut out = String::from("{");
    let _ = write!(
        out,
        "\"concurrency\": {}, \"duration_s\": {secs}, \"classes\": {{",
        args.concurrency
    );
    let mut first = true;
    for (k, v) in &mut merged {
        all.lat_us.extend_from_slice(&v.lat_us);
        all.errors += v.errors;
        all.bytes += v.bytes;
        if !first {
            out.push_str(", ");
        }
        first = false;
        report(k, v, secs, &mut out);
    }
    out.push_str("}, ");
    report("total", &mut all, secs, &mut out);
    out.push('}');
    println!("{out}");
    ExitCode::SUCCESS
}
