//! Admission control on the active, before a standby has proved the
//! secret: a cap on connections still in the handshake, overall and per
//! address, and a lockout for an address that keeps failing it.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// Failed handshakes an address may have before it is locked out.
pub(crate) const MAX_FAILURES: u32 = 5;
/// How long a lockout lasts, counted from the last failure; failures older
/// than this are forgotten.
pub(crate) const LOCKOUT: Duration = Duration::from_secs(60);
/// The most addresses whose failures are remembered at once. Past this,
/// failures from new addresses are not counted until older ones expire, so
/// a flood of addresses cannot grow the table without bound.
const MAX_TRACKED: usize = 4096;

/// Why a connection was not admitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// Too many connections are waiting to prove the secret.
    Busy,
    /// Too many of them from this address.
    BusyPeer,
    /// This address failed the handshake too often.
    LockedOut,
}

#[derive(Debug, Default)]
struct State {
    pending: usize,
    per_ip: HashMap<IpAddr, usize>,
    failures: HashMap<IpAddr, (u32, Instant)>,
}

/// Shared by every connection of one server.
#[derive(Debug)]
pub(crate) struct Gate {
    max: usize,
    max_per_ip: usize,
    state: Mutex<State>,
}

/// One admitted connection, counted until it proves the secret or ends.
#[derive(Debug)]
pub(crate) struct Pending {
    gate: Arc<Gate>,
    ip: IpAddr,
}

impl Drop for Pending {
    fn drop(&mut self) {
        let mut st = self.gate.lock();
        st.pending = st.pending.saturating_sub(1);
        if let Some(n) = st.per_ip.get_mut(&self.ip) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                st.per_ip.remove(&self.ip);
            }
        }
    }
}

/// The address limits apply to: IPv4-mapped IPv6 addresses as IPv4, and
/// other IPv6 addresses by their /64, the smallest block a site is
/// usually given.
pub(crate) fn bucket(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => {
                let s = v6.segments();
                IpAddr::V6(std::net::Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
            }
        },
    }
}

impl Gate {
    pub(crate) fn new(max: usize, max_per_ip: usize) -> Arc<Gate> {
        Arc::new(Gate {
            max: max.max(1),
            max_per_ip: max_per_ip.max(1),
            state: Mutex::new(State::default()),
        })
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Admit a new connection from `ip`, or say why not.
    pub(crate) fn admit(self: &Arc<Self>, ip: IpAddr, now: Instant) -> Result<Pending, Refusal> {
        let ip = bucket(ip);
        let mut st = self.lock();
        if let Some(&(count, last)) = st.failures.get(&ip) {
            if now.saturating_duration_since(last) >= LOCKOUT {
                st.failures.remove(&ip);
            } else if count >= MAX_FAILURES {
                return Err(Refusal::LockedOut);
            }
        }
        if st.pending >= self.max {
            return Err(Refusal::Busy);
        }
        let n = st.per_ip.entry(ip).or_insert(0);
        if *n >= self.max_per_ip {
            return Err(Refusal::BusyPeer);
        }
        *n += 1;
        st.pending += 1;
        Ok(Pending {
            gate: self.clone(),
            ip,
        })
    }

    /// Count a failed proof from `ip`. True when this failure locks the
    /// address out.
    pub(crate) fn failed(&self, ip: IpAddr, now: Instant) -> bool {
        let ip = bucket(ip);
        let mut st = self.lock();
        if st.failures.len() >= MAX_TRACKED && !st.failures.contains_key(&ip) {
            st.failures
                .retain(|_, (_, last)| now.saturating_duration_since(*last) < LOCKOUT);
            if st.failures.len() >= MAX_TRACKED {
                return false;
            }
        }
        let e = st.failures.entry(ip).or_insert((0, now));
        if now.saturating_duration_since(e.1) >= LOCKOUT {
            e.0 = 0;
        }
        e.0 += 1;
        e.1 = now;
        e.0 == MAX_FAILURES
    }

    /// Forget the failures of an address that has now proved the secret.
    pub(crate) fn succeeded(&self, ip: IpAddr) {
        self.lock().failures.remove(&bucket(ip));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("ip")
    }

    #[test]
    fn caps_pending_connections() {
        let gate = Gate::new(3, 2);
        let now = Instant::now();
        let a1 = gate.admit(ip("192.0.2.1"), now).expect("a1");
        let _a2 = gate.admit(ip("192.0.2.1"), now).expect("a2");
        assert_eq!(
            gate.admit(ip("192.0.2.1"), now).err(),
            Some(Refusal::BusyPeer)
        );
        let _b1 = gate.admit(ip("192.0.2.2"), now).expect("b1");
        assert_eq!(gate.admit(ip("192.0.2.3"), now).err(), Some(Refusal::Busy));
        drop(a1);
        let _a3 = gate
            .admit(ip("192.0.2.1"), now)
            .expect("a slot is free again");
    }

    #[test]
    fn ipv6_counts_by_64_and_mapped_as_ipv4() {
        let gate = Gate::new(10, 1);
        let now = Instant::now();
        let _a = gate.admit(ip("2001:db8:1:2::1"), now).expect("a");
        assert_eq!(
            gate.admit(ip("2001:db8:1:2:ffff::9"), now).err(),
            Some(Refusal::BusyPeer)
        );
        let _b = gate.admit(ip("2001:db8:1:3::1"), now).expect("other /64");
        let _c = gate.admit(ip("192.0.2.1"), now).expect("c");
        assert_eq!(
            gate.admit(ip("::ffff:192.0.2.1"), now).err(),
            Some(Refusal::BusyPeer)
        );
    }

    #[test]
    fn locks_out_after_repeated_failures() {
        let gate = Gate::new(10, 10);
        let t0 = Instant::now();
        let peer = ip("192.0.2.7");
        for i in 1..MAX_FAILURES {
            assert!(!gate.failed(peer, t0), "failure {i}");
            assert!(gate.admit(peer, t0).is_ok());
        }
        assert!(gate.failed(peer, t0), "this one locks it out");
        assert_eq!(gate.admit(peer, t0).err(), Some(Refusal::LockedOut));
        // Other addresses are unaffected.
        assert!(gate.admit(ip("192.0.2.8"), t0).is_ok());
        // Still locked just before the lockout ends, free after.
        let almost = t0 + LOCKOUT - Duration::from_millis(1);
        assert_eq!(gate.admit(peer, almost).err(), Some(Refusal::LockedOut));
        assert!(gate.admit(peer, t0 + LOCKOUT).is_ok());
        // And the count started again.
        assert!(!gate.failed(peer, t0 + LOCKOUT));
    }

    #[test]
    fn success_forgets_failures() {
        let gate = Gate::new(10, 10);
        let now = Instant::now();
        let peer = ip("192.0.2.9");
        for _ in 1..MAX_FAILURES {
            gate.failed(peer, now);
        }
        gate.succeeded(peer);
        assert!(!gate.failed(peer, now));
        assert!(gate.admit(peer, now).is_ok());
    }

    #[test]
    fn failure_table_is_bounded() {
        let gate = Gate::new(10, 10);
        let now = Instant::now();
        for i in 0..(MAX_TRACKED as u32 + 100) {
            gate.failed(IpAddr::V4(std::net::Ipv4Addr::from(i)), now);
        }
        assert_eq!(gate.lock().failures.len(), MAX_TRACKED);
        // Once they expire, new addresses are tracked again.
        gate.failed(ip("198.51.100.1"), now + LOCKOUT);
        assert_eq!(gate.lock().failures.len(), 1);
    }
}
