//! `irrd/rpki/validators.py` `BulkRouteROAValidator`.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use store::{ReadView, Result, RpkiStatus, StatusChange};

use crate::importer::{RPKI_IRR_PSEUDO_SOURCE, Roa};

/// The route objects whose RPKI status changes, as v4's
/// `validate_all_routes()` returns them: (now valid, now invalid, now
/// not_found), each with `old_status` and the columns the journal needs.
pub type RpkiChanges = (
    Vec<StatusChange<RpkiStatus>>,
    Vec<StatusChange<RpkiStatus>>,
    Vec<StatusChange<RpkiStatus>>,
);

/// Validates routes against every ROA in the store, as v4's bulk
/// validator does with its trie.
#[derive(Debug, Default)]
pub struct BulkRouteRoaValidator {
    excluded_sources: HashSet<String>,
    /// (ip version, prefix length, network) -> [(asn, max_length)]
    roas: HashMap<(u8, u8, u128), Vec<(i64, i64)>>,
}

fn mask(v: u128, len: u8, bits: u32) -> u128 {
    if len == 0 {
        return 0;
    }
    let max = if bits == 128 {
        u128::MAX
    } else {
        (1u128 << bits) - 1
    };
    if u32::from(len) >= bits {
        return v & max;
    }
    v & (max & !(max >> u32::from(len)))
}

impl BulkRouteRoaValidator {
    /// Build from the store's `roa_object` table. `excluded_sources` are
    /// the sources with `rpki_excluded` set (v4 reads the source settings
    /// dict directly).
    pub fn from_store(view: &ReadView<'_>, excluded_sources: HashSet<String>) -> Result<Self> {
        let mut roas: HashMap<(u8, u8, u128), Vec<(i64, i64)>> = HashMap::new();
        for roa in view.roas()? {
            roas.entry((roa.ip_version, roa.prefix.len, roa.prefix.first()))
                .or_default()
                .push((roa.asn, roa.max_length));
        }
        Ok(BulkRouteRoaValidator {
            excluded_sources,
            roas,
        })
    }

    /// `BulkRouteROAValidator(dh, roas)`: from the ROAs just imported.
    pub fn from_roas(roas: &[Roa], excluded_sources: HashSet<String>) -> Self {
        let mut map: HashMap<(u8, u8, u128), Vec<(i64, i64)>> = HashMap::new();
        for roa in roas {
            if let Some(p) = roa.ip_prefix() {
                map.entry((p.version(), p.len, p.first()))
                    .or_default()
                    .push((i64::from(roa.asn), roa.max_length));
            }
        }
        BulkRouteRoaValidator {
            excluded_sources,
            roas: map,
        }
    }

    /// `validate_all_routes(sources=None)`: every route and route6 object
    /// outside the RPKI pseudo source whose status would change. The lists
    /// are in store order; v4's come in PostgreSQL's unordered scan order.
    pub fn validate_all_routes(&self, view: &ReadView<'_>) -> Result<RpkiChanges> {
        let (mut valid, mut invalid, mut not_found) = (Vec::new(), Vec::new(), Vec::new());
        for source in view.object_sources()? {
            if source == RPKI_IRR_PSEUDO_SOURCE {
                continue;
            }
            for class in ["route", "route6"] {
                for item in view.objects(Some(&source), Some(class))? {
                    let (_, o) = item?;
                    let (Some(ip), Some(len)) = (o.ip_first, o.prefix_length) else {
                        continue;
                    };
                    // A missing origin matches no ROA, as AS0 never does.
                    let new = self.validate_route(ip, len, o.asn_first.unwrap_or(0), o.source);
                    if new == o.rpki_status {
                        continue;
                    }
                    let change = StatusChange {
                        pk: o.pk,
                        rpsl_pk: o.rpsl_pk.to_owned(),
                        source: o.source.to_owned(),
                        object_class: o.object_class.to_owned(),
                        object_text: o.object_text.to_owned(),
                        prefix: o.prefix,
                        old_status: o.rpki_status,
                        rpki_status: new,
                        scopefilter_status: o.scopefilter_status,
                        route_preference_status: o.route_preference_status,
                    };
                    match new {
                        RpkiStatus::Valid => valid.push(change),
                        RpkiStatus::Invalid => invalid.push(change),
                        RpkiStatus::NotFound => not_found.push(change),
                    }
                }
            }
        }
        Ok((valid, invalid, not_found))
    }

    /// `validate_route(prefix_ip, prefix_length, prefix_asn, source)`.
    pub fn validate_route(
        &self,
        prefix_ip: IpAddr,
        prefix_length: u32,
        prefix_asn: u32,
        source: &str,
    ) -> RpkiStatus {
        if self.excluded_sources.contains(source) {
            return RpkiStatus::NotFound;
        }
        let (ver, bits, v) = match prefix_ip {
            IpAddr::V4(a) => (4u8, 32u32, u128::from(u32::from(a))),
            IpAddr::V6(a) => (6u8, 128u32, u128::from(a)),
        };
        let max_len = prefix_length.min(bits) as u8;
        let mut covered = false;
        for len in 0..=max_len {
            if let Some(list) = self.roas.get(&(ver, len, mask(v, len, bits))) {
                covered = true;
                for (asn, max_length) in list {
                    if *asn != 0
                        && *asn == i64::from(prefix_asn)
                        && i64::from(prefix_length) <= *max_length
                    {
                        return RpkiStatus::Valid;
                    }
                }
            }
        }
        if covered {
            RpkiStatus::Invalid
        } else {
            RpkiStatus::NotFound
        }
    }

    /// Whether any ROA is loaded.
    pub fn is_empty(&self) -> bool {
        self.roas.is_empty()
    }
}

/// `SingleRouteROAValidator.validate_route(route, asn, source)`: look up
/// the ROAs covering one route in the store, as v4 does for each NRTM
/// operation. `rpki_excluded` is `get_setting("sources.{source}.rpki_excluded")`.
pub fn validate_route_single(
    view: &ReadView<'_>,
    route: &store::IpPrefix,
    asn: u32,
    rpki_excluded: bool,
) -> Result<RpkiStatus> {
    if rpki_excluded {
        return Ok(RpkiStatus::NotFound);
    }
    let covering = view.roas_covering(route)?;
    if covering.is_empty() {
        return Ok(RpkiStatus::NotFound);
    }
    for roa in &covering {
        if roa.asn != 0 && roa.asn == i64::from(asn) && i64::from(route.len) <= roa.max_length {
            return Ok(RpkiStatus::Valid);
        }
    }
    Ok(RpkiStatus::Invalid)
}

#[cfg(test)]
mod tests {
    use super::*;

    type Entry = ((u8, u8, u128), (i64, i64));

    fn validator(roas: &[Entry]) -> BulkRouteRoaValidator {
        let mut v = BulkRouteRoaValidator::default();
        for (k, r) in roas {
            v.roas.entry(*k).or_default().push(*r);
        }
        v.excluded_sources.insert("EXCL".into());
        v
    }

    // From v4's test_validators.py TestBulkRouteROAValidator: a /24 ROA
    // for AS65546 max length 25 covering 192.0.2.0/24.
    #[test]
    fn valid_invalid_not_found() {
        let net = u128::from(u32::from(std::net::Ipv4Addr::new(192, 0, 2, 0)));
        let v = validator(&[((4, 24, net), (65546, 25)), ((4, 0, 0), (0, 32))]);
        let ip: IpAddr = "192.0.2.0".parse().expect("ip");
        assert_eq!(v.validate_route(ip, 24, 65546, "TEST"), RpkiStatus::Valid);
        assert_eq!(v.validate_route(ip, 25, 65546, "TEST"), RpkiStatus::Valid);
        assert_eq!(v.validate_route(ip, 26, 65546, "TEST"), RpkiStatus::Invalid);
        assert_eq!(v.validate_route(ip, 24, 65547, "TEST"), RpkiStatus::Invalid);
        assert_eq!(
            v.validate_route(ip, 24, 65547, "EXCL"),
            RpkiStatus::NotFound
        );
        let empty = validator(&[]);
        assert_eq!(
            empty.validate_route(ip, 24, 65546, "TEST"),
            RpkiStatus::NotFound
        );
    }
}

#[cfg(test)]
mod full_length {
    use super::*;

    #[test]
    fn masks_at_zero_and_full_length() {
        assert_eq!(mask(u128::MAX, 128, 128), u128::MAX);
        assert_eq!(mask(u128::MAX, 0, 128), 0);
        assert_eq!(mask(0xFFFF_FFFF, 32, 32), 0xFFFF_FFFF);
        let mut v = BulkRouteRoaValidator::default();
        let a = 0x2a0c_9c80u128 << 96;
        v.roas.entry((6, 128, a)).or_default().push((204760, 128));
        let ip: IpAddr = "2a0c:9c80::".parse().expect("ip");
        assert_eq!(v.validate_route(ip, 128, 204760, "X"), RpkiStatus::Valid);
    }
}
