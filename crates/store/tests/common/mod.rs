#![allow(dead_code, unreachable_pub)]

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use store::{
    Json, NewRpslObject, RoutePreferenceStatus, RpkiStatus, ScopeFilterStatus, SourceSettings,
    Store, StoreOptions, StoreSettings,
};

static COUNTER: AtomicUsize = AtomicUsize::new(0);

/// A fresh directory under the system temp dir, removed on drop.
pub struct TempDir(pub PathBuf);

impl TempDir {
    pub fn new(tag: &str) -> Self {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let p =
            std::env::temp_dir().join(format!("irrd-ng-store-{tag}-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).expect("temp dir");
        TempDir(p)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub fn settings(sources: &[(&str, SourceSettings)]) -> StoreSettings {
    StoreSettings {
        sources: sources
            .iter()
            .map(|(n, s)| ((*n).to_owned(), s.clone()))
            .collect(),
        ..StoreSettings::default()
    }
}

pub fn open(dir: &TempDir, settings: StoreSettings) -> Store {
    let mut o = StoreOptions::new(&dir.0);
    o.initial_map_size = 64 << 20;
    Store::open(&o, settings).expect("open store")
}

/// A route object as v4's tests mock it.
pub fn route(pk: &str, source: &str, prefix: &str, asn: u32, mnt: &str) -> NewRpslObject {
    let p = store::IpPrefix::parse(prefix).expect("prefix");
    let last = p.last();
    let ip_last = match p.addr {
        std::net::IpAddr::V4(_) => std::net::IpAddr::V4(std::net::Ipv4Addr::from(last as u32)),
        std::net::IpAddr::V6(_) => std::net::IpAddr::V6(std::net::Ipv6Addr::from(last)),
    };
    NewRpslObject {
        rpsl_pk: pk.to_owned(),
        source: source.to_owned(),
        object_class: "route".to_owned(),
        parsed_data: Json::canonical(&format!(
            r#"{{"mnt-by": ["{mnt}"], "source": "{source}", "origin": "AS{asn}"}}"#
        ))
        .expect("json"),
        object_text: "object-text".to_owned(),
        ip_first: Some(p.addr),
        ip_last: Some(ip_last),
        prefix: Some(p),
        prefix_length: Some(u32::from(p.len)),
        asn_first: Some(asn),
        asn_last: Some(asn),
        rpki_status: RpkiStatus::NotFound,
        scopefilter_status: ScopeFilterStatus::InScope,
        route_preference_status: RoutePreferenceStatus::Visible,
    }
}

pub fn simple(pk: &str, class: &str, source: &str) -> NewRpslObject {
    NewRpslObject {
        rpsl_pk: pk.to_owned(),
        source: source.to_owned(),
        object_class: class.to_owned(),
        parsed_data: Json::canonical(&format!(
            r#"{{"mnt-by": ["MNT-TEST"], "source": "{source}"}}"#
        ))
        .expect("json"),
        object_text: "object-text".to_owned(),
        ip_first: None,
        ip_last: None,
        prefix: None,
        prefix_length: None,
        asn_first: None,
        asn_last: None,
        rpki_status: RpkiStatus::NotFound,
        scopefilter_status: ScopeFilterStatus::InScope,
        route_preference_status: RoutePreferenceStatus::Visible,
    }
}
