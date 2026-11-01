//! whois queries, IRRd and RIPE style, one per line, in one session (so
//! `!!`, `!t` and `-k` carry over), against a small store.
#![no_main]

use std::sync::{Arc, OnceLock};

use libfuzzer_sys::fuzz_target;
use nrtm::file_import::{self, ImportSettings, ParseEnv, apply_file_import};
use query::{NrtmServer, QuerySettings, SourceQuerySettings, WhoisSession};
use rpki::{ScopeFilterConfig, ScopeFilterValidator};
use rpsl::{Keyring, RpslSettings};
use store::{Store, StoreOptions, StoreSettings};

const DATA: &str = "\
route:          192.0.2.0/24
origin:         AS65537
mnt-by:         MNT-A
member-of:      RS-REF
source:         TEST

route6:         2001:db8::/32
origin:         AS65537
mnt-by:         MNT-A
source:         TEST

aut-num:        AS65537
as-name:        A
member-of:      AS-REF
mnt-by:         MNT-A
source:         TEST

as-set:         AS-TOP
members:        AS65537, AS-MID, AS-LOOP
mnt-by:         MNT-A
source:         TEST

as-set:         AS-MID
members:        AS65538, AS-TOP, AS-MISSING
mnt-by:         MNT-A
source:         TEST

as-set:         AS-LOOP
members:        AS-LOOP
mnt-by:         MNT-A
source:         TEST

as-set:         AS-REF
mbrs-by-ref:    MNT-A
mnt-by:         MNT-A
source:         TEST

route-set:      RS-TOP
members:        198.51.100.0/24^+, AS65537, RS-REF
mnt-by:         MNT-A
source:         TEST

route-set:      RS-REF
mbrs-by-ref:    ANY
mnt-by:         MNT-A
source:         TEST

mntner:         MNT-A
auth:           CRYPT-PW LEuuhsBJNFV0Q
upd-to:         a@example.net
mnt-by:         MNT-A
source:         TEST
";

fn setup() -> &'static (Store, Arc<QuerySettings>) {
    static S: OnceLock<(Store, Arc<QuerySettings>)> = OnceLock::new();
    S.get_or_init(|| {
        let p = std::env::temp_dir().join(format!("irrd-ng-fuzz-whois-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        let mut o = StoreOptions::new(&p);
        o.initial_map_size = 32 << 20;
        let st = Store::open(&o, StoreSettings::default()).expect("store");
        let rpsl_settings = RpslSettings::default();
        let keyring = Keyring::new();
        let scope = ScopeFilterValidator::new(ScopeFilterConfig::default());
        let env = ParseEnv {
            rpsl: &rpsl_settings,
            keyring: &keyring,
            roa_validator: None,
            scopefilter: &scope,
        };
        let settings = ImportSettings {
            source: "TEST".into(),
            object_class_filter: None,
            strict_import_keycert_objects: false,
            direct_error_return: true,
            keep_plain_text: false,
        };
        let paragraphs = rpsl::split_rpsl_file(DATA.as_bytes());
        let parsed = file_import::parse_paragraphs(&paragraphs, &settings, &env).expect("parse");
        st.write(move |tx| apply_file_import(tx, "TEST", &parsed.actions, None))
            .expect("apply");
        let mut s = QuerySettings {
            version: "4.5.4".into(),
            sources: vec!["TEST".into()],
            ..QuerySettings::default()
        };
        s.per_source
            .insert("TEST".into(), SourceQuerySettings::default());
        (st, Arc::new(s))
    })
}

fuzz_target!(|data: &[u8]| {
    let (store, settings) = setup();
    let text = String::from_utf8_lossy(data);
    let mut session = WhoisSession::new(
        settings.clone(),
        Arc::new(NrtmServer),
        "192.0.2.1",
        "192.0.2.1:65000",
    );
    for line in text.split('\n').take(16) {
        let mut out = Vec::new();
        session.query_whois(store, line.trim_end_matches('\r'), &mut out);
        let _ = session.query_http(store, line);
    }
});
