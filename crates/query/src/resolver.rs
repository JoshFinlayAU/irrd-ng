//! A port of `QueryResolver` (`irrd/server/query_resolver.py`) and the
//! parts of `RPSLDatabaseQuery` and `Preloader` it uses, over the store.
//!
//! The resolver keeps v4's per-session state: selected sources, the `-T`
//! class filter for the next query, and the three `!f` filter switches.
//! Every lookup runs against one [`ReadView`], so a query sees one
//! consistent snapshot of the store.
//!
//! v4 answers `!g`, `!6`, `!a` and set expansion from its Redis preload
//! (`irrd/storage/preload.py`), which is built with `default_suppression()`
//! regardless of the `!f` switches, and answers everything else with SQL
//! filtered by the session's switches. Both are reproduced here: the
//! preload paths read the store's route-origin and set-member indexes and
//! always apply default suppression.

use std::borrow::Cow;
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;

use rpsl::Ip;
use serde::Deserialize;
use store::{
    DatabaseStatus, ReadView, RoutePreferenceStatus, RpkiStatus, RpslObjectRef, ScopeFilterStatus,
    Space,
};

use crate::messages;
use crate::settings::QuerySettings;

/// `InvalidQueryException`: a user error, reported as v4 reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryError {
    /// `InvalidQueryException` with this text.
    Invalid(String),
    /// Any other exception: v4 logs it and answers with its internal error
    /// message.
    Internal(String),
}

impl From<store::StoreError> for QueryError {
    fn from(e: store::StoreError) -> Self {
        QueryError::Internal(e.to_string())
    }
}

pub(crate) type QResult<T> = Result<T, QueryError>;

pub(crate) fn invalid<T>(msg: String) -> QResult<T> {
    Err(QueryError::Invalid(msg))
}

/// `RouteLookupType`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteLookupType {
    /// `EXACT`
    Exact,
    /// `LESS_SPECIFIC_ONE_LEVEL`
    LessSpecificOneLevel,
    /// `LESS_SPECIFIC_WITH_EXACT`
    LessSpecificWithExact,
    /// `MORE_SPECIFIC_WITHOUT_EXACT`
    MoreSpecificWithoutExact,
}

/// One object in a result, with its internal id (for tie-breaks).
pub type Found<'t> = (u64, RpslObjectRef<'t>);

/// The WHERE clause of a prepared `RPSLDatabaseQuery`, as far as it is
/// independent of the lookup itself.
#[derive(Debug, Clone, Default)]
struct Filter {
    /// `sources(...)`, upper-cased. Empty: no source filter.
    sources: Vec<String>,
    /// Each `object_classes(...)` call adds one list; all must match.
    classes: Vec<Vec<String>>,
    rpki: bool,
    scope: bool,
    routepref: bool,
    /// The list given to the last `object_classes()` call
    /// (`_set_object_classes`), which decides prefix-column searches.
    last_classes: Option<Vec<String>>,
}

impl Filter {
    fn object_classes(&mut self, classes: Vec<String>) {
        self.last_classes = Some(classes.clone());
        self.classes.push(classes);
    }

    fn class_ok(&self, class: &str) -> bool {
        self.classes
            .iter()
            .all(|list| list.iter().any(|c| c == class))
    }

    fn passes(&self, o: &RpslObjectRef<'_>) -> bool {
        (self.sources.is_empty() || self.sources.iter().any(|s| s == o.source))
            && self.class_ok(o.object_class)
            && (!self.rpki || matches!(o.rpki_status, RpkiStatus::NotFound | RpkiStatus::Valid))
            && (!self.scope || o.scopefilter_status == ScopeFilterStatus::InScope)
            && (!self.routepref || o.route_preference_status == RoutePreferenceStatus::Visible)
    }

    /// `_prefix_query_permitted()`
    fn prefix_query_permitted(&self, settings: &QuerySettings) -> bool {
        settings.inetnum_search_disabled
            || self
                .last_classes
                .as_ref()
                .is_some_and(|c| !c.is_empty() && !c.iter().any(|x| x == "inetnum"))
    }
}

/// `default_suppression()`
fn visible(o: &RpslObjectRef<'_>) -> bool {
    o.is_visible()
}

/// The resolver: one per whois session (or HTTP request).
#[derive(Debug, Clone)]
pub struct QueryResolver {
    settings: Arc<QuerySettings>,
    /// `source_manager.sources`
    sources: Vec<String>,
    /// `source_manager.sources_resolved`, kept current with `sources`.
    sources_resolved: Vec<String>,
    object_class_filter: Vec<String>,
    /// `rpki_aware`
    pub(crate) rpki_aware: bool,
    rpki_invalid_filter_enabled: bool,
    out_scope_filter_enabled: bool,
    route_preference_filter_enabled: bool,
    /// The client's user agent (`!n`, `-V`).
    pub user_agent: Option<String>,
}

/// Which set store `Preloader.set_members` looks in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SetClass {
    AsSet,
    RouteSet,
}

impl SetClass {
    fn name(self) -> &'static str {
        match self {
            SetClass::AsSet => "as-set",
            SetClass::RouteSet => "route-set",
        }
    }

    fn member_classes(self) -> &'static [&'static str] {
        match self {
            SetClass::AsSet => &["aut-num"],
            SetClass::RouteSet => &["route", "route6"],
        }
    }
}

/// A set of member or set names.
type Names<'t> = HashSet<Cow<'t, str>>;

/// State of one `members_for_set` / `routes_for_as_set` resolution.
struct SetResolve {
    root_class: Option<SetClass>,
    excluded: HashSet<String>,
    max_depth: i64,
}

#[derive(Deserialize)]
struct MemberOfObject<'a> {
    #[serde(borrow, default, rename = "mnt-by")]
    mnt_by: Option<OneOrMany<'a>>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum OneOrMany<'a> {
    #[serde(borrow)]
    One(Cow<'a, str>),
    #[serde(borrow)]
    Many(Vec<Cow<'a, str>>),
}

impl<'a> OneOrMany<'a> {
    fn into_vec(self) -> Vec<Cow<'a, str>> {
        match self {
            OneOrMany::One(s) => vec![s],
            OneOrMany::Many(v) => v,
        }
    }
}

/// `parsed_data[key]` as a string, or each string of a list.
pub(crate) fn parsed_field<'a>(parsed: &'a str, key: &str) -> Vec<Cow<'a, str>> {
    #[derive(Deserialize)]
    struct Any<'a>(#[serde(borrow)] std::collections::BTreeMap<Cow<'a, str>, serde_json::Value>);
    // Cheap path for the common case of a borrowed lookup on one key.
    let Ok(Any(map)) = serde_json::from_str::<Any<'a>>(parsed) else {
        return Vec::new();
    };
    match map.get(key) {
        Some(serde_json::Value::String(s)) => vec![Cow::Owned(s.clone())],
        Some(serde_json::Value::Array(items)) => items
            .iter()
            .filter_map(|i| i.as_str().map(|s| Cow::Owned(s.to_owned())))
            .collect(),
        _ => Vec::new(),
    }
}

/// `parsed_data` as a JSON object.
pub(crate) fn parsed_value(parsed: &str) -> serde_json::Value {
    serde_json::from_str(parsed).unwrap_or(serde_json::Value::Null)
}

/// `"AS" + str(asn_first)`: the origin keys of v4's preload. Origins in
/// any other spelling never match there.
fn preload_origin(origin: &str) -> Option<u32> {
    let digits = origin.strip_prefix("AS")?;
    if digits.is_empty()
        || !digits.bytes().all(|b| b.is_ascii_digit())
        || (digits.len() > 1 && digits.starts_with('0'))
    {
        return None;
    }
    digits.parse().ok()
}

/// IPy's `IP(text)`, as a value or `None` for its `ValueError`.
pub(crate) fn ipy(text: &str) -> Option<Ip> {
    Ip::parse(text, 0).ok()
}

/// The `(net, broadcast)` pair v4 compares against `ip_first`/`ip_last`,
/// with the broadcast's own (re-guessed) IP version.
struct IpBounds {
    version: u8,
    net: u128,
    bcast: u128,
    bcast_version: u8,
    prefixlen: u32,
}

impl IpBounds {
    fn of(ip: &Ip) -> Self {
        let b = ip.broadcast();
        IpBounds {
            version: ip.version(),
            net: ip.net().int(),
            bcast: b.int(),
            bcast_version: b.version(),
            prefixlen: ip.prefixlen(),
        }
    }

    fn space(&self) -> Space {
        if self.version == 4 {
            Space::Ipv4
        } else {
            Space::Ipv6
        }
    }

    /// A broadcast address in the other family (IPv6 within `::/96`, where
    /// IPy guesses IPv4) never equals and always sorts below an IPv6
    /// `ip_last`. Those queries are degenerate; irrd-ng answers them empty.
    fn consistent(&self) -> bool {
        self.version == self.bcast_version
    }
}

fn addr_u128(a: &IpAddr) -> u128 {
    match a {
        IpAddr::V4(v) => u128::from(u32::from(*v)),
        IpAddr::V6(v) => u128::from(*v),
    }
}

/// `prefix >>= cidr` (`contains_or_equals`) and `prefix << cidr`.
fn prefix_relation(o: &RpslObjectRef<'_>, q: &IpBounds, strictly_inside: bool) -> bool {
    let Some(p) = o.prefix else {
        return false;
    };
    if p.version() != q.version {
        return false;
    }
    let bits = if q.version == 4 { 32 } else { 128 };
    let mask = |len: u32| -> u128 {
        if len == 0 {
            0
        } else {
            let m = if bits == 128 {
                u128::MAX
            } else {
                (1u128 << bits) - 1
            };
            m & !(m >> len)
        }
    };
    let plen = u32::from(p.len);
    if strictly_inside {
        plen > q.prefixlen && p.first() & mask(q.prefixlen) == q.net
    } else {
        plen <= q.prefixlen && q.net & mask(plen) == p.first()
    }
}

impl QueryResolver {
    /// A fresh resolver, as v4 creates one per connection.
    pub fn new(settings: Arc<QuerySettings>) -> Self {
        let sources = if settings.sources_default.is_empty() {
            settings.all_valid_sources()
        } else {
            settings.sources_default.clone()
        };
        let rpki_aware = settings.rpki_enabled;
        let mut r = QueryResolver {
            settings,
            sources,
            sources_resolved: Vec::new(),
            object_class_filter: Vec::new(),
            rpki_aware,
            rpki_invalid_filter_enabled: rpki_aware,
            out_scope_filter_enabled: true,
            route_preference_filter_enabled: true,
            user_agent: None,
        };
        r.resolve_sources();
        r
    }

    /// The settings in use.
    pub fn settings(&self) -> &QuerySettings {
        &self.settings
    }

    /// `source_manager.sources`
    pub fn sources(&self) -> &[String] {
        &self.sources
    }

    /// `source_manager.sources_resolved`: aliases expanded, de-duplicated.
    pub fn sources_resolved(&self) -> &[String] {
        &self.sources_resolved
    }

    fn resolve_sources(&mut self) {
        let mut out: Vec<String> = Vec::new();
        for s in &self.sources {
            if self.settings.is_valid_real_source(s) && !out.contains(s) {
                out.push(s.clone());
            }
            if let Some(aliased) = self.settings.alias(s) {
                for a in aliased {
                    if !out.contains(a) {
                        out.push(a.clone());
                    }
                }
            }
        }
        self.sources_resolved = out;
    }

    /// `set_query_sources()`
    pub fn set_query_sources(&mut self, sources: Option<Vec<String>>) -> QResult<()> {
        let sources = match sources {
            None => {
                if self.settings.sources_default.is_empty() {
                    self.settings.all_valid_sources()
                } else {
                    self.settings.sources_default.clone()
                }
            }
            Some(s) => {
                if !s.iter().all(|x| self.settings.is_valid_source(x)) {
                    return invalid(messages::SOURCES_UNAVAILABLE.to_owned());
                }
                s
            }
        };
        self.sources = sources;
        self.resolve_sources();
        Ok(())
    }

    /// `disable_rpki_filter()`
    pub fn disable_rpki_filter(&mut self) {
        self.rpki_invalid_filter_enabled = false;
    }

    /// `disable_out_of_scope_filter()`
    pub fn disable_out_of_scope_filter(&mut self) {
        self.out_scope_filter_enabled = false;
    }

    /// `disable_route_preference_filter()`
    pub fn disable_route_preference_filter(&mut self) {
        self.route_preference_filter_enabled = false;
    }

    /// `set_object_class_filter_next_query()`
    pub fn set_object_class_filter_next_query(&mut self, classes: Vec<String>) {
        self.object_class_filter = classes;
    }

    /// `_prepare_query()`: sources, the `-T` filter (then cleared) and the
    /// session's status filters.
    fn prepare(&mut self) -> Filter {
        let mut f = Filter {
            sources: self
                .sources_resolved
                .iter()
                .map(|s| rpsl::python::strip(&rpsl::python::upper(s)).to_owned())
                .collect(),
            ..Filter::default()
        };
        if !self.object_class_filter.is_empty() {
            f.object_classes(std::mem::take(&mut self.object_class_filter));
        }
        f.rpki = self.rpki_invalid_filter_enabled;
        f.scope = self.out_scope_filter_enabled;
        f.routepref = self.route_preference_filter_enabled;
        f
    }

    /// Load, filter, de-duplicate and order objects by id.
    fn collect<'t>(
        &self,
        view: &ReadView<'t>,
        mut ids: Vec<u64>,
        filter: &Filter,
        extra: impl Fn(&RpslObjectRef<'t>) -> bool,
    ) -> QResult<Vec<Found<'t>>> {
        ids.sort_unstable();
        ids.dedup();
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            if let Some(o) = view.object_by_id(id)?
                && filter.passes(&o)
                && extra(&o)
            {
                out.push((id, o));
            }
        }
        out.sort_by(crate::order::object_cmp);
        Ok(out)
    }

    /// `key_lookup()`: `!m`.
    pub fn key_lookup<'t>(
        &mut self,
        view: &ReadView<'t>,
        object_class: &str,
        rpsl_pk: &str,
    ) -> QResult<Vec<Found<'t>>> {
        let mut f = self.prepare();
        f.object_classes(vec![object_class.to_owned()]);
        let pk = rpsl::python::upper(rpsl_pk);
        let pk = rpsl::python::strip(&pk);
        if f.sources.is_empty() {
            let ids = view.ids_by_rpsl_pk(pk)?;
            let mut found = self.collect(view, ids, &f, |_| true)?;
            found.truncate(1);
            return Ok(found);
        }
        for source in &f.sources {
            if let Some(id) = view.object_id(source, object_class, pk)?
                && let Some(o) = view.object_by_id(id)?
                && f.passes(&o)
            {
                return Ok(vec![(id, o)]);
            }
        }
        Ok(Vec::new())
    }

    /// `rpsl_text_search()`: RIPE free text.
    pub fn rpsl_text_search<'t>(
        &mut self,
        view: &ReadView<'t>,
        value: &str,
    ) -> QResult<Vec<Found<'t>>> {
        let mut f = self.prepare();
        let asdot = self.settings.asdot_queries;
        if let Ok((_, asn)) = rpsl::parse_as_number(value, false, true, asdot) {
            f.object_classes(vec!["as-block".into(), "as-set".into(), "aut-num".into()]);
            let ids = view
                .range_less_specific(Space::Asn, u128::from(asn), u128::from(asn))?
                .into_iter()
                .map(|(id, _, _)| id)
                .collect();
            return self.collect(view, ids, &f, |_| true);
        }
        if let Some(ip) = ipy(value) {
            return self.ip_less_specific(view, &f, &ip);
        }
        let upper = rpsl::python::upper(value);
        let mut ids = view.ids_by_rpsl_pk(&upper)?;
        let pattern = like_pattern(&format!("%{value}%"));
        let sources: Vec<String> = if f.sources.is_empty() {
            view.database_statuses()?
                .into_iter()
                .map(|s| s.source)
                .collect()
        } else {
            f.sources.clone()
        };
        for class in ["person", "role"] {
            if !f.class_ok(class) {
                continue;
            }
            for source in &sources {
                for item in view.objects(Some(source), Some(class))? {
                    let (id, o) = item?;
                    if parsed_field(o.parsed_data, class)
                        .first()
                        .is_some_and(|v| ilike(&pattern, v))
                    {
                        ids.push(id);
                    }
                }
            }
        }
        self.collect(view, ids, &f, |_| true)
    }

    /// `ip_less_specific()` on a prepared query.
    fn ip_less_specific<'t>(
        &self,
        view: &ReadView<'t>,
        f: &Filter,
        ip: &Ip,
    ) -> QResult<Vec<Found<'t>>> {
        let q = IpBounds::of(ip);
        if !q.consistent() {
            return Ok(Vec::new());
        }
        let ids = view
            .range_less_specific(q.space(), q.net, q.bcast)?
            .into_iter()
            .map(|(id, _, _)| id)
            .collect();
        if f.prefix_query_permitted(&self.settings) {
            self.collect(view, ids, f, |o| prefix_relation(o, &q, false))
        } else {
            self.collect(view, ids, f, |_| true)
        }
    }

    /// `route_search()`: `!r`, `-x`, `-l`, `-L`, `-M`.
    pub fn route_search<'t>(
        &mut self,
        view: &ReadView<'t>,
        ip: &Ip,
        lookup: RouteLookupType,
    ) -> QResult<Vec<Found<'t>>> {
        let mut f = self.prepare();
        f.object_classes(vec!["route".into(), "route6".into()]);
        let q = IpBounds::of(ip);
        if !q.consistent() {
            return Ok(Vec::new());
        }
        match lookup {
            RouteLookupType::Exact => {
                let ids = view
                    .range_exact(q.space(), q.net, q.bcast)?
                    .into_iter()
                    .map(|(id, _, _)| id)
                    .collect();
                self.collect(view, ids, &f, |_| true)
            }
            RouteLookupType::LessSpecificWithExact => self.ip_less_specific(view, &f, ip),
            RouteLookupType::LessSpecificOneLevel => {
                let ids = view
                    .range_less_specific(q.space(), q.net, q.bcast)?
                    .into_iter()
                    .filter(|(_, first, last)| !(*first == q.net && *last == q.bcast))
                    .map(|(id, _, _)| id)
                    .collect();
                let found = self.collect(view, ids, &f, |_| true)?;
                let size = |o: &RpslObjectRef<'_>| match (o.ip_first, o.ip_last) {
                    (Some(a), Some(b)) => addr_u128(&b).wrapping_sub(addr_u128(&a)),
                    _ => u128::MAX,
                };
                let Some(min) = found.iter().map(|(_, o)| size(o)).min() else {
                    return Ok(found);
                };
                Ok(found.into_iter().filter(|(_, o)| size(o) == min).collect())
            }
            RouteLookupType::MoreSpecificWithoutExact => {
                let ids = view
                    .range_more_specific(q.space(), q.net, q.bcast)?
                    .into_iter()
                    .map(|(id, _, _)| id)
                    .collect();
                if f.prefix_query_permitted(&self.settings) {
                    self.collect(view, ids, &f, |o| prefix_relation(o, &q, true))
                } else {
                    self.collect(view, ids, &f, |_| true)
                }
            }
        }
    }

    /// `rpsl_attribute_search()`: `-i`, `!o`.
    pub fn rpsl_attribute_search<'t>(
        &mut self,
        view: &ReadView<'t>,
        attribute: &str,
        value: &str,
    ) -> QResult<Vec<Found<'t>>> {
        let names = crate::lookup_field_names();
        if !names.contains(&attribute) {
            return invalid(messages::inverse_not_supported(
                attribute,
                &names.join(", "),
            ));
        }
        let f = self.prepare();
        let attr = rpsl::python::lower(attribute);
        let value = rpsl::python::upper(value);
        let ids = view.ids_by_lookup(&attr, Some(&value))?;
        self.collect(view, ids, &f, |_| true)
    }

    // ---- preload paths ----

    /// `Preloader.routes_for_origins()`, in a fixed order: v4 returns a
    /// Python set, whose order changes from one start to the next.
    /// irrd-ng sorts by address family, address and length.
    pub(crate) fn routes_for_origins(
        &self,
        view: &ReadView<'_>,
        origins: &mut dyn Iterator<Item = &str>,
        ip_version: Option<u8>,
        out: &mut Vec<(u8, u128, u8)>,
    ) -> QResult<()> {
        let sources = &self.sources_resolved;
        let mut asns: Vec<u32> = origins.filter_map(preload_origin).collect();
        if asns.is_empty() || sources.is_empty() {
            return Ok(());
        }
        asns.sort_unstable();
        asns.dedup();
        for source in sources {
            for &asn in &asns {
                for r in view.routes_for_origin(source, asn, ip_version)? {
                    if !(matches!(r.rpki_status, RpkiStatus::NotFound | RpkiStatus::Valid)
                        && r.scopefilter_status == ScopeFilterStatus::InScope
                        && r.route_preference_status == RoutePreferenceStatus::Visible)
                    {
                        continue;
                    }
                    let (v, a) = match r.ip_first {
                        IpAddr::V4(x) => (4, u128::from(u32::from(x))),
                        IpAddr::V6(x) => (6, u128::from(x)),
                    };
                    out.push((v, a, r.prefix_length));
                }
            }
        }
        Ok(())
    }

    /// `routes_for_origin()`: `!g`, `!6`. `origin` is already `ASnnn`.
    pub fn routes_for_origin(
        &self,
        view: &ReadView<'_>,
        origin: &str,
        ip_version: Option<u8>,
    ) -> QResult<Vec<(u8, u128, u8)>> {
        let mut out = Vec::new();
        self.routes_for_origins(view, &mut std::iter::once(origin), ip_version, &mut out)?;
        out.sort_unstable();
        out.dedup();
        Ok(out)
    }

    /// `routes_for_as_set()`: `!a`.
    pub fn routes_for_as_set(
        &self,
        view: &ReadView<'_>,
        set_name: &str,
        ip_version: Option<u8>,
        exclude_sets: &[String],
    ) -> QResult<Vec<(u8, u128, u8)>> {
        let mut st = SetResolve {
            root_class: Some(SetClass::AsSet),
            excluded: exclude_sets.iter().cloned().collect(),
            max_depth: 0,
        };
        let mut seen = HashSet::new();
        let start: HashSet<Cow<'_, str>> = [Cow::Owned(set_name.to_owned())].into();
        let members = self.recursive_set_resolve(view, &mut st, start, &mut seen, None)?;
        let mut out = Vec::new();
        self.routes_for_origins(
            view,
            &mut members.iter().map(|m| m.as_ref()),
            ip_version,
            &mut out,
        )?;
        out.sort_unstable();
        out.dedup();
        Ok(out)
    }

    /// `members_for_set()`: `!i`. Sorted, as v4 sorts.
    pub fn members_for_set(
        &self,
        view: &ReadView<'_>,
        parameter: &str,
        exclude_sets: &[String],
        depth: i64,
        recursive: bool,
        root_source: Option<&str>,
    ) -> QResult<Vec<String>> {
        let mut st = SetResolve {
            root_class: None,
            excluded: exclude_sets.iter().cloned().collect(),
            max_depth: depth,
        };
        let start: HashSet<Cow<'_, str>> = [Cow::Owned(parameter.to_owned())].into();
        let mut members: HashSet<Cow<'_, str>> = if !recursive {
            let (mut members, leaf) = self.find_set_members(view, &mut st, &start, root_source)?;
            members.extend(leaf);
            members
        } else {
            let mut seen = HashSet::new();
            self.recursive_set_resolve(view, &mut st, start, &mut seen, root_source)?
        };
        members.remove(parameter);
        if self.settings.ipv4_only_route_set_members {
            members.retain(|m| match ipy(m) {
                None => true,
                Some(_) => Ip::parse(m, 4).is_ok(),
            });
        }
        let mut out: Vec<String> = members.into_iter().map(Cow::into_owned).collect();
        out.sort_unstable();
        Ok(out)
    }

    /// `_recursive_set_resolve()`
    fn recursive_set_resolve<'t>(
        &self,
        view: &ReadView<'t>,
        st: &mut SetResolve,
        members: HashSet<Cow<'t, str>>,
        sets_seen: &mut HashSet<Cow<'t, str>>,
        root_source: Option<&str>,
    ) -> QResult<HashSet<Cow<'t, str>>> {
        if members.iter().all(|m| sets_seen.contains(m)) {
            return Ok(HashSet::new());
        }
        sets_seen.extend(members.iter().cloned());

        let mut set_members: HashSet<Cow<'t, str>> = HashSet::new();
        let mut resolved_as_members: HashSet<Cow<'t, str>> = HashSet::new();
        let (sub_members, leaf_members) = self.find_set_members(view, st, &members, root_source)?;

        for sub in &sub_members {
            if matches!(st.root_class, None | Some(SetClass::RouteSet)) {
                let head = sub.split('^').next().unwrap_or_default();
                if ipy(head).is_some() {
                    set_members.insert(sub.clone());
                    continue;
                }
            }
            if let Ok((formatted, _)) = rpsl::parse_as_number(sub, false, false, false) {
                if st.root_class == Some(SetClass::RouteSet) {
                    let mut routes = Vec::new();
                    self.routes_for_origins(
                        view,
                        &mut std::iter::once(formatted.as_str()),
                        None,
                        &mut routes,
                    )?;
                    for (v, a, l) in routes {
                        set_members.insert(Cow::Owned(prefix_text(v, a, l)));
                    }
                    resolved_as_members.insert(sub.clone());
                } else {
                    set_members.insert(sub.clone());
                }
            }
        }

        st.max_depth -= 1;
        if st.max_depth == 0 {
            let mut all = set_members;
            all.extend(sub_members);
            all.extend(leaf_members);
            return Ok(all);
        }

        let further: HashSet<Cow<'t, str>> = sub_members
            .into_iter()
            .filter(|m| {
                !set_members.contains(m)
                    && !sets_seen.contains(m)
                    && !resolved_as_members.contains(m)
                    && !st.excluded.contains(m.as_ref())
            })
            .collect();
        let new_members = self.recursive_set_resolve(view, st, further, sets_seen, None)?;
        set_members.extend(new_members);
        Ok(set_members)
    }

    /// `_find_set_members()`: (members found, names not found).
    fn find_set_members<'t>(
        &self,
        view: &ReadView<'t>,
        st: &mut SetResolve,
        set_names: &HashSet<Cow<'t, str>>,
        limit_source: Option<&str>,
    ) -> QResult<(Names<'t>, Names<'t>)> {
        let mut members = HashSet::new();
        let mut leaf = HashSet::new();
        let limited;
        let sources: &[String] = match limit_source {
            Some(s) => {
                limited = [s.to_owned()];
                &limited
            }
            None => &self.sources_resolved,
        };
        let as_set_only = st.root_class == Some(SetClass::AsSet);
        for name in set_names {
            match self.preload_set_members(view, name, sources, as_set_only)? {
                None => {
                    leaf.insert(name.clone());
                }
                Some((found, class)) => {
                    members.extend(found);
                    if st.root_class.is_none() {
                        st.root_class = Some(class);
                    }
                }
            }
        }
        Ok((members, leaf))
    }

    /// `Preloader.set_members()`: the members of the set in the first
    /// source (in order) that has it, as-sets before route-sets, including
    /// members added by `mbrs-by-ref`/`member-of`.
    fn preload_set_members<'t>(
        &self,
        view: &ReadView<'t>,
        set_pk: &str,
        sources: &[String],
        as_set_only: bool,
    ) -> QResult<Option<(Vec<Cow<'t, str>>, SetClass)>> {
        let pk = rpsl::python::upper(set_pk);
        let entries = view.set_members(&pk)?;
        if entries.is_empty() {
            return Ok(None);
        }
        let classes: &[SetClass] = if as_set_only {
            &[SetClass::AsSet]
        } else {
            &[SetClass::AsSet, SetClass::RouteSet]
        };
        for &class in classes {
            for source in sources {
                let Some((_, _, sm)) = entries
                    .iter()
                    .find(|(s, c, _)| s == source && c == class.name())
                else {
                    continue;
                };
                let mut out: Vec<Cow<'t, str>> =
                    sm.members.iter().map(|m| Cow::Borrowed(*m)).collect();
                if !sm.mbrs_by_ref.is_empty() {
                    self.mbrs_by_ref_members(view, &pk, source, class, &sm.mbrs_by_ref, &mut out)?;
                }
                if out.is_empty() {
                    // v4 stores the members joined by "," and splits them
                    // again, so an empty set has one member: "".
                    out.push(Cow::Borrowed(""));
                }
                return Ok(Some((out, class)));
            }
        }
        Ok(None)
    }

    /// Members included by reference: visible objects of the member classes
    /// in the same source whose `member-of` names the set and whose
    /// `mnt-by` meets its `mbrs-by-ref` (or it allows `ANY`).
    fn mbrs_by_ref_members<'t>(
        &self,
        view: &ReadView<'t>,
        set_pk: &str,
        source: &str,
        class: SetClass,
        mbrs_by_ref: &[&'t str],
        out: &mut Vec<Cow<'t, str>>,
    ) -> QResult<()> {
        let any = mbrs_by_ref.contains(&"ANY");
        for id in view.ids_by_lookup("member-of", Some(set_pk))? {
            let Some(o) = view.object_by_id(id)? else {
                continue;
            };
            if o.source != source
                || !class.member_classes().contains(&o.object_class)
                || !visible(&o)
            {
                continue;
            }
            if !any {
                let mnt_by = serde_json::from_str::<MemberOfObject<'t>>(o.parsed_data)
                    .ok()
                    .and_then(|m| m.mnt_by)
                    .map(OneOrMany::into_vec)
                    .unwrap_or_default();
                if !mnt_by.iter().any(|m| mbrs_by_ref.contains(&m.as_ref())) {
                    continue;
                }
            }
            for v in parsed_field(o.parsed_data, o.object_class) {
                out.push(Cow::Owned(v.into_owned()));
            }
        }
        Ok(())
    }

    // ---- status ----

    /// `DatabaseStatusQuery().sources(sources)`: rows of the listed sources
    /// that exist, ordered by first position in the list.
    pub(crate) fn status_rows(
        view: &ReadView<'_>,
        sources: &[String],
    ) -> QResult<Vec<DatabaseStatus>> {
        let wanted: Vec<String> = sources
            .iter()
            .map(|s| rpsl::python::upper(s).into_owned())
            .collect();
        let mut rows: Vec<(usize, DatabaseStatus)> = view
            .database_statuses()?
            .into_iter()
            .filter_map(|st| wanted.iter().position(|w| *w == st.source).map(|i| (i, st)))
            .collect();
        rows.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.source.cmp(&b.1.source)));
        Ok(rows.into_iter().map(|(_, st)| st).collect())
    }
}

/// `f"{ip_first}/{prefix_length}"` with PostgreSQL's `inet` text.
pub(crate) fn prefix_text(version: u8, addr: u128, len: u8) -> String {
    let mut s = String::with_capacity(44);
    write_prefix(&mut s, version, addr, len);
    s
}

/// [`prefix_text`] into a buffer.
pub(crate) fn write_prefix(out: &mut String, version: u8, addr: u128, len: u8) {
    use std::fmt::Write as _;
    let ip = if version == 4 {
        IpAddr::V4(std::net::Ipv4Addr::from(addr as u32))
    } else {
        IpAddr::V6(std::net::Ipv6Addr::from(addr))
    };
    let _ = write!(out, "{}/{len}", store::InetDisplay(&ip));
}

/// A compiled `LIKE` pattern: `%`, `_` and `\` escapes.
#[derive(Debug)]
pub(crate) enum LikeToken {
    Any,
    One,
    Char(char),
}

/// Lower-cased (ILIKE) and tokenised.
pub(crate) fn like_pattern(p: &str) -> Vec<LikeToken> {
    let lower = p.to_lowercase();
    let mut out = Vec::new();
    let mut chars = lower.chars();
    while let Some(c) = chars.next() {
        match c {
            '%' => {
                if !matches!(out.last(), Some(LikeToken::Any)) {
                    out.push(LikeToken::Any);
                }
            }
            '_' => out.push(LikeToken::One),
            '\\' => match chars.next() {
                Some(n) => out.push(LikeToken::Char(n)),
                None => out.push(LikeToken::Char('\\')),
            },
            c => out.push(LikeToken::Char(c)),
        }
    }
    out
}

/// `text ILIKE pattern`.
pub(crate) fn ilike(pattern: &[LikeToken], text: &str) -> bool {
    let t: Vec<char> = text.to_lowercase().chars().collect();
    // Iterative wildcard match with backtracking to the last `%`.
    let (mut pi, mut ti) = (0usize, 0usize);
    let mut star: Option<(usize, usize)> = None;
    while ti < t.len() {
        match pattern.get(pi) {
            Some(LikeToken::Any) => {
                star = Some((pi, ti));
                pi += 1;
                continue;
            }
            Some(LikeToken::One) => {
                pi += 1;
                ti += 1;
                continue;
            }
            Some(LikeToken::Char(c)) if *c == t[ti] => {
                pi += 1;
                ti += 1;
                continue;
            }
            _ => {}
        }
        match star {
            Some((sp, st)) => {
                pi = sp + 1;
                ti = st + 1;
                star = Some((sp, st + 1));
            }
            None => return false,
        }
    }
    pattern[pi..].iter().all(|t| matches!(t, LikeToken::Any))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn like_matching() {
        let p = like_pattern("%foo_b%");
        assert!(ilike(&p, "a FOOxBar"));
        assert!(!ilike(&p, "a foobar"));
        assert!(ilike(&like_pattern("%a\\%%"), "xa%y"));
        assert!(!ilike(&like_pattern("%a\\%%"), "xaby"));
        assert!(ilike(&like_pattern("%%"), ""));
        assert!(ilike(&like_pattern("%x\\%"), "abx%"));
    }

    #[test]
    fn preload_origin_spelling() {
        assert_eq!(preload_origin("AS65537"), Some(65537));
        assert_eq!(preload_origin("AS0"), Some(0));
        assert_eq!(preload_origin("AS065537"), None);
        assert_eq!(preload_origin("as65537"), None);
        assert_eq!(preload_origin("AS"), None);
    }
}
