//! `sqlTrace`: v4 reports `repr()` of each `RPSLDatabaseQuery` it ran,
//! which is SQLAlchemy's compiled SQL and its bind parameters. irrd-ng
//! has no SQL, so it renders the statement v4 would have built for the
//! same query. v4 lists the selected columns in Python set order, which
//! changes from one start to the next; irrd-ng lists them in table order.

use std::collections::HashMap;
use std::fmt::Write as _;

use graphql::value::str_repr;
use query::QueryResolver;
use query::objects::{IpFilter, ObjectQuery};

/// A bind parameter value, as Python's `repr()` shows it.
#[derive(Debug, Clone)]
enum P {
    Str(String),
    Int(i128),
    Strs(Vec<String>),
    Ints(Vec<i128>),
    Enums(&'static str, Vec<(String, String)>),
}

impl P {
    fn repr(&self) -> String {
        match self {
            P::Str(s) => str_repr(s),
            P::Int(i) => i.to_string(),
            P::Strs(l) => format!(
                "[{}]",
                l.iter().map(|s| str_repr(s)).collect::<Vec<_>>().join(", ")
            ),
            P::Ints(l) => format!(
                "[{}]",
                l.iter().map(i128::to_string).collect::<Vec<_>>().join(", ")
            ),
            P::Enums(cls, l) => format!(
                "[{}]",
                l.iter()
                    .map(|(name, value)| format!("<{cls}.{name}: '{value}'>"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        }
    }
}

#[derive(Default)]
struct Compiler {
    counters: HashMap<String, usize>,
    params: Vec<(String, P)>,
    clauses: Vec<String>,
    lookup_counter: usize,
}

impl Compiler {
    /// An anonymous bind parameter named after its column.
    fn bind(&mut self, base: &str, v: P) -> String {
        let n = self.counters.entry(base.to_owned()).or_insert(0);
        *n += 1;
        let name = format!("{base}_{n}");
        self.params.push((name.clone(), v));
        name
    }

    fn named(&mut self, name: String, v: P) -> String {
        self.params.push((name.clone(), v));
        name
    }

    fn in_(&mut self, col: &str, v: P) {
        let p = self.bind(col, v);
        self.clauses
            .push(format!("rpsl_objects.{col} IN (__[POSTCOMPILE_{p}])"));
    }

    fn cmp(&mut self, col: &str, op: &str, v: P) -> String {
        let p = self.bind(col, v);
        format!("rpsl_objects.{col} {op} :{p}")
    }

    fn cast(&mut self, ip: &rpsl::Ip) -> String {
        let p = self.bind("param", P::Str(ip.to_string()));
        format!("CAST(:{p} AS CIDR)")
    }

    fn ip_bounds(ip: &rpsl::Ip) -> (String, String, i128) {
        (
            ip.net().to_string(),
            ip.broadcast().to_string(),
            i128::from(ip.version()),
        )
    }

    fn ip_filter(&mut self, f: IpFilter, ip: &rpsl::Ip, prefix_ok: bool) {
        let (net, bcast, ver) = Self::ip_bounds(ip);
        match f {
            IpFilter::Exact => {
                let a = self.cmp("ip_first", "=", P::Str(net));
                let b = self.cmp("ip_last", "=", P::Str(bcast));
                let c = self.cmp("ip_version", "=", P::Int(ver));
                self.clauses.extend([a, b, c]);
            }
            IpFilter::LessSpecific if prefix_ok => {
                let c = self.cast(ip);
                self.clauses.push(format!("rpsl_objects.prefix >>= {c}"));
            }
            IpFilter::LessSpecific => {
                let a = self.cmp("ip_first", "<=", P::Str(net));
                let b = self.cmp("ip_last", ">=", P::Str(bcast));
                let c = self.cmp("ip_version", "=", P::Int(ver));
                self.clauses.extend([a, b, c]);
            }
            IpFilter::MoreSpecific if prefix_ok => {
                let c = self.cast(ip);
                self.clauses.push(format!("rpsl_objects.prefix << {c}"));
            }
            IpFilter::MoreSpecific => {
                let a = self.cmp("ip_first", ">=", P::Str(net.clone()));
                let b = self.cmp("ip_first", "<=", P::Str(bcast.clone()));
                let c = self.cmp("ip_last", "<=", P::Str(bcast.clone()));
                let d = self.cmp("ip_last", ">=", P::Str(net.clone()));
                let e = self.cmp("ip_version", "=", P::Int(ver));
                let x = self.cmp("ip_first", "=", P::Str(net));
                let y = self.cmp("ip_last", "=", P::Str(bcast));
                self.clauses
                    .extend([a, b, c, d, e, format!("NOT ({x} AND {y})")]);
            }
            IpFilter::LessSpecificOneLevel => {
                let a = self.cmp("ip_first", "<=", P::Str(net.clone()));
                let b = self.cmp("ip_last", ">=", P::Str(bcast.clone()));
                let c = self.cmp("ip_version", "=", P::Int(ver));
                let x = self.cmp("ip_first", "=", P::Str(net));
                let y = self.cmp("ip_last", "=", P::Str(bcast));
                self.clauses.extend([a, b, c, format!("NOT ({x} AND {y})")]);
                let inner = self.clauses.join(" AND ");
                let l = self.bind("param", P::Int(1));
                self.clauses.push(format!(
                    "rpsl_objects.ip_size IN (SELECT rpsl_objects.ip_size \nFROM rpsl_objects \nWHERE {inner} ORDER BY rpsl_objects.ip_size ASC\n LIMIT :{l})"
                ));
            }
            IpFilter::Any if prefix_ok => {
                let c = self.cast(ip);
                self.clauses.push(format!(
                    "((rpsl_objects.prefix >>= {c}) OR (rpsl_objects.prefix << {c}))"
                ));
            }
            IpFilter::Any => {
                let a = self.cmp("ip_first", "<=", P::Str(net.clone()));
                let b = self.cmp("ip_last", ">=", P::Str(bcast.clone()));
                let c = self.cmp("ip_first", ">=", P::Str(net.clone()));
                let d = self.cmp("ip_first", "<=", P::Str(bcast.clone()));
                let e = self.cmp("ip_last", "<=", P::Str(bcast));
                let f2 = self.cmp("ip_last", ">=", P::Str(net));
                let v = self.cmp("ip_version", "=", P::Int(ver));
                self.clauses
                    .push(format!("({a} AND {b} OR {c} AND {d} AND {e} AND {f2})"));
                self.clauses.push(v);
            }
        }
    }

    fn render(self, select: &[&str], limit: Option<String>) -> String {
        let cols: Vec<String> = select.iter().map(|c| format!("rpsl_objects.{c}")).collect();
        let mut s = format!(
            "RPSLDatabaseQuery: SELECT {} \nFROM rpsl_objects \nWHERE {}",
            cols.join(", "),
            self.clauses.join(" AND ")
        );
        if let Some(l) = limit {
            let _ = write!(s, "\n LIMIT :{l}");
        }
        let params: Vec<String> = self
            .params
            .iter()
            .map(|(k, v)| format!("{}: {}", str_repr(k), v.repr()))
            .collect();
        let _ = write!(s, "\nPARAMS: {{{}}}", params.join(", "));
        s
    }
}

fn statuses<T: Copy>(
    cls: &'static str,
    l: &[T],
    label: fn(T) -> &'static str,
    value: fn(T) -> &'static str,
) -> P {
    P::Enums(
        cls,
        l.iter()
            .map(|s| (label(*s).to_owned(), value(*s).to_owned()))
            .collect(),
    )
}

/// `repr()` of the `RPSLDatabaseQuery` for an [`ObjectQuery`], with the
/// filters in the order the resolvers apply them.
pub(crate) fn object_query(q: &ObjectQuery, columns: &[&str]) -> String {
    let mut c = Compiler::default();
    if let Some(pks) = &q.rpsl_pks {
        c.in_("rpsl_pk", P::Strs(pks.clone()));
    }
    // A text search on an AS number adds its own class list last.
    let n_classes = q.classes.len() - usize::from(q.text_asn.is_some());
    for l in &q.classes[..n_classes] {
        c.in_("object_class", P::Strs(l.clone()));
    }
    if let Some(a) = &q.asns_first {
        c.in_("asn_first", P::Ints(a.clone()));
    }
    if let Some(t) = &q.text_search {
        if let Some(asn) = q.text_asn {
            c.in_(
                "object_class",
                P::Strs(vec!["as-block".into(), "as-set".into(), "aut-num".into()]),
            );
            let a = c.cmp("asn_first", "<=", P::Int(i128::from(asn)));
            let b = c.cmp("asn_last", ">=", P::Int(i128::from(asn)));
            c.clauses.extend([a, b]);
        } else if let Ok(ip) = rpsl::Ip::parse(t, 0) {
            let prefix_ok = q
                .classes
                .last()
                .is_some_and(|l| !l.is_empty() && !l.iter().any(|x| x == "inetnum"));
            c.ip_filter(IpFilter::LessSpecific, &ip, prefix_ok);
        } else {
            let n = c.lookup_counter;
            c.lookup_counter += 1;
            let pk = c.cmp("rpsl_pk", "=", P::Str(rpsl::python::upper(t).into_owned()));
            let o1 = c.cmp("object_class", "=", P::Str("person".into()));
            let ts = c.named(
                format!("lookup_attr_text_search{n}"),
                P::Str(format!("%{t}%")),
            );
            let o2 = c.cmp("object_class", "=", P::Str("role".into()));
            c.clauses.push(format!(
                "({pk} OR {o1} AND parsed_data->>'person' ILIKE :{ts} OR {o2} AND parsed_data->>'role' ILIKE :{ts})"
            ));
        }
    }
    if let Some(r) = &q.rpki {
        c.in_(
            "rpki_status",
            statuses("RPKIStatus", r, |s| s.pg_label(), |s| s.py_value()),
        );
    }
    if let Some(r) = &q.scope {
        c.in_(
            "scopefilter_status",
            statuses("ScopeFilterStatus", r, |s| s.pg_label(), |s| s.py_value()),
        );
    }
    if let Some(r) = &q.routepref {
        c.in_(
            "route_preference_status",
            statuses(
                "RoutePreferenceStatus",
                r,
                |s| s.pg_label(),
                |s| s.py_value(),
            ),
        );
    }
    if let Some(s) = &q.sources {
        c.in_("source", P::Strs(s.clone()));
    }
    for (attr, values) in &q.lookups {
        let mut parts = Vec::new();
        for v in values {
            let n = c.lookup_counter;
            c.lookup_counter += 1;
            let an = c.named(format!("lookup_attr_name{n}"), P::Str(attr.clone()));
            let av = c.named(
                format!("lookup_attr_value{n}"),
                P::Str(rpsl::python::upper(v).into_owned()),
            );
            parts.push(format!("parsed_data->:{an} ? :{av}"));
        }
        match parts.len() {
            0 => {}
            1 => c.clauses.push(parts.remove(0)),
            _ => c.clauses.push(format!("({})", parts.join(" OR "))),
        }
    }
    let prefix_ok = q
        .classes
        .last()
        .is_some_and(|l| !l.is_empty() && !l.iter().any(|x| x == "inetnum"));
    for (f, ip) in &q.ip {
        c.ip_filter(*f, ip, prefix_ok);
    }
    let limit = q.limit.map(|l| c.bind("param", P::Int(i128::from(l))));
    c.render(columns, limit)
}

/// The query `members_for_set_per_source()` runs to find the sources of a
/// set.
pub(crate) fn set_sources_query(r: &QueryResolver, name: &str) -> String {
    let mut c = Compiler::default();
    let sources: Vec<String> = r
        .sources_resolved()
        .iter()
        .map(|s| rpsl::python::strip(&rpsl::python::upper(s)).to_owned())
        .collect();
    if !sources.is_empty() {
        c.in_("source", P::Strs(sources));
    }
    c.in_(
        "rpki_status",
        P::Enums(
            "RPKIStatus",
            vec![
                ("not_found".into(), "NOT_FOUND".into()),
                ("valid".into(), "VALID".into()),
            ],
        ),
    );
    c.in_(
        "scopefilter_status",
        P::Enums(
            "ScopeFilterStatus",
            vec![("in_scope".into(), "IN_SCOPE".into())],
        ),
    );
    c.in_(
        "route_preference_status",
        P::Enums(
            "RoutePreferenceStatus",
            vec![("visible".into(), "VISIBLE".into())],
        ),
    );
    c.in_(
        "object_class",
        P::Strs(vec!["as-set".into(), "route-set".into()]),
    );
    c.in_(
        "rpsl_pk",
        P::Strs(vec![
            rpsl::python::strip(&rpsl::python::upper(name)).to_owned(),
        ]),
    );
    c.render(&["source"], None)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Recorded from v4 (`rpslObjects(mntBy: [...], recordLimit: 3,
    /// objectClass: ["route", "aut-num"])`), columns in table order.
    #[test]
    fn lookup_query_like_v4() {
        let mut q = ObjectQuery {
            limit: Some(3),
            rpki: Some(vec![store::RpkiStatus::NotFound, store::RpkiStatus::Valid]),
            scope: Some(vec![store::ScopeFilterStatus::InScope]),
            routepref: Some(vec![store::RoutePreferenceStatus::Visible]),
            sources: Some(vec!["RADB".into(), "NTTCOM".into()]),
            ..Default::default()
        };
        q.object_classes(vec!["route".into(), "aut-num".into()]);
        q.lookups
            .push(("mnt-by".into(), vec!["MAINT-AS10217".into()]));
        assert_eq!(
            object_query(&q, &["rpsl_pk", "source", "object_class", "parsed_data"]),
            "RPSLDatabaseQuery: SELECT rpsl_objects.rpsl_pk, rpsl_objects.source, rpsl_objects.object_class, rpsl_objects.parsed_data \nFROM rpsl_objects \nWHERE rpsl_objects.object_class IN (__[POSTCOMPILE_object_class_1]) AND rpsl_objects.rpki_status IN (__[POSTCOMPILE_rpki_status_1]) AND rpsl_objects.scopefilter_status IN (__[POSTCOMPILE_scopefilter_status_1]) AND rpsl_objects.route_preference_status IN (__[POSTCOMPILE_route_preference_status_1]) AND rpsl_objects.source IN (__[POSTCOMPILE_source_1]) AND parsed_data->:lookup_attr_name0 ? :lookup_attr_value0\n LIMIT :param_1\nPARAMS: {'object_class_1': ['route', 'aut-num'], 'rpki_status_1': [<RPKIStatus.not_found: 'NOT_FOUND'>, <RPKIStatus.valid: 'VALID'>], 'scopefilter_status_1': [<ScopeFilterStatus.in_scope: 'IN_SCOPE'>], 'route_preference_status_1': [<RoutePreferenceStatus.visible: 'VISIBLE'>], 'source_1': ['RADB', 'NTTCOM'], 'lookup_attr_name0': 'mnt-by', 'lookup_attr_value0': 'MAINT-AS10217', 'param_1': 3}"
        );
    }
}
