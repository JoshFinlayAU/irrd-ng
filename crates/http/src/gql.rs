//! `/graphql/`: ariadne's `GraphQLHTTPHandler` with IRRd's schema,
//! resolvers (`irrd/server/graphql/resolvers.py`), scalars, extension and
//! error formatter, and the GraphiQL explorer page.

use std::cell::RefCell;
use std::sync::OnceLock;

use graphql::{FieldInfo, ResolveError, ScalarError, Schema, Value};
use query::objects::{IpFilter, ObjectQuery};
use query::{QueryResolver, QuerySettings};
use store::{ReadView, RoutePreferenceStatus, RpkiStatus, RpslObjectRef, ScopeFilterStatus};

use crate::messages;

/// The schema, built once from v4's SDL.
pub(crate) fn schema() -> &'static Schema {
    static SCHEMA: OnceLock<Schema> = OnceLock::new();
    SCHEMA.get_or_init(|| Schema::from_sdl(include_str!("../../../parity/reference/graphql.sdl")))
}

/// `irrd/server/graphql/graphiql.html`
pub(crate) const GRAPHIQL_HTML: &str = include_str!("graphiql.html");

/// `OBJECT_CLASS_MAPPING[object_class].__name__`
fn graphql_type_name(class: &str) -> Option<&'static str> {
    Some(match class {
        "as-block" => "RPSLAsBlock",
        "as-set" => "RPSLAsSet",
        "aut-num" => "RPSLAutNum",
        "domain" => "RPSLDomain",
        "filter-set" => "RPSLFilterSet",
        "inet-rtr" => "RPSLInetRtr",
        "inet6num" => "RPSLInet6Num",
        "inetnum" => "RPSLInetnum",
        "irt" => "RPSLIrt",
        "key-cert" => "RPSLKeyCert",
        "mntner" => "RPSLMntner",
        "organisation" => "RPSLOrganisation",
        "peering-set" => "RPSLPeeringSet",
        "person" => "RPSLPerson",
        "role" => "RPSLRole",
        "route" => "RPSLRoute",
        "route-set" => "RPSLRouteSet",
        "route6" => "RPSLRoute6",
        "rtr-set" => "RPSLRtrSet",
        _ => return None,
    })
}

/// Python's `str.title()`.
fn py_title(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut prev_cased = false;
    for c in s.chars() {
        if c.is_alphabetic() {
            if prev_cased {
                out.extend(c.to_lowercase());
            } else {
                out.extend(c.to_uppercase());
            }
            prev_cased = true;
        } else {
            out.push(c);
            prev_cased = false;
        }
    }
    out
}

/// `snake_to_camel_case()`
pub(crate) fn snake_to_camel_case(s: &str) -> String {
    let replaced = s.replace('_', "-");
    let mut parts = replaced.split('-');
    let mut out = parts.next().unwrap_or_default().to_owned();
    for p in parts {
        out.push_str(&py_title(p));
    }
    out
}

/// ariadne's `convert_camel_case_to_snake()`
pub(crate) fn camel_to_snake(name: &str) -> String {
    let g: Vec<char> = name.chars().collect();
    let lowered: Vec<char> = name.to_lowercase().chars().collect();
    if g.len() != lowered.len() {
        return name.to_lowercase();
    }
    let max = g.len().saturating_sub(1);
    let mut out = String::new();
    for (i, &c) in lowered.iter().enumerate() {
        let insert = i > 0
            && ((c != g[i] && g[i - 1] != '_' && !out.is_empty() && out.ends_with(g[i - 1]))
                || (i < max && g[i] != c && g[i + 1] == lowered[i + 1] && g[i + 1] != '_')
                || (c.is_ascii_digit() && !g[i - 1].is_ascii_digit())
                || (!c.is_ascii_digit() && g[i] != '_' && g[i - 1].is_ascii_digit()));
        if insert {
            out.push('_');
        }
        out.push(c);
    }
    out
}

/// `datetime.__str__()` for a UTC timestamp.
fn py_datetime_str(t: store::Timestamp) -> String {
    query::status::isoformat(t).replacen('T', " ", 1)
}

fn config_value(v: &query::ConfigValue) -> Value {
    match v {
        query::ConfigValue::Null => Value::Null,
        query::ConfigValue::Bool(b) => Value::Bool(*b),
        query::ConfigValue::Int(i) => Value::Int(*i),
        query::ConfigValue::Float(f) => Value::Float(*f),
        query::ConfigValue::Str(s) => Value::Str(s.clone()),
        query::ConfigValue::List(l) => Value::List(l.iter().map(config_value).collect()),
        query::ConfigValue::Dict(d) => {
            Value::Object(d.iter().map(|(k, v)| (k.clone(), config_value(v))).collect())
        }
    }
}

// ---- scalars ----

/// The `ASN` and `IP` scalars' value parsers (`schema_builder.py`).
#[derive(Debug)]
pub(crate) struct IrrdScalars;

/// Python's `int(str)`.
fn py_int_str(s: &str) -> Option<i128> {
    let t = s.trim();
    let (neg, digits) = match t.as_bytes().first() {
        Some(b'-') => (true, &t[1..]),
        Some(b'+') => (false, &t[1..]),
        _ => (false, t),
    };
    if digits.is_empty()
        || digits.starts_with('_')
        || digits.ends_with('_')
        || digits.contains("__")
    {
        return None;
    }
    let clean: String = digits.chars().filter(|c| *c != '_').collect();
    if !clean.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let v: i128 = clean.parse().ok()?;
    Some(if neg { -v } else { v })
}

fn py_type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "NoneType",
        Value::Bool(_) => "bool",
        Value::Int(_) | Value::BigInt(_) => "int",
        Value::Float(_) => "float",
        Value::Str(_) => "str",
        Value::List(_) => "list",
        Value::Object(_) => "dict",
    }
}

fn py_str(v: &Value) -> String {
    match v {
        Value::Str(s) => s.clone(),
        Value::Float(f) => graphql::value::float_repr(*f),
        other => graphql::value::inspect(other),
    }
}

impl graphql::ScalarParsers for IrrdScalars {
    fn parse_value(&self, name: &str, v: &Value) -> Result<Value, ScalarError> {
        match name {
            "ASN" => match v {
                Value::Int(_) | Value::BigInt(_) => Ok(v.clone()),
                Value::Bool(b) => Ok(Value::Int(i128::from(*b))),
                Value::Float(f) => {
                    if f.is_nan() {
                        Err(ScalarError::GraphQL(format!("Invalid ASN: {}; must be numeric", py_str(v))))
                    } else if f.is_infinite() {
                        Err(ScalarError::Other("cannot convert float infinity to integer".into()))
                    } else {
                        Ok(Value::Int(f.trunc() as i128))
                    }
                }
                Value::Str(s) => match py_int_str(s) {
                    Some(i) => Ok(Value::Int(i)),
                    None => Err(ScalarError::GraphQL(format!("Invalid ASN: {s}; must be numeric"))),
                },
                other => Err(ScalarError::Other(format!(
                    "int() argument must be a string, a bytes-like object or a real number, not '{}'",
                    py_type_name(other)
                ))),
            },
            "IP" => {
                let text = match v {
                    Value::Str(s) => s.clone(),
                    Value::Int(i) => i.to_string(),
                    Value::Bool(b) => i128::from(*b).to_string(),
                    other => {
                        return Err(ScalarError::Other(format!(
                            "Unsupported data type: <class '{}'>",
                            py_type_name(other)
                        )));
                    }
                };
                match rpsl::Ip::parse(&text, 0) {
                    Ok(ip) => Ok(Value::Str(ip.to_string())),
                    Err(e) => Err(ScalarError::GraphQL(format!(
                        "Invalid IP: {}: {}",
                        py_str(v),
                        rpsl::ipy::clean_ip_value_error(&e.to_string())
                    ))),
                }
            }
            _ => Ok(v.clone()),
        }
    }
}

// ---- resolvers ----

/// The resolvers for one request, over one read view.
pub(crate) struct Resolvers<'v, 't> {
    pub view: &'v ReadView<'t>,
    pub settings: &'v QuerySettings,
    pub client_host: String,
    /// `info.context["sql_trace"]` and `["sql_queries"]`.
    pub sql_trace: RefCell<bool>,
    pub sql_queries: RefCell<Option<Vec<String>>>,
}

impl std::fmt::Debug for Resolvers<'_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Resolvers").finish_non_exhaustive()
    }
}

fn internal<T>(m: impl Into<String>) -> Result<T, ResolveError> {
    Err(ResolveError::Internal(m.into()))
}

fn query_err(e: query::QueryError) -> ResolveError {
    match e {
        query::QueryError::Invalid(m) | query::QueryError::Internal(m) => ResolveError::Internal(m),
    }
}

fn arg<'a>(args: &'a [(String, Value)], name: &str) -> Option<&'a Value> {
    args.iter().find(|(k, _)| k == name).map(|(_, v)| v)
}

/// A list argument's strings, or `None` for a null (which v4 iterates
/// and fails on).
fn str_list(v: &Value) -> Option<Vec<String>> {
    match v {
        Value::List(l) => Some(l.iter().filter_map(|x| x.as_str().map(str::to_owned)).collect()),
        _ => None,
    }
}

/// `_collect_predicate_names()`: field names, through inline fragments;
/// a fragment spread contributes its fragment's name.
fn predicate_names(sel: &graphql::ast::SelectionSet, out: &mut Vec<String>) {
    for s in &sel.selections {
        match s {
            graphql::ast::Selection::Field(f) => out.push(f.name.value.clone()),
            graphql::ast::Selection::FragmentSpread(fs) => out.push(fs.name.value.clone()),
            graphql::ast::Selection::InlineFragment(i) => predicate_names(&i.selection_set, out),
        }
    }
}

/// The table columns of `rpsl_objects`, in table order.
const OBJECT_COLUMNS: &[&str] = &[
    "pk",
    "rpsl_pk",
    "source",
    "object_class",
    "parsed_data",
    "object_text",
    "ip_version",
    "ip_first",
    "ip_last",
    "ip_size",
    "prefix",
    "prefix_length",
    "asn_first",
    "asn_last",
    "rpki_status",
    "scopefilter_status",
    "route_preference_status",
    "created",
    "updated",
];

/// `_columns_for_graphql_selection()`, in table order.
fn columns_for_selection(info: &FieldInfo<'_>) -> Vec<&'static str> {
    let mut wanted: Vec<&'static str> = vec!["object_class", "source", "parsed_data", "rpsl_pk"];
    let mut names = Vec::new();
    if let Some(ss) = &info.field_nodes[0].selection_set {
        predicate_names(ss, &mut names);
    }
    for n in names {
        let snake = camel_to_snake(&n);
        if let Some(c) = OBJECT_COLUMNS.iter().find(|c| **c == snake) {
            wanted.push(c);
        }
        if snake == "asn" {
            wanted.push("asn_first");
            wanted.push("asn_last");
        }
        if snake == "prefix" {
            wanted.push("ip_first");
            wanted.push("prefix_length");
        }
    }
    OBJECT_COLUMNS
        .iter()
        .copied()
        .filter(|c| wanted.contains(c))
        .collect()
}

impl<'v, 't> Resolvers<'v, 't> {
    fn trace(&self, entry: String) {
        if *self.sql_trace.borrow() {
            self.sql_queries
                .borrow_mut()
                .get_or_insert_with(Vec::new)
                .push(entry);
        }
    }

    /// `_rpsl_db_query_to_graphql_out()`
    fn objects_out(
        &self,
        q: &ObjectQuery,
        columns: &[&str],
    ) -> Result<Value, ResolveError> {
        self.trace(crate::sqltrace::object_query(q, columns));
        let found = q.execute(self.view, self.settings).map_err(query_err)?;
        let mut out = Vec::with_capacity(found.len());
        for (_, o) in found {
            out.push(self.object_out(&o, columns)?);
        }
        Ok(Value::List(out))
    }

    fn object_out(&self, o: &RpslObjectRef<'_>, columns: &[&str]) -> Result<Value, ResolveError> {
        let mut r = Value::Object(Vec::new());
        let ip_first_text = o.ip_first.map(|ip| store::InetDisplay(&ip).to_string());
        for c in columns {
            let v = match *c {
                "rpsl_pk" => Value::str(o.rpsl_pk),
                "source" => Value::str(o.source),
                "object_class" => Value::str(o.object_class),
                "object_text" => Value::Str(rpsl::text::remove_auth_hashes(o.object_text).into_owned()),
                "ip_first" => ip_first_text.clone().map_or(Value::Null, Value::Str),
                "ip_last" => o
                    .ip_last
                    .map_or(Value::Null, |ip| Value::Str(store::InetDisplay(&ip).to_string())),
                "prefix" => o.prefix.map_or(Value::Null, |p| Value::Str(p.to_string())),
                "prefix_length" => o.prefix_length.map_or(Value::Null, |l| Value::Int(i128::from(l))),
                "asn_first" => o.asn_first.map_or(Value::Null, |a| Value::Int(i128::from(a))),
                "asn_last" => o.asn_last.map_or(Value::Null, |a| Value::Int(i128::from(a))),
                "rpki_status" => Value::str(o.rpki_status.pg_label()),
                "route_preference_status" => Value::str(o.route_preference_status.pg_label()),
                "updated" => Value::Str(py_datetime_str(o.updated)),
                _ => continue,
            };
            r.set(&snake_to_camel_case(c), v);
        }
        if columns.contains(&"ip_first")
            && let (Some(ip), Some(len)) = (&ip_first_text, o.prefix_length)
            && len != 0
        {
            r.set("prefix", Value::Str(format!("{ip}/{len}")));
        }
        if columns.contains(&"asn_first")
            && let Some(a) = o.asn_first
            && o.asn_last == Some(a)
        {
            r.set("asn", Value::Int(i128::from(a)));
        }
        let Some(type_name) = graphql_type_name(o.object_class) else {
            return internal(format!("KeyError: '{}'", o.object_class));
        };
        let schema = schema();
        let tid = schema.type_id(type_name).unwrap_or(0);
        let parsed = graphql::value::json_loads_str(o.parsed_data).unwrap_or(Value::Null);
        if let Value::Object(fields) = parsed {
            for (key, mut value) in fields {
                if key == "auth"
                    && let Value::List(items) = &value
                {
                    value = Value::List(
                        items
                            .iter()
                            .map(|v| match v {
                                Value::Str(s) => Value::Str(rpsl::text::remove_auth_hashes(s).into_owned()),
                                other => other.clone(),
                            })
                            .collect(),
                    );
                }
                let camel = snake_to_camel_case(&key);
                let Some(fdef) = schema.t(tid).field(&camel) else {
                    return internal(format!("KeyError: '{key}'"));
                };
                let is_string = matches!(&fdef.type_, graphql::schema::TypeRef::Named(t) if schema.t(*t).name == "String");
                if is_string && let Value::List(items) = &value {
                    value = Value::Str(
                        items
                            .iter()
                            .map(|v| v.as_str().unwrap_or_default().to_owned())
                            .collect::<Vec<_>>()
                            .join("\n"),
                    );
                }
                r.set(&camel, value);
            }
        }
        Ok(r)
    }

    fn rpsl_objects(&self, info: &FieldInfo<'_>, args: &[(String, Value)]) -> Result<Value, ResolveError> {
        let kwargs: Vec<(String, &Value)> = args.iter().map(|(k, v)| (camel_to_snake(k), v)).collect();
        let kw = |n: &str| kwargs.iter().find(|(k, _)| k == n).map(|(_, v)| *v);
        let low_keys = [
            "object_class",
            "rpki_status",
            "scope_filter_status",
            "route_preference_status",
            "sources",
            "sql_trace",
        ];
        let only_low = kwargs.iter().all(|(k, _)| low_keys.contains(&k.as_str()));
        let rpki_sufficient = matches!(kw("rpki_status"), Some(Value::List(l)) if l.len() == 1 && matches!(l[0].as_str(), Some("valid" | "invalid")));
        if only_low && !rpki_sufficient {
            return internal(messages::GRAPHQL_MORE_SPECIFIC);
        }
        if kw("sql_trace").is_some_and(Value::truthy) {
            *self.sql_trace.borrow_mut() = true;
        }
        let columns = columns_for_selection(info);
        let mut q = ObjectQuery::default();
        if let Some(v) = kw("record_limit") {
            match v {
                Value::Int(i) => q.limit = Some(i64::try_from(*i).unwrap_or(i64::MAX)),
                // LIMIT NULL: no limit.
                _ => {}
            }
        }
        if let Some(v) = kw("rpsl_pk") {
            let Some(l) = str_list(v) else {
                return internal("TypeError: 'NoneType' object is not iterable");
            };
            q.rpsl_pks = Some(
                l.iter()
                    .map(|p| rpsl::python::strip(&rpsl::python::upper(p)).to_owned())
                    .collect(),
            );
        }
        if let Some(v) = kw("object_class") {
            let Some(l) = str_list(v) else {
                return internal("ArgumentError");
            };
            q.object_classes(l);
        }
        if let Some(v) = kw("asn") {
            let Value::List(l) = v else {
                return internal("ArgumentError");
            };
            q.asns_first = Some(
                l.iter()
                    .filter_map(|x| match x {
                        Value::Int(i) => Some(*i),
                        _ => None,
                    })
                    .collect(),
            );
        }
        if let Some(v) = kw("text_search") {
            let Value::Str(s) = v else {
                return internal("AttributeError");
            };
            q.text_search(s, self.settings);
        }
        let statuses = |v: Option<&Value>| -> Result<Option<Vec<String>>, ResolveError> {
            match v {
                None => Ok(None),
                Some(v) => str_list(v).map(Some).ok_or(ResolveError::Internal("ArgumentError".into())),
            }
        };
        q.rpki = Some(match statuses(kw("rpki_status"))? {
            Some(l) => l.iter().filter_map(|s| RpkiStatus::from_pg_label(s)).collect(),
            None => vec![RpkiStatus::NotFound, RpkiStatus::Valid],
        });
        q.scope = Some(match statuses(kw("scope_filter_status"))? {
            Some(l) => l.iter().filter_map(|s| ScopeFilterStatus::from_pg_label(s)).collect(),
            None => vec![ScopeFilterStatus::InScope],
        });
        q.routepref = Some(match statuses(kw("route_preference_status"))? {
            Some(l) => l
                .iter()
                .filter_map(|s| RoutePreferenceStatus::from_pg_label(s))
                .collect(),
            None => vec![RoutePreferenceStatus::Visible],
        });
        let mut resolver = QueryResolver::new(std::sync::Arc::new(self.settings.clone()));
        if let Some(v) = kw("sources") {
            match v {
                Value::Null => {}
                v => {
                    let l = str_list(v).unwrap_or_default();
                    resolver.set_query_sources(Some(l)).map_err(query_err)?;
                }
            }
        }
        q.sources = Some(
            resolver
                .sources_resolved()
                .iter()
                .map(|s| rpsl::python::strip(&rpsl::python::upper(s)).to_owned())
                .collect(),
        );
        let lookup_names = query::lookup_field_names();
        for (k, v) in &kwargs {
            let attr = k.replace('_', "-");
            if lookup_names.contains(&attr.as_str()) {
                let Some(l) = str_list(v) else {
                    return internal("TypeError: 'NoneType' object is not iterable");
                };
                q.lookups.push((attr, l));
            }
        }
        for (name, f) in [
            ("ip_exact", IpFilter::Exact),
            ("ip_less_specific", IpFilter::LessSpecific),
            ("ip_more_specific", IpFilter::MoreSpecific),
            ("ip_less_specific_one_level", IpFilter::LessSpecificOneLevel),
            ("ip_any", IpFilter::Any),
        ] {
            if let Some(v) = kw(name) {
                let Some(ip) = v.as_str().and_then(|s| rpsl::Ip::parse(s, 0).ok()) else {
                    return internal("TypeError");
                };
                q.ip.push((f, ip));
            }
        }
        self.objects_out(&q, &columns)
    }

    /// `_resolve_subquery()`
    fn subquery(
        &self,
        info: &FieldInfo<'_>,
        parent: &Value,
        classes: Vec<String>,
        pk_field: &str,
        sticky: bool,
    ) -> Result<Value, ResolveError> {
        let pks: Vec<String> = match parent.get(pk_field) {
            None | Some(Value::Null) => return Ok(Value::List(Vec::new())),
            Some(Value::List(l)) if l.is_empty() => return Ok(Value::List(Vec::new())),
            Some(Value::Str(s)) if s.is_empty() => return Ok(Value::List(Vec::new())),
            Some(Value::List(l)) => l.iter().filter_map(|v| v.as_str().map(str::to_owned)).collect(),
            Some(Value::Str(s)) => vec![s.clone()],
            Some(_) => return Ok(Value::List(Vec::new())),
        };
        let columns = columns_for_selection(info);
        let mut q = ObjectQuery::default();
        q.object_classes(classes);
        q.rpsl_pks = Some(
            pks.iter()
                .map(|p| rpsl::python::strip(&rpsl::python::upper(p)).to_owned())
                .collect(),
        );
        if sticky {
            let src = parent.get("source").and_then(Value::as_str).unwrap_or_default();
            q.sources = Some(vec![rpsl::python::strip(&rpsl::python::upper(src)).to_owned()]);
        }
        self.objects_out(&q, &columns)
    }

    fn referring(parent: &Value, attr: &str) -> Vec<String> {
        let class = parent.get("objectClass").and_then(Value::as_str).unwrap_or_default();
        rpsl::class_by_name(class)
            .and_then(|c| c.field(attr))
            .map(|f| f.kind.referring().iter().map(|s| (*s).to_owned()).collect())
            .unwrap_or_default()
    }

    fn journal(&self, parent: &Value) -> Result<Value, ResolveError> {
        let source = parent.get("source").and_then(Value::as_str).unwrap_or_default();
        let list = self.settings.source(source).nrtm_access_list.clone();
        let permitted = self
            .settings
            .is_client_permitted(&self.client_host, list.as_deref(), true)
            .unwrap_or(false);
        if !permitted {
            return Err(ResolveError::GraphQL(messages::journal_denied(source)));
        }
        let pk = parent.get("rpslPk").and_then(Value::as_str).unwrap_or_default();
        let src = rpsl::python::strip(&rpsl::python::upper(source)).to_owned();
        let pk = rpsl::python::strip(&rpsl::python::upper(pk)).to_owned();
        let mut out = Vec::new();
        let entries = self
            .view
            .journal(Some(&src), None, None)
            .map_err(|e| ResolveError::Internal(e.to_string()))?;
        for e in entries {
            let e = e.map_err(|e| ResolveError::Internal(e.to_string()))?;
            if e.rpsl_pk != pk {
                continue;
            }
            out.push(Value::Object(vec![
                ("pk".into(), Value::Str(e.pk.to_string())),
                ("rpslPk".into(), Value::str(e.rpsl_pk)),
                ("source".into(), Value::str(e.source)),
                ("serialNrtm".into(), Value::Int(i128::from(e.serial_nrtm))),
                ("serialGlobal".into(), Value::Int(i128::from(e.serial_global))),
                ("operation".into(), Value::str(e.operation.pg_label())),
                ("objectClass".into(), Value::str(e.object_class)),
                (
                    "objectText".into(),
                    Value::Str(rpsl::text::remove_auth_hashes(e.object_text).into_owned()),
                ),
                ("origin".into(), Value::str(e.origin.pg_label())),
                ("timestamp".into(), Value::Str(py_datetime_str(e.timestamp))),
            ]));
        }
        Ok(Value::List(out))
    }

    fn database_status(&self, args: &[(String, Value)]) -> Result<Value, ResolveError> {
        let sources = match arg(args, "sources") {
            None | Some(Value::Null) => None,
            Some(v) => Some(str_list(v).unwrap_or_default()),
        };
        let rows = self.database_status_rows(sources)?;
        let mut out = Vec::new();
        for (name, data) in rows {
            let Value::Object(fields) = data else { continue };
            // OrderedDict(data), then source, then camelCase copies.
            let mut o = Value::Object(fields.clone());
            o.set("source", Value::Str(name));
            for (k, v) in fields {
                o.set(&snake_to_camel_case(&k), v);
            }
            out.push(o);
        }
        Ok(Value::List(out))
    }

    /// `QueryResolver.database_status()`
    fn database_status_rows(
        &self,
        sources: Option<Vec<String>>,
    ) -> Result<Vec<(String, Value)>, ResolveError> {
        let st = self.settings;
        let sources = sources.unwrap_or_else(|| st.all_valid_sources());
        let invalid: Vec<&String> = sources.iter().filter(|s| !st.is_valid_source(s)).collect();
        let rows = QueryResolver::status_rows(self.view, &sources).map_err(query_err)?;
        let mut results: Vec<(String, Value)> = Vec::new();
        let set = |results: &mut Vec<(String, Value)>, k: String, v: Value| {
            match results.iter_mut().find(|(key, _)| *key == k) {
                Some(e) => e.1 = v,
                None => results.push((k, v)),
            }
        };
        let opt_int = |v: Option<i64>| v.map_or(Value::Null, |i| Value::Int(i128::from(i)));
        let opt_str = |v: Option<String>| v.map_or(Value::Null, Value::Str);
        for row in rows {
            let source = rpsl::python::upper(&row.source).into_owned();
            let s = st.source(&source);
            let o = Value::Object(vec![
                ("source_type".into(), Value::str("regular")),
                ("authoritative".into(), config_value(&s.authoritative)),
                (
                    "object_class_filter".into(),
                    s.object_class_filter.as_ref().map_or(Value::Null, |l| {
                        Value::List(l.iter().map(|c| Value::Str(c.clone())).collect())
                    }),
                ),
                (
                    "rpki_rov_filter".into(),
                    Value::Bool(st.rpki_enabled && !s.rpki_excluded),
                ),
                (
                    "scopefilter_enabled".into(),
                    Value::Bool(st.scopefilter_enabled && !s.scopefilter_excluded),
                ),
                ("route_preference".into(), config_value(&s.route_object_preference)),
                ("local_journal_kept".into(), config_value(&s.keep_journal)),
                ("serial_oldest_journal".into(), opt_int(row.serial_oldest_journal)),
                ("serial_newest_journal".into(), opt_int(row.serial_newest_journal)),
                ("serial_last_export".into(), opt_int(row.serial_last_export)),
                ("serial_newest_mirror".into(), opt_int(row.serial_newest_mirror)),
                (
                    "nrtm4_client_session_id".into(),
                    opt_str(row.nrtm4_client_session_id.map(|u| u.to_string())),
                ),
                ("nrtm4_client_version".into(), opt_int(row.nrtm4_client_version)),
                (
                    "nrtm4_server_session_id".into(),
                    opt_str(row.nrtm4_server_session_id.map(|u| u.to_string())),
                ),
                ("nrtm4_server_version".into(), opt_int(row.nrtm4_server_version)),
                (
                    "nrtm4_server_last_update_notification_file_update".into(),
                    opt_str(
                        row.nrtm4_server_last_update_notification_file_update
                            .map(query::status::isoformat),
                    ),
                ),
                (
                    "nrtm4_server_last_snapshot_version".into(),
                    opt_int(row.nrtm4_server_last_snapshot_version),
                ),
                (
                    "rpsl_data_updated".into(),
                    Value::Str(query::status::isoformat(row.rpsl_data_updated)),
                ),
                ("last_update".into(), Value::Str(query::status::isoformat(row.updated))),
                (
                    "synchronised_serials".into(),
                    Value::Bool(query::status::is_serial_synchronised(st, &row)),
                ),
            ]);
            set(&mut results, source, o);
        }
        for s in &sources {
            if let Some(aliased) = st.alias(s) {
                set(
                    &mut results,
                    s.clone(),
                    Value::Object(vec![
                        ("source_type".into(), Value::str("alias")),
                        (
                            "aliased_sources".into(),
                            Value::List(aliased.iter().map(|a| Value::Str(a.clone())).collect()),
                        ),
                    ]),
                );
            }
        }
        for s in invalid {
            set(
                &mut results,
                rpsl::python::upper(s).into_owned(),
                Value::Object(vec![("error".into(), Value::str("Unknown source"))]),
            );
        }
        Ok(results)
    }

    fn resolver(&self, sources: Option<&Value>) -> Result<QueryResolver, ResolveError> {
        let mut r = QueryResolver::new(std::sync::Arc::new(self.settings.clone()));
        let s = match sources {
            None | Some(Value::Null) => None,
            Some(v) => Some(str_list(v).unwrap_or_default()),
        };
        r.set_query_sources(s).map_err(query_err)?;
        Ok(r)
    }

    fn ip_version(args: &[(String, Value)]) -> Result<Option<u8>, ResolveError> {
        match arg(args, "ipVersion") {
            None | Some(Value::Null) => Ok(None),
            Some(Value::Int(4)) => Ok(Some(4)),
            Some(Value::Int(6)) => Ok(Some(6)),
            // Any other version selects nothing in v4's preload.
            Some(_) => Ok(Some(0)),
        }
    }

    fn prefixes(list: Vec<(u8, u128, u8)>, version: Option<u8>) -> Value {
        Value::List(
            list.into_iter()
                .filter(|(v, _, _)| version != Some(0) || *v == 0)
                .map(|(v, a, l)| Value::Str(query::resolver::prefix_text(v, a, l)))
                .collect(),
        )
    }

    fn asn_prefixes(&self, args: &[(String, Value)]) -> Result<Value, ResolveError> {
        let r = self.resolver(arg(args, "sources"))?;
        let version = Self::ip_version(args)?;
        let asns = match arg(args, "asns") {
            Some(Value::List(l)) => l.clone(),
            _ => Vec::new(),
        };
        let mut out = Vec::new();
        for asn in asns {
            let text = match &asn {
                Value::Int(i) => format!("AS{i}"),
                Value::BigInt(s) => format!("AS{s}"),
                other => format!("AS{}", py_str(other)),
            };
            let prefixes = if version == Some(0) {
                Vec::new()
            } else {
                r.routes_for_origin(self.view, &text, version).map_err(query_err)?
            };
            out.push(Value::Object(vec![
                ("asn".into(), asn),
                ("prefixes".into(), Self::prefixes(prefixes, version)),
            ]));
        }
        Ok(Value::List(out))
    }

    /// `{i.upper() for i in set_names}`: a set, iterated in first-seen
    /// order here (v4's order changes from one start to the next).
    fn upper_set(v: Option<&Value>) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for s in v.and_then(str_list).unwrap_or_default() {
            let u = rpsl::python::upper(&s).into_owned();
            if !out.contains(&u) {
                out.push(u);
            }
        }
        out
    }

    fn as_set_prefixes(&self, args: &[(String, Value)]) -> Result<Value, ResolveError> {
        let trace = arg(args, "sqlTrace").is_some_and(Value::truthy);
        let names = Self::upper_set(arg(args, "setNames"));
        let exclude = Self::upper_set(arg(args, "excludeSets"));
        let r = self.resolver(arg(args, "sources"))?;
        let version = Self::ip_version(args)?;
        let mut out = Vec::new();
        for name in names {
            let prefixes = if version == Some(0) {
                Vec::new()
            } else {
                r.routes_for_as_set(self.view, &name, version, &exclude)
                    .map_err(query_err)?
            };
            out.push(Value::Object(vec![
                ("rpslPk".into(), Value::Str(name)),
                ("prefixes".into(), Self::prefixes(prefixes, version)),
            ]));
        }
        if trace {
            *self.sql_queries.borrow_mut() = Some(Vec::new());
        }
        Ok(Value::List(out))
    }

    fn recursive_set_members(&self, args: &[(String, Value)]) -> Result<Value, ResolveError> {
        let trace = arg(args, "sqlTrace").is_some_and(Value::truthy);
        let names = Self::upper_set(arg(args, "setNames"));
        let exclude = Self::upper_set(arg(args, "excludeSets"));
        let depth = match arg(args, "depth") {
            None => 0,
            Some(Value::Int(i)) => i64::try_from(*i).unwrap_or(i64::MAX),
            // depth=None: `None -= 1` raises a TypeError.
            Some(_) => return internal("TypeError: unsupported operand type(s) for -=: 'NoneType' and 'int'"),
        };
        let mut r = self.resolver(arg(args, "sources"))?;
        let mut trace_entries = Vec::new();
        let mut out = Vec::new();
        for name in names {
            if trace {
                trace_entries.push(crate::sqltrace::set_sources_query(&r, &name));
            }
            for (source, members) in r
                .members_for_set_per_source(self.view, &name, &exclude, depth, true)
                .map_err(query_err)?
            {
                out.push(Value::Object(vec![
                    ("rpslPk".into(), Value::Str(name.clone())),
                    ("rootSource".into(), Value::Str(source)),
                    ("members".into(), Value::List(members.into_iter().map(Value::Str).collect())),
                ]));
            }
        }
        if trace {
            *self.sql_queries.borrow_mut() = Some(trace_entries);
        }
        Ok(Value::List(out))
    }
}

impl graphql::Resolvers for Resolvers<'_, '_> {
    fn resolve(
        &self,
        info: &FieldInfo<'_>,
        parent: &Value,
        args: &[(String, Value)],
    ) -> Option<Result<Value, ResolveError>> {
        let schema = schema();
        if info.parent_type == "Query" {
            return Some(match info.field_name {
                "rpslObjects" => self.rpsl_objects(info, args),
                "databaseStatus" => self.database_status(args),
                "asnPrefixes" => self.asn_prefixes(args),
                "asSetPrefixes" => self.as_set_prefixes(args),
                "recursiveSetMembers" => self.recursive_set_members(args),
                _ => return None,
            });
        }
        let is_rpsl_type = info.parent_type.starts_with("RPSL")
            && schema
                .type_id(info.parent_type)
                .is_some_and(|t| schema.t(t).interfaces.iter().any(|i| schema.t(*i).name == "RPSLObject"));
        if !is_rpsl_type {
            return None;
        }
        let has_field = |f: &str| {
            schema
                .type_id(info.parent_type)
                .is_some_and(|t| schema.t(t).field(f).is_some())
        };
        Some(match info.field_name {
            "mntByObjs" => self.subquery(info, parent, vec!["mntner".into()], "mntBy", true),
            "journal" => self.journal(parent),
            "adminCObjs" if has_field("adminCObjs") => {
                self.subquery(info, parent, vec!["role".into(), "person".into()], "adminC", true)
            }
            "techCObjs" if has_field("techCObjs") => {
                self.subquery(info, parent, vec!["role".into(), "person".into()], "techC", true)
            }
            "mbrsByRefObjs" if has_field("mbrsByRefObjs") => {
                self.subquery(info, parent, vec!["mntner".into()], "mbrsByRef", true)
            }
            "memberOfObjs" if has_field("memberOfObjs") => {
                let classes = Self::referring(parent, "member-of");
                self.subquery(info, parent, classes, "memberOf", true)
            }
            "membersObjs" if has_field("membersObjs") => {
                let classes: Vec<String> = Self::referring(parent, "members")
                    .into_iter()
                    .filter(|c| c != "aut-num" && c != "inet-rtr")
                    .collect();
                self.subquery(info, parent, classes, "members", false)
            }
            _ => return None,
        })
    }

    fn resolve_type(&self, _abstract_type: &str, value: &Value) -> Result<Option<String>, ResolveError> {
        let class = value
            .get("objectClass")
            .or_else(|| value.get("object_class"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        match graphql_type_name(class) {
            Some(n) => Ok(Some(n.to_owned())),
            None => internal(format!("KeyError: '{class}'")),
        }
    }
}

impl graphql::Extensions for Resolvers<'_, '_> {
    fn sql_queries(&self) -> Option<Vec<String>> {
        self.sql_queries.borrow().clone()
    }
}
