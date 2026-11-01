//! Behaviours of graphql-core 3.3 and ariadne 1.1 that IRRd 4.5.4 exposes,
//! checked against answers recorded from v4 (parity/corpus/graphql has
//! the same cases for the differential run).

use graphql::{
    Extensions, FieldInfo, Outcome, ResolveError, Resolvers, ScalarError, ScalarParsers, Schema,
    Value,
};

const SDL: &str = r#"
enum Status {
  valid
  invalid
}

scalar ASN

type Query {
  objects(pk: [String!], limit: Int, asn: [ASN!], status: [Status!]): [Obj!]
  sets(names: [String!]!, depth: Int): [Obj!]
}

interface Thing {
  pk: String
}

type Obj implements Thing {
  pk: String
  name: String!
  tags: [String!]
}
"#;

struct NoScalars;
impl ScalarParsers for NoScalars {
    fn parse_value(&self, name: &str, v: &Value) -> Result<Value, ScalarError> {
        match (name, v) {
            ("ASN", Value::Str(s)) => s
                .parse::<i128>()
                .map(Value::Int)
                .map_err(|_| ScalarError::GraphQL(format!("Invalid ASN: {s}; must be numeric"))),
            ("ASN", Value::Int(_)) => Ok(v.clone()),
            ("ASN", _) => Err(ScalarError::Other("int() argument must be a string".into())),
            _ => Ok(v.clone()),
        }
    }
}

struct Data;
impl Resolvers for Data {
    fn resolve(
        &self,
        info: &FieldInfo<'_>,
        _parent: &Value,
        _args: &[(String, Value)],
    ) -> Option<Result<Value, ResolveError>> {
        match (info.parent_type, info.field_name) {
            ("Query", "objects") => Some(Ok(Value::List(vec![Value::Object(vec![
                ("pk".into(), Value::str("A")),
                ("tags".into(), Value::List(vec![Value::str("x")])),
            ])]))),
            ("Query", "sets") => Some(Err(ResolveError::Internal("ValueError".into()))),
            _ => None,
        }
    }

    fn resolve_type(&self, _t: &str, _v: &Value) -> Result<Option<String>, ResolveError> {
        Ok(Some("Obj".into()))
    }
}

impl Extensions for Data {
    fn sql_queries(&self) -> Option<Vec<String>> {
        None
    }
}

fn run(body: &str) -> (bool, String) {
    let schema = Schema::from_sdl(SDL);
    let data = graphql::value::json_loads_str(body).expect("json");
    match graphql::graphql(&schema, &NoScalars, &Data, &Data, &data, &|| 0.0) {
        Outcome::Result(ok, v) => (ok, graphql::value::json_dumps(&v)),
        Outcome::Crash(e) => (false, format!("crash: {e}")),
    }
}

fn q(query: &str) -> String {
    run(&graphql::value::json_dumps(&Value::Object(vec![(
        "query".into(),
        Value::str(query),
    )])))
    .1
}

#[test]
fn syntax_error_location_at_line_start_reports_previous_line() {
    // Source.get_location() uses str.splitlines().
    assert_eq!(
        q("{\n"),
        r#"{"errors":[{"message":"Syntax Error: Expected Name, found <EOF>.","locations":[{"line":1,"column":2}]}],"extensions":{"execution":0.0}}"#
    );
}

#[test]
fn cost_validator_rejects_variables_in_required_arguments() {
    // ariadne computes argument values without variables, and reports
    // str(error) with the printed source location.
    let out = q("query($n: [String!]!) { sets(names: $n) { pk } }");
    assert!(
        out.starts_with(r#"{"errors":[{"message":"Invalid argument\n\nGraphQL request:1:37\n1 | query($n: [String!]!) { sets(names: $n) { pk } }\n  |                                     ^"}"#),
        "{out}"
    );
}

#[test]
fn directive_locations_are_shown_in_lower_case_words() {
    let out = q("query @skip(if: true) { __typename }");
    assert!(
        out.contains("Directive '@skip' may not be used on query."),
        "{out}"
    );
}

#[test]
fn object_literal_for_a_leaf_has_no_location() {
    let out = q("{ objects(limit: {a: 1}) { pk } }");
    assert!(
        out.contains(r#"{"message":"Int cannot represent non-integer value: { a: 1 }"}"#),
        "{out}"
    );
}

#[test]
fn custom_scalar_exceptions_are_hidden_and_graphql_errors_are_not() {
    let out = q("{ objects(asn: {a: 1}) { pk } }");
    assert!(
        out.contains(r#""message":"Internal server error","locations""#),
        "{out}"
    );
    let out = q(r#"{ objects(asn: "AS1") { pk } }"#);
    assert!(
        out.contains(r#"{"message":"Invalid ASN: AS1; must be numeric"}"#),
        "{out}"
    );
}

#[test]
fn non_null_violation_is_an_internal_error_with_a_path() {
    let out = q("{ objects { name } }");
    assert_eq!(
        out,
        r#"{"data":{"objects":null},"errors":[{"message":"Internal server error","locations":[{"line":1,"column":13}],"path":["objects",0,"name"]}],"extensions":{"execution":0.0}}"#
    );
}

#[test]
fn resolver_exceptions_null_the_field() {
    let out = q(r#"{ sets(names: ["X"]) { pk } }"#);
    assert_eq!(
        out,
        r#"{"data":{"sets":null},"errors":[{"message":"Internal server error","locations":[{"line":1,"column":3}],"path":["sets"]}],"extensions":{"execution":0.0}}"#
    );
}

#[test]
fn suggestions_and_unknown_fields() {
    let out = q("{ object { pk } }");
    assert!(
        out.contains("Cannot query field 'object' on type 'Query'. Did you mean 'objects'?"),
        "{out}"
    );
}

#[test]
fn request_shapes() {
    assert_eq!(
        run("[]").1,
        r#"{"errors":[{"message":"Operation data should be a JSON object"}],"extensions":{"execution":0.0}}"#
    );
    assert_eq!(
        run(r#"{"query": "{ __typename }", "operationName": 5}"#).1,
        r#"{"errors":[{"message":"\"5\" is not a valid operation name."}],"extensions":{"execution":0.0}}"#
    );
    assert_eq!(
        run(r#"{"query": "{ __typename }"}"#),
        (
            true,
            r#"{"data":{"__typename":"Query"},"extensions":{"execution":0.0}}"#.to_owned()
        )
    );
}

#[test]
fn type_map_order_puts_built_in_scalars_after_their_first_use() {
    let schema = Schema::from_sdl(SDL);
    let names: Vec<&str> = schema.types.iter().map(|t| t.name.as_str()).collect();
    assert_eq!(
        &names[..7],
        &["Status", "ASN", "Query", "String", "Int", "Thing", "Obj"]
    );
}

/// Deeply nested documents end in v4's `RecursionError` (a 500) at a fixed
/// depth instead of overflowing the stack.
#[test]
fn deep_nesting_is_a_recursion_error() {
    let max = graphql::parser::MAX_NESTING;
    let crash = format!("crash: {}", graphql::parser::RECURSION_ERROR);
    let selections = |n: usize| format!("{}{}", "{ a ".repeat(n), "}".repeat(n));
    // The outermost braces are the operation's own selection set.
    let ok = q(&selections(max));
    assert!(
        ok.contains("Cannot query field 'a' on type 'Query'."),
        "{ok}"
    );
    assert_eq!(q(&selections(max + 1)), crash);
    let values = |n: usize| {
        format!(
            "{{ objects(pk: {}\"x\"{}) {{ pk }} }}",
            "[".repeat(n),
            "]".repeat(n)
        )
    };
    assert!(!q(&values(max - 1)).starts_with("crash"));
    assert_eq!(q(&values(max)), crash);
    let objects = |n: usize| {
        format!(
            "{{ objects(pk: {}1{}) {{ pk }} }}",
            "{a: ".repeat(n),
            "}".repeat(n)
        )
    };
    assert!(!q(&objects(max - 1)).starts_with("crash"));
    assert_eq!(q(&objects(max)), crash);
    let types = |n: usize| {
        format!(
            "query($v: {}String{}) {{ objects(pk: $v) {{ pk }} }}",
            "[".repeat(n),
            "]".repeat(n)
        )
    };
    assert!(!q(&types(max)).starts_with("crash"));
    assert_eq!(q(&types(max + 1)), crash);
    // Far past the limit, as an attacker would send it.
    assert_eq!(q(&"[".repeat(100_000)), q("["));
    assert_eq!(q(&format!("{{ objects(pk: {}", "[".repeat(100_000))), crash);
    assert_eq!(q(&"{ a ".repeat(100_000)), crash);
}
