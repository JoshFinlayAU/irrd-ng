#!/usr/bin/env python3
"""Build an HTTP API load mix for loadgen (mode `http`) from the corpus
bindings: GraphQL lookups of the kinds irrexplorer and similar tools send,
set expansion over GraphQL, /v1/whois/, /v1/status/ and /metrics/.

    http_mix.py --bindings bindings.json [--limit N] > mix.tsv
"""

import argparse
import json


def gql(query, variables=None):
    body = {"query": query}
    if variables is not None:
        body["variables"] = variables
    return "POST /graphql/ " + json.dumps(body, separators=(",", ":"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bindings", required=True)
    ap.add_argument("--limit", type=int, default=25)
    args = ap.parse_args()
    b = json.load(open(args.bindings))
    lines = []

    def add(weight, cls, spec):
        lines.append(f"{weight}\t{cls}\thttp\t{spec}")

    route_fields = "rpslPk source ... on RPSLRoute { prefix asn rpkiStatus } ... on RPSLRoute6 { prefix asn rpkiStatus }"
    for r in b.get("route4", [])[: args.limit]:
        add(4, "gql_ip_any", gql(
            "query($p: IP!) { rpslObjects(ipAny: $p, objectClass: [\"route\", \"route6\"], "
            "rpkiStatus: [valid, invalid, not_found]) { " + route_fields + " } }", {"p": r["prefix"]}))
    for a in b.get("origin4", [])[: args.limit]:
        add(4, "gql_origin", gql(
            "query($a: [ASN!]) { rpslObjects(asn: $a, objectClass: [\"route\", \"route6\"]) { "
            + route_fields + " } }", {"a": [int(a[2:])]}))
        add(2, "gql_asn_prefixes", gql("{ asnPrefixes(asns: [%s]) { asn prefixes } }" % a[2:]))
    for pk in b.get("aut_num", [])[: args.limit]:
        add(3, "gql_pk", gql("{ rpslObjects(rpslPk: \"%s\") { rpslPk source objectText "
                             "mntByObjs { rpslPk } } }" % pk))
    for s in b.get("as_set_large", [])[:5]:
        add(1, "gql_set_prefixes", gql("{ asSetPrefixes(setNames: [\"%s\"]) { rpslPk prefixes } }" % s))
        add(1, "gql_set_members", gql("{ recursiveSetMembers(setNames: [\"%s\"]) "
                                      "{ rpslPk rootSource members } }" % s))
    for pk in b.get("aut_num", [])[: args.limit]:
        add(3, "whois_http", f"GET /v1/whois/?q=!m{'aut-num'},{pk}")
    add(1, "status", "GET /v1/status/")
    add(1, "metrics", "GET /metrics/")
    add(1, "gql_db_status", gql("{ databaseStatus { source serialNewestJournal lastUpdate } }"))
    print("\n".join(lines))


if __name__ == "__main__":
    main()
