# GraphQL and HTTP API corpora

`tools/http_diff.py` replays these against v4 and irrd-ng and compares the responses (`parity/run.sh --suite graphql|api|events`). The GraphQL suite reads `corpus/graphql/*.gq`; the api and events suites read `corpus/http/api.gq` and `corpus/http/events.gq`.

## Syntax

- `# comment` lines and blank lines between items are ignored.
- `@tags a,b` tags the items that follow; the file name is always a tag.
- `@limit N` caps how many times a templated item is expanded (default 10).
- `@gql [OperationName]` starts a GraphQL request. The query text follows, up to `@end`. A line `@variables <JSON>` inside it sets `variables`. The request is `POST /graphql/` with `Content-Type: application/json` and a body of `query`, `variables` (when given) and `operationName` (when given).
- `@request METHOD PATH` starts a raw request: header lines, then a blank line and the body (if any), up to `@end`. Without a blank line there is no body.
- `@ws [extensions]` starts a WebSocket session to `/v1/event-stream/`, offering `extensions` if given. Lines `send <text>` send a text message; `wait` collects messages until the server is quiet for 1.5 seconds or closes.

`{name}`, `{name.field}`, `{name|lower}`, `{name|upper}` and `{name|digits}` take values from the corpus bindings (`tools/corpus_bindings.py`), as in the whois corpus; `|digits` keeps only the digits (an AS number for an `ASN` argument). An item is repeated once per value, up to the limit, and dropped when the data has no values for a placeholder.

## What is masked and what may be reordered

Two servers legitimately differ in the `date` header, GraphQL's `extensions.execution` time (and so the content length), the `Listening on` line of `/v1/status/` (each server's own address), the time-dependent values in `/metrics/`, the initial download's `generated_at` and `generated_on`, and the event stream's `event_id`. These are masked.

Where v4's own order is not fixed, a permutation of v4's answer counts as "equivalent", never "same": lists of RPSL objects (PostgreSQL returns them without `ORDER BY`), `prefixes` and the per-set results of `asSetPrefixes` and `recursiveSetMembers` (Python set order), `errors` (async resolvers finish in any order), the selected columns in an SQL trace (a Python set) and the rows of the initial download. Everything else must be byte-identical.
