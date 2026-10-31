# whois query corpus

Queries only, no registry data. `parity/run.sh` expands these templates
against the data actually loaded (`tools/corpus_bindings.py` picks the
objects, `tools/corpus_expand.py` substitutes them) and replays the result
against v4 and irrd-ng with `tools/whois_diff.py`.

| file | what |
|---|---|
| `irrd.q` | every IRRd-style command (`!v !t !n !s !j !J !g !6 !i !a !e !m !o !r !f !! !q`) with valid, invalid and edge arguments, including all of v4's `test_query_parser.py` queries |
| `ripe.q` | every RIPE flag (`-k -a -F -r -s -T -t -i -K -V -q -g -x -l -L -M`), `-t` for all 19 classes, free-text search |
| `sets.q` | the deepest, largest, looping, dangling and `mbrs-by-ref` sets, case, `!e` exclusions, `!s` restrictions |
| `sessions.q` | keepalive sessions: `!!`, `-k`, `!q`, empty lines, state carried across queries (`!s`, `!e`, `-s`, `-T`, `-K`, `!f`) |
| `bgpq4.q` | bgpq4 1.12's exact query sequences, captured from its traffic |
| `peval.q` | peval's (IRRToolSet) query sequences, captured the same way |
| `irrexplorer.q` | the whois equivalents of what irrexplorer-ng asks (it uses GraphQL; see `../graphql/irrexplorer.graphql`) |
| `unordered.tsv` | the answers whose order v4 itself does not fix, and how they are compared |

## Syntax

```
# comment
@tags a,b            tags for the following items (the file stem is always a tag)
@limit N             expansions per templated item (default 25, times --scale)
!gAS64496            one query on its own connection
!g{origin4}          a template: one item per bound value
!m{obj.cls},{obj.pk} fields of the same record advance together
!i{as_set|lower},1   |lower and |upper change case
@session             the lines up to @end go over one connection
!!
!v
@end
@raw !v\r\n          exact bytes (\n \r \t \\ \xHH), no newline added
```

Lines are sent as written, followed by `\n`; trailing spaces count. An item
whose placeholder has no value in the loaded data is dropped and counted.
Item ids are `<file>:<line>[#k]`, stable for a given data set.

## Placeholders

Defined in `tools/corpus_bindings.py`: `as_set`, `as_set_deep`,
`as_set_large`, `as_set_loop`, `as_set_dangling`, `as_set_hier`,
`as_set_refd`, `as_set_wide`, `as_set_empty`, `route_set`, `route_set_deep`,
`route_set_hier`, `route_set_loop`, `aut_num`, `aut_num_no_routes`,
`origin4`, `origin6`, `origin_many4`, `origin_many6`, `large_origin`,
`route4`/`route6` (`.prefix .origin .net .len`), `route4_covering`,
`route6_covering`, `route4_nested`, `route6_nested`, `route4_host`,
`route6_host`, `mntner`, `mntner_busy`, `member_of_target`,
`mbrs_by_ref_mnt`, `obj` (`.cls .pk`, every class present), `source`,
`sources_csv`.

## Adding queries

Add the query to the file it belongs in, run `parity/run.sh --test v4-twin`
to make sure v4 answers it the same way twice, and commit. Never add
expected output: v4 is the expectation, every run.
