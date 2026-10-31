# What irrexplorer-ng asks IRRd, as whois. irrexplorer-ng itself talks
# GraphQL only (src/server/sources/irrd.ts): rpslObjects by ipAny, by asn,
# by members and by rpslPk, and recursiveSetMembers depth 1. These are the
# whois queries that answer the same questions; the GraphQL forms are kept
# in parity/corpus/graphql/irrexplorer.graphql for the graphql suite.

@tags irrexplorer
!r{route4.prefix},L
!r{route4.prefix},M
!r{route6.prefix},L
!r{route6.prefix},M
!r{route4_host},L
-i origin {origin4}
-i origin {origin6}
-T route,route6 -i origin {origin_many4}
!i{as_set}
!i{route_set}
-i members {aut_num}
-T as-set -i members {aut_num}
-T aut-num {aut_num}
-T as-set {as_set}
-i mbrs-by-ref {mbrs_by_ref_mnt}
-s {source} -T as-set {as_set}
!m{obj.cls},{obj.pk}
