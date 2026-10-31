# bgpq4 1.12 query sequences, captured from its traffic through
# tools/fault_proxy.py --log against v4 (2026-10-31). bgpq4 opens one
# keepalive session per run: !!, identifies itself with !n, probes !a
# support with a bare !a (an F error), reads !s-lc, sets the sources
# (its own list back, or -S), asks, and ends with !q. -L walks set levels
# with non-recursive !i and then asks !g per AS in lower case; -f/-G/-H
# ask !i<set>,1; a single ASN goes straight to !g/!6.

@tags bgpq4
@limit 10
# bgpq4 -4|-6 [-A] [-m N] [-R N] [-b] [-X] [-U] [-E] [-J] [-j] [-F ...] AS-SET
@session
!!
!nbgpq4 1.12
!a
!s-lc
!a4{as_set_large}
!s{sources_csv}
!q
@end
@session
!!
!nbgpq4 1.12
!a
!s-lc
!a6{as_set_large}
!s{sources_csv}
!q
@end
@session
!!
!nbgpq4 1.12
!a
!s-lc
!a4{as_set_deep}
!s{sources_csv}
!q
@end
# bgpq4 -S RADB,ARIN -4 AS-SET
@session
!!
!nbgpq4 1.12
!a
!sRADB,ARIN
!a4{as_set_large}
!sRADB,ARIN
!q
@end
# bgpq4 -f|-G|-H <asn> AS-SET (as-path and AS lists)
@session
!!
!nbgpq4 1.12
!a
!s-lc
!s{sources_csv}
!i{as_set_large},1
!q
@end
# bgpq4 -4 RS-SET (route-set, any form)
@session
!!
!nbgpq4 1.12
!s-lc
!s{sources_csv}
!s{sources_csv}
!i{route_set_deep},1
!q
@end
# bgpq4 -4 ASN, and bgpq4 -6 -A ASN AS-SET
@session
!!
!nbgpq4 1.12
!s-lc
!s{sources_csv}
!g{origin_many4|lower}
!q
@end
@session
!!
!nbgpq4 1.12
!a
!s-lc
!a6{as_set_large}
!s{sources_csv}
!6{origin_many6|lower}
!q
@end
# bgpq4 -L 2 AS-SET: set levels by non-recursive !i, then !g per AS
@session
!!
!nbgpq4 1.12
!a
!s-lc
!s{sources_csv}
!i{as_set_deep}
!i{as_set}
!g{origin4|lower}
!g{origin_many4|lower}
!g{aut_num_no_routes|lower}
!q
@end
# bgpq4 against an AS-SET that does not exist
@session
!!
!nbgpq4 1.12
!a
!s-lc
!a4AS-NONEXISTENT-ZZZ
!s{sources_csv}
!q
@end
