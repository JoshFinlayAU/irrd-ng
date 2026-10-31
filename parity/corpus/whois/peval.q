# peval (IRRToolSet, built from github.com/irrtoolset/irrtoolset master)
# query sequences, captured through tools/fault_proxy.py --log against v4
# (2026-10-31). peval keeps one !! session: !s-*, !s-lc, then !i<set>,1 for
# the set, !v, and one RIPE-style `-K -r -i origin ASn` per member AS
# (inside the IRRd keepalive session). A route-set needs only !i<set>,1, a
# single ASN only !v and the -K query.

@tags peval
@limit 10
@session
!!
!s-*
!s-lc
!i{as_set_large},1
!v
-K -r -i origin {origin_many4}
-K -r -i origin {origin4}
-K -r -i origin {origin6}
-K -r -i origin {aut_num_no_routes}
@end
@session
!!
!s-*
!s-lc
!i{route_set_deep},1
@end
@session
!!
!s-*
!s-lc
!v
-K -r -i origin {origin_many4}
@end
