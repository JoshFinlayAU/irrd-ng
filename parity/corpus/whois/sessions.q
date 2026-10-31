# Multi-command (keepalive) sessions: state carried across queries, framing
# of consecutive answers, and what closes the connection.

@tags session,keepalive
@session
!!
!v
!v
@end
@session
!!
!v
!q
!v
@end
@session
!v
!v
@end
@session
!!
!!
!v
@end
@session
!!

!v

@end
@session
-k
-t aut-num
-t route
@end
@session
-k
-k
{aut_num}
@end
@session
-k
!v
!gAS64496
-x 192.0.2.0/24
@end
@session
!!
-x 192.0.2.0/24
!v
@end
@session
!!
!t300
!v
@end
@session
!!
!tfoo
!v
@end
@session
!!
!nbgpq4
!v
@end
@session
!!
!x
!v
!gASfoobar
!v
@end

@tags session,state
@session
!!
!s-lc
!sRADB
!s-lc
!s-*
!s-lc
!sUNKNOWN
!s-lc
@end
@session
!!
!sRADB,ARIN
!g{origin4}
!s{source}
!g{origin4}
@end
@session
!!
!e-lc
!eAS-A,AS-B
!e-lc
!e
!e-lc
@end
@session
-k
-s RADB
{aut_num}
-a
{aut_num}
@end
@session
-k
-T aut-num
{aut_num}
{aut_num}
@end
@session
-k
-K
{as_set}
{as_set}
@end
@session
!!
!fno-rpki-filter
!r{route4.prefix}
-x {route4.prefix}
!fno-scope-filter
!fno-route-preference-filter
!r{route4.prefix},L
@end

@tags session,mixed
@limit 10
@session
!!
!g{origin4}
!6{origin6}
!i{as_set},1
!a4{as_set}
!r{route4.prefix},o
!m{obj.cls},{obj.pk}
!o{mntner}
-x {route4.prefix}
{aut_num}
!j-*
!v
@end
@session
!!
!rnot-a-prefix
!r{route4.prefix},L
!mfoo
!maut-num,{aut_num}
!gASfoobar
!g{origin_many4}
@end
