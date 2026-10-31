# IRRd-style commands: every command with valid, invalid and edge arguments.
# One query per connection unless inside @session. See README.md for syntax.

@tags irrd,basic
!v
!V
!x
!
!!
!q
!Q
!fno-rpki-filter
!FNO-RPKI-FILTER
!fno-scope-filter
!fno-route-preference-filter
!fno-rpki
!f
!fno-rpki-filter,extra
 !v
!v   
@raw !v\r\n
@raw !v
@raw \x00 foo\n
@raw !v\x00\n
@raw !\xff\xfe\n
@raw !gAS\xc3\xa9\n

@tags irrd,t
!t
!t300
!t1
!t1000
!t1001
!t0
!t-1
!tfoo
!t 300
!t3.5

@tags irrd,n
!n
!nuser-agent
!nbgpq4 with spaces
!n!!

@tags irrd,s
!s-lc
!s-*
!s
!s-LC
!sRADB
!sradb
!sRADB,ARIN
!sRADB,UNKNOWN
!sUNKNOWN
!s,
!sRADB,
!s{source}
!sRPKI

@tags irrd,j
!j
!j-*
!jRADB
!jradb,arin
!jRADB,UNKNOWN
!jUNKNOWN
!j{source}
!j-
!jRPKI
!J
!J-*
!JRADB
!Jradb,ARIN
!JUNKNOWN
!J{source}

@tags irrd,g
!g
!gAS
!gAS0
!gAS64496
!gas64496
!gAS064496
!g64496
!gAS4294967295
!gAS4294967296
!gAS1.10
!gAS65536.0
!gASfoobar
!gAS-FOO
!g AS64496
!g{origin4}
!g{origin_many4}
!g{aut_num_no_routes}
!6
!6AS64496
!6as065547
!6ASfoobar
!6{origin6}
!6{origin_many6}
!6{origin4}

@tags irrd,i
!i
!i123
!iAS-NONEXISTENT-ZZZ
!iAS-NONEXISTENT-ZZZ,1
!iAS64496
!iRS-NONEXISTENT-ZZZ,1
!i{as_set}
!i{as_set},1
!i{as_set_hier}
!i{as_set_hier},1
!i{route_set}
!i{route_set},1
!i{as_set},0
!i{as_set},2
!i{as_set},
!i{as_set_empty}
!i{as_set_empty},1

@tags irrd,a
!a
!a4
!a6
!aAS-NONEXISTENT-ZZZ
!a4AS-NONEXISTENT-ZZZ
!aAS64496
!a{as_set}
!a4{as_set}
!a6{as_set}
!a{route_set}
!a4{route_set}
!a{aut_num}

@tags irrd,e
!e
!e-lc
!eAS-A,AS-b
!e,

@tags irrd,m
!m
!mfoo
!maut-num
!maut-num,
!maut-num,AS64496
!mAUT-NUM,AS64496
!mroute,192.0.2.0/25
!mroute,192.0.2.0/25-As65530
!mroute,192.0.2.0/25 AS65530
!mroute,192.0.2.0/25AS65530
!mnosuchclass,FOO
!m{obj.cls},{obj.pk}
@limit 10
!m{obj.cls},{obj.pk},extra
@limit 25
!mroute,{route4.prefix}{route4.origin}
!mroute,{route4.prefix} {route4.origin}
!mroute,{route4.prefix}-{route4.origin}
!mroute6,{route6.prefix}{route6.origin}
!mroute,{route4.prefix}
!mroute6,{route6.prefix}{route4.origin}
!maut-num,{aut_num}
!mas-set,{as_set}
!mroute-set,{route_set}
!mmntner,{mntner}

@tags irrd,o
!o
!oMNT-NOT-EXISTING
!o{mntner}
!o{mntner_busy}

@tags irrd,r
!r
!rz
!rz,o
!r192.0.2.0/25
!r192.0.2.0/25,o
!r192.0.2.0/25,l
!r192.0.2.0/25,L
!r192.0.2.0/25,M
!r192.0.2.0/25,z
!r192.0.2.0/25,
!r192.0.2.0/25,o,l
!r192.0.2.0/32,o
!r192.0.2.1
!r192.0.2.1/24
!r192.0.2.0/33
!r192.0.2.0/-1
!r192.0.2.0/24.0
!r0.0.0.0/0,M
!r0.0.0.0/0
!r::/0
!r2001:db8::/32
!r2001:db8::/129
!r2001:DB8::/32,o
!r10.0.0.0/8,M
!r1.2.3
!r1.2.3.4.5
!r010.0.0.0/8
!r192.0.2.0-192.0.2.255
!r192.0.2.0/255.255.255.0
!r{route4.prefix}
!r{route4.prefix},o
!r{route4.prefix},l
!r{route4.prefix},L
!r{route4.prefix},M
!r{route4_covering},M
!r{route4_covering},o
!r{route4_nested},l
!r{route4_nested},L
!r{route4_host},l
!r{route4_host},L
!r{route4_host}
!r{route6.prefix}
!r{route6.prefix},o
!r{route6.prefix},l
!r{route6.prefix},L
!r{route6.prefix},M
!r{route6_covering},M
!r{route6_nested},l
!r{route6_nested},L
!r{route6_host},L

@tags irrd,r,edge-length
# /0, /32, /128 and host-length prefixes, v4 and v6 (a mask overflow on
# /32 and /128 less-specific searches made !r...,L return nothing).
!r0.0.0.0/0,L
!r0.0.0.0/0,l
!r0.0.0.0/0,o
!r::/0,L
!r::/0,o
!r{route4_host}/32
!r{route4_host}/32,o
!r{route4_host}/32,l
!r{route4_host}/32,L
!r{route4_host}/32,M
!r{route6_host}/128
!r{route6_host}/128,o
!r{route6_host}/128,l
!r{route6_host}/128,L
!r{route6_host}/128,M
!r{route6_host},L
!r{route6_host}/64,L
!r{route4.net}/{route4.len},L
!r255.255.255.255/32,L
!rffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128,L
!r2001:500:856e::30/128,L
