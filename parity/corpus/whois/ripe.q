# RIPE-style flags and free-text search.

@tags ripe,basic
-k
-a
-F
-r
-F -r
-z
-
--
-i
-s
-T
-t
-V
-q
-g
-x
-l
-L
-M
foo
query
-e foo
-k -k
-V user-agent
-V user-agent -s RADB
-V user-agent !v
-V user-agent !!
-V user-agent !gAS64496
-V ua
-V  ua  !v
-v
-K

@tags ripe,t
-t aut-num
-t AUT-NUM
-t nosuchclass
-t aut-num route
-t as-block
-t as-set
-t domain
-t filter-set
-t inet-rtr
-t inet6num
-t inetnum
-t irt
-t key-cert
-t mntner
-t organisation
-t peering-set
-t person
-t role
-t route
-t route-set
-t route6
-t rtr-set

@tags ripe,q
-q sources
-q unknow
-q SOURCES

@tags ripe,g
-g RADB:3:1-LAST
-g UNKNOWN:1:1-LAST
-g RADB:9:1-LAST
-g RADB:1:1-LAST:foo
-g RADB:3:1-5
-g RADB:3:x-LAST
-g RADB:3:5
-g RADB

@tags ripe,s
-s RADB
-s radb,arin
-s UNKNOWN
-s RADB {aut_num}
-s {source} {aut_num}
-a {aut_num}
-s RADB -a {aut_num}
-a -s RADB {aut_num}
-s RPKI -x {route4.prefix}

@tags ripe,i
-i mnt-by MNT-NOT-EXISTING
-i mnt-by
-i nosuchattr FOO
-i descr FOO
-i mnt-by {mntner}
-i mnt-by {mntner_busy}
-i MNT-BY {mntner}
-i origin {origin4}
-i origin {origin6}
-i origin {aut_num_no_routes}
-i origin as64496
-i member-of {member_of_target}
-i mbrs-by-ref {mbrs_by_ref_mnt}
-i members {aut_num}
-i mp-members {aut_num}
-i admin-c FOO-NONEXISTENT
-i tech-c FOO-NONEXISTENT
-i zone-c FOO-NONEXISTENT
-i person FOO-NONEXISTENT
-i role FOO-NONEXISTENT
-T route -i mnt-by {mntner_busy}
-T route6 -i origin {origin6}
-T route,route6 -i origin {origin4}
-T nosuchclass -i origin {origin4}
-K -i origin {origin4}
-r -i origin {origin4}

@tags ripe,route
-x 192.0.2.0/32
-x not-a-prefix
-x 192.0.2.0/25
-l 192.0.2.0/25
-L 192.0.2.0/25
-M 192.0.2.0/25
-K -x 192.0.2.0/25
-r  -x   192.0.2.0/25
-x192.0.2.0/24
-x {route4.prefix}
-l {route4.prefix}
-L {route4.prefix}
-M {route4.prefix}
-M {route4_covering}
-l {route4_nested}
-L {route4_nested}
-L {route4_host}
-x {route4_host}
-x {route6.prefix}
-l {route6_nested}
-L {route6_nested}
-M {route6_covering}
-K -x {route4.prefix}
-K -M {route4_covering}
-T route6 -M {route4_covering}
-x {route4.prefix} extra
-F -r -x {route4.prefix}

@tags ripe,text
{aut_num}
{as_set}
{route_set}
{mntner}
{route4.prefix}
{route6.prefix}
{route4_host}
{route4.prefix}{route4.origin}
{obj.pk}
-K {as_set}
-K {route_set}
-K {aut_num}
-T aut-num {aut_num}
-T as-set {aut_num}
-T as-set,route-set {as_set}
-T AUT-NUM {aut_num}
-s RADB -T aut-num {aut_num}
{aut_num} {as_set}
AS64496
as64496
64496
AS-NONEXISTENT-ZZZ
192.0.2.0/24
2001:db8::/32

@tags ripe,route,edge-length
-x 0.0.0.0/0
-l 0.0.0.0/0
-L 0.0.0.0/0
-L ::/0
-x {route4_host}/32
-l {route4_host}/32
-L {route4_host}/32
-M {route4_host}/32
-x {route6_host}/128
-l {route6_host}/128
-L {route6_host}/128
-M {route6_host}/128
-L {route6_host}
-L 255.255.255.255/32
-L ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128
-L 2001:500:856e::30/128
