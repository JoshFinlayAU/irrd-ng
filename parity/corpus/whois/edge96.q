# IPv6 route searches in and around ::/96, where v4 stores ip_last as IPv4
# (IPy re-guesses the broadcast) and Postgres orders all IPv4 below IPv6.
# Data: the synthetic source EDGE96 (corpus/whois/data/EDGE96.db, also used
# by crates/query's ipv6_searches_inside_96 test), loaded by parity/load.sh.

@tags edge96,r
!r::/0
!r::/0,o
!r::/0,l
!r::/0,L
-x ::/0
-l ::/0
-L ::/0
::/0
-T route6 ::/0
-s EDGE96 -L ::/0
-s EDGE96 ::/0
!r::/8
!r::/8,o
!r::/8,l
!r::/8,L
!r::/8,M
-x ::/8
-l ::/8
-L ::/8
-M ::/8
::/8
-T route6 ::/8
-s EDGE96 -L ::/8
-s EDGE96 ::/8
!r::/95
!r::/95,o
!r::/95,l
!r::/95,L
!r::/95,M
-x ::/95
-l ::/95
-L ::/95
-M ::/95
::/95
-T route6 ::/95
-s EDGE96 -L ::/95
-s EDGE96 ::/95
!r::/96
!r::/96,o
!r::/96,l
!r::/96,L
!r::/96,M
-x ::/96
-l ::/96
-L ::/96
-M ::/96
::/96
-T route6 ::/96
-s EDGE96 -L ::/96
-s EDGE96 ::/96
!r::/97
!r::/97,o
!r::/97,l
!r::/97,L
!r::/97,M
-x ::/97
-l ::/97
-L ::/97
-M ::/97
::/97
-T route6 ::/97
-s EDGE96 -L ::/97
-s EDGE96 ::/97
!r::/104
!r::/104,o
!r::/104,l
!r::/104,L
!r::/104,M
-x ::/104
-l ::/104
-L ::/104
-M ::/104
::/104
-T route6 ::/104
-s EDGE96 -L ::/104
-s EDGE96 ::/104
!r::/120
!r::/120,o
!r::/120,l
!r::/120,L
!r::/120,M
-x ::/120
-l ::/120
-L ::/120
-M ::/120
::/120
-T route6 ::/120
-s EDGE96 -L ::/120
-s EDGE96 ::/120
!r::/128
!r::/128,o
!r::/128,l
!r::/128,L
!r::/128,M
-x ::/128
-l ::/128
-L ::/128
-M ::/128
::/128
-T route6 ::/128
-s EDGE96 -L ::/128
-s EDGE96 ::/128
!r::1
!r::1,o
!r::1,l
!r::1,L
!r::1,M
-x ::1
-l ::1
-L ::1
-M ::1
::1
-T route6 ::1
-s EDGE96 -L ::1
-s EDGE96 ::1
!r::102:304
!r::102:304,o
!r::102:304,l
!r::102:304,L
!r::102:304,M
-x ::102:304
-l ::102:304
-L ::102:304
-M ::102:304
::102:304
-T route6 ::102:304
-s EDGE96 -L ::102:304
-s EDGE96 ::102:304
!r::ffff:0:0/96
!r::ffff:0:0/96,o
!r::ffff:0:0/96,l
!r::ffff:0:0/96,L
!r::ffff:0:0/96,M
-x ::ffff:0:0/96
-l ::ffff:0:0/96
-L ::ffff:0:0/96
-M ::ffff:0:0/96
::ffff:0:0/96
-T route6 ::ffff:0:0/96
-s EDGE96 -L ::ffff:0:0/96
-s EDGE96 ::ffff:0:0/96
!r::1:0:0/96
!r::1:0:0/96,o
!r::1:0:0/96,l
!r::1:0:0/96,L
!r::1:0:0/96,M
-x ::1:0:0/96
-l ::1:0:0/96
-L ::1:0:0/96
-M ::1:0:0/96
::1:0:0/96
-T route6 ::1:0:0/96
-s EDGE96 -L ::1:0:0/96
-s EDGE96 ::1:0:0/96
!r::/64
!r::/64,o
!r::/64,l
!r::/64,L
!r::/64,M
-x ::/64
-l ::/64
-L ::/64
-M ::/64
::/64
-T route6 ::/64
-s EDGE96 -L ::/64
-s EDGE96 ::/64
!r::2/127
!r::2/127,o
!r::2/127,l
!r::2/127,L
!r::2/127,M
-x ::2/127
-l ::2/127
-L ::2/127
-M ::2/127
::2/127
-T route6 ::2/127
-s EDGE96 -L ::2/127
-s EDGE96 ::2/127
!r::ffff:1.2.3.4
!r::ffff:1.2.3.4,o
!r::ffff:1.2.3.4,l
!r::ffff:1.2.3.4,L
!r::ffff:1.2.3.4,M
-x ::ffff:1.2.3.4
-l ::ffff:1.2.3.4
-L ::ffff:1.2.3.4
-M ::ffff:1.2.3.4
::ffff:1.2.3.4
-T route6 ::ffff:1.2.3.4
-s EDGE96 -L ::ffff:1.2.3.4
-s EDGE96 ::ffff:1.2.3.4
!r::1.2.3.0/120
!r::1.2.3.0/120,o
!r::1.2.3.0/120,l
!r::1.2.3.0/120,L
!r::1.2.3.0/120,M
-x ::1.2.3.0/120
-l ::1.2.3.0/120
-L ::1.2.3.0/120
-M ::1.2.3.0/120
::1.2.3.0/120
-T route6 ::1.2.3.0/120
-s EDGE96 -L ::1.2.3.0/120
-s EDGE96 ::1.2.3.0/120
!r::ffff:0:0/80
!r::ffff:0:0/80,o
!r::ffff:0:0/80,l
!r::ffff:0:0/80,L
!r::ffff:0:0/80,M
-x ::ffff:0:0/80
-l ::ffff:0:0/80
-L ::ffff:0:0/80
-M ::ffff:0:0/80
::ffff:0:0/80
-T route6 ::ffff:0:0/80
-s EDGE96 -L ::ffff:0:0/80
-s EDGE96 ::ffff:0:0/80
!r::/32
!r::/32,o
!r::/32,l
!r::/32,L
!r::/32,M
-x ::/32
-l ::/32
-L ::/32
-M ::/32
::/32
-T route6 ::/32
-s EDGE96 -L ::/32
-s EDGE96 ::/32
!r::1:0:1/128
!r::1:0:1/128,o
!r::1:0:1/128,l
!r::1:0:1/128,L
!r::1:0:1/128,M
-x ::1:0:1/128
-l ::1:0:1/128
-L ::1:0:1/128
-M ::1:0:1/128
::1:0:1/128
-T route6 ::1:0:1/128
-s EDGE96 -L ::1:0:1/128
-s EDGE96 ::1:0:1/128
!r::0.0.1.0/120
!r::0.0.1.0/120,o
!r::0.0.1.0/120,l
!r::0.0.1.0/120,L
!r::0.0.1.0/120,M
-x ::0.0.1.0/120
-l ::0.0.1.0/120
-L ::0.0.1.0/120
-M ::0.0.1.0/120
::0.0.1.0/120
-T route6 ::0.0.1.0/120
-s EDGE96 -L ::0.0.1.0/120
-s EDGE96 ::0.0.1.0/120
!r1::/16
!r1::/16,o
!r1::/16,l
!r1::/16,L
!r1::/16,M
-x 1::/16
-l 1::/16
-L 1::/16
-M 1::/16
1::/16
-T route6 1::/16
-s EDGE96 -L 1::/16
-s EDGE96 1::/16
!r::/1
!r::/1,o
!r::/1,l
!r::/1,L
-x ::/1
-l ::/1
-L ::/1
::/1
-T route6 ::/1
-s EDGE96 -L ::/1
-s EDGE96 ::/1
!r::102:300/120
!r::102:300/120,o
!r::102:300/120,l
!r::102:300/120,L
!r::102:300/120,M
-x ::102:300/120
-l ::102:300/120
-L ::102:300/120
-M ::102:300/120
::102:300/120
-T route6 ::102:300/120
-s EDGE96 -L ::102:300/120
-s EDGE96 ::102:300/120
!r::1:0:0/95
!r::1:0:0/95,o
!r::1:0:0/95,l
!r::1:0:0/95,L
!r::1:0:0/95,M
-x ::1:0:0/95
-l ::1:0:0/95
-L ::1:0:0/95
-M ::1:0:0/95
::1:0:0/95
-T route6 ::1:0:0/95
-s EDGE96 -L ::1:0:0/95
-s EDGE96 ::1:0:0/95
!r::ffff:ffff:ffff/128
!r::ffff:ffff:ffff/128,o
!r::ffff:ffff:ffff/128,l
!r::ffff:ffff:ffff/128,L
!r::ffff:ffff:ffff/128,M
-x ::ffff:ffff:ffff/128
-l ::ffff:ffff:ffff/128
-L ::ffff:ffff:ffff/128
-M ::ffff:ffff:ffff/128
::ffff:ffff:ffff/128
-T route6 ::ffff:ffff:ffff/128
-s EDGE96 -L ::ffff:ffff:ffff/128
-s EDGE96 ::ffff:ffff:ffff/128
!r::ffff:c000:200/120
!r::ffff:c000:200/120,o
!r::ffff:c000:200/120,l
!r::ffff:c000:200/120,L
!r::ffff:c000:200/120,M
-x ::ffff:c000:200/120
-l ::ffff:c000:200/120
-L ::ffff:c000:200/120
-M ::ffff:c000:200/120
::ffff:c000:200/120
-T route6 ::ffff:c000:200/120
-s EDGE96 -L ::ffff:c000:200/120
!r::2:0:0/95
!r::2:0:0/95,o
!r::2:0:0/95,l
!r::2:0:0/95,L
!r::2:0:0/95,M
-x ::2:0:0/95
-l ::2:0:0/95
-L ::2:0:0/95
-M ::2:0:0/95
::2:0:0/95
-T route6 ::2:0:0/95
-s EDGE96 -L ::2:0:0/95
!r2001:db8::/32
!r2001:db8::/32,o
!r2001:db8::/32,l
!r2001:db8::/32,L
!r2001:db8::/32,M
-x 2001:db8::/32
-l 2001:db8::/32
-L 2001:db8::/32
-M 2001:db8::/32
2001:db8::/32
-T route6 2001:db8::/32
-s EDGE96 -L 2001:db8::/32
!r0:0:0:1::/64
!r0:0:0:1::/64,o
!r0:0:0:1::/64,l
!r0:0:0:1::/64,L
!r0:0:0:1::/64,M
-x 0:0:0:1::/64
-l 0:0:0:1::/64
-L 0:0:0:1::/64
-M 0:0:0:1::/64
0:0:0:1::/64
-T route6 0:0:0:1::/64
-s EDGE96 -L 0:0:0:1::/64

@tags edge96,r,huge
# More-specifics of ::/0 and ::/1: every IPv6 route; hundreds of MB on Tier 2,
# where run-tier2.sh skips the huge tag.
!r::/0,M
-M ::/0
!r::/1,M
-M ::/1

@tags edge96,r
@session
!!
!sEDGE96
!r::/96,L
!r::/96,M
!r::ffff:0:0/96,l
@end
