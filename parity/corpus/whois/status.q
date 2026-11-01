# Suppressed objects (RPKI invalid, out of scope, route preference) and the
# !f overrides that show them. The fixed prefixes are those of the
# synthetic STATUSAUTH and STATUSLOW sources of the status suite
# (parity/status/data, loaded by parity/status/run.sh --queries); on other
# data they find nothing, on both servers alike.
@tags status

!r192.0.2.0/24,l
!r192.0.2.0/24,L
!r192.0.2.0/24,M
!r192.0.0.0/16,M
!r198.51.100.0/24,o
!r100.64.0.0/10,M
!r2001:db8::/32,M
!gAS65001
!gAS65009
!gAS65013
!6AS65001
!6AS65009
!aAS65001
!iAS65001
!mroute,192.0.2.0/24AS65001
!mroute,192.0.2.128/25AS65013
!maut-num,AS23456
-x 192.0.2.0/24
-M 192.0.0.0/16
-L 192.0.2.128/25
-i origin AS65009
-s STATUSAUTH -M 192.0.0.0/8
-s STATUSLOW -T route 192.0.2.0/25
-s RPKI -M 192.0.2.0/24
AS65001
192.0.2.0/24

@session
!!
!r192.0.2.0/24,M
!fno-rpki-filter
!r192.0.2.0/24,M
!gAS65001
!r2001:db8::/32,M
!q
@end

@session
!!
!fno-scope-filter
!r100.64.0.0/10,M
!maut-num,AS23456
!gAS23456
-x 10.0.0.0/8
!q
@end

@session
!!
!fno-route-preference-filter
!r192.0.2.0/24,l
!r198.51.100.0/24,o
!gAS65001
!6AS65001
!q
@end

@session
!!
!fno-rpki-filter
!fno-scope-filter
!fno-route-preference-filter
!r192.0.0.0/8,M
!r2001:db8::/32,M
!q
@end

@session
-k
-M 192.0.0.0/16
-r -M 192.0.0.0/16
-k
@end
