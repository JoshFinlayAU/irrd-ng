# NRTMv3 serving (-g) and its information query (-q sources), against
# sources that keep a journal. The `nrtm` binding comes from the serving
# differential (parity/mirror/serve.sh), which knows each source's journal
# range; without it (Tier 1 has no journals) these items are dropped.
#
# nrtm fields: source, oldest, newest, mid (a serial in between), next
# (newest + 1), after (newest + 2), before (oldest - 1).

@tags nrtm,range
-g {nrtm.source}:3:{nrtm.oldest}-LAST
-g {nrtm.source}:1:{nrtm.oldest}-LAST
-g {nrtm.source}:3:{nrtm.oldest}-{nrtm.mid}
-g {nrtm.source}:1:{nrtm.mid}-{nrtm.newest}
-g {nrtm.source}:3:{nrtm.mid}-{nrtm.mid}
-g {nrtm.source}:3:{nrtm.newest}-LAST
-g {nrtm.source|lower}:3:{nrtm.mid}-LAST

@tags nrtm,edges
-g {nrtm.source}:3:{nrtm.next}-LAST
-g {nrtm.source}:3:{nrtm.after}-LAST
-g {nrtm.source}:3:{nrtm.before}-LAST
-g {nrtm.source}:3:{nrtm.before}-{nrtm.newest}
-g {nrtm.source}:3:{nrtm.oldest}-{nrtm.after}
-g {nrtm.source}:3:{nrtm.newest}-{nrtm.oldest}
-g {nrtm.source}:3:{nrtm.oldest}-0
-g {nrtm.source}:3:0-LAST
-g {nrtm.source}:3:-1-LAST
-g {nrtm.source}:2:{nrtm.oldest}-LAST
-g {nrtm.source}:3:{nrtm.oldest}
-g {nrtm.source}:3:{nrtm.oldest}-{nrtm.newest}:x

@tags nrtm,irrd
!j{nrtm.source}
-q sources

@tags nrtm,session
@session
-k
-g {nrtm.source}:3:{nrtm.mid}-LAST
-g {nrtm.source}:3:{nrtm.next}-LAST
-k
@end
@session
!!
-g {nrtm.source}:3:{nrtm.oldest}-{nrtm.mid}
!v
@end
