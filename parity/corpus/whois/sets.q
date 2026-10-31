# Set expansion: deepest, largest, looping and dangling sets, exclusions.
@limit 10

@tags sets,deep
!i{as_set_deep}
!i{as_set_deep},1
!a{as_set_deep}
!a4{as_set_deep}
!a6{as_set_deep}
!i{route_set_deep}
!i{route_set_deep},1
!a{route_set_deep}
-K {as_set_deep}

@tags sets,large
!i{as_set_large},1
!a4{as_set_large}
!a6{as_set_large}
!i{as_set_wide}
!i{as_set_wide},1

@tags sets,loop
!i{as_set_loop},1
!a{as_set_loop}
!i{route_set_loop},1

@tags sets,dangling
!i{as_set_dangling}
!i{as_set_dangling},1
!a{as_set_dangling}

@tags sets,refd
!i{as_set_refd}
!i{as_set_refd},1
!a{as_set_refd}

@tags sets,case
!i{as_set_deep|lower},1
!a{as_set_deep|lower}
!i{route_set_deep|lower},1
!g{origin4|lower}

@tags sets,exclude
@session
!!
!e{as_set_deep}
!e-lc
!i{as_set_deep},1
!a{as_set_deep}
!e
!e-lc
!i{as_set_deep},1
@end
@session
!!
!eAS-NONEXISTENT-ZZZ,{as_set_large}
!e-lc
!i{as_set_large},1
!a4{as_set_large}
@end
@session
!!
!e{as_set_loop}
!i{as_set_loop},1
@end

@tags sets,sources
@session
!!
!sRADB
!i{as_set_deep},1
!a{as_set_deep}
!s-lc
@end
@session
!!
!s{source}
!i{as_set_large},1
!g{origin_many4}
@end
