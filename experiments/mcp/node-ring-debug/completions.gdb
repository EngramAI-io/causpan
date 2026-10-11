# Offset 8256 is checked against setup-return metadata in the same capture.
set pagination off
set confirm off
catch syscall 425
commands
silent
printf "SETUP_STOP tid=%d x0=%ld params=%p\n", $_thread, $x0, $x1
x/30wx $x1
continue
end
set pagination off
set confirm off
set breakpoint pending on
break uv__io_uring_enter
commands
silent
printf "RING_ENTER fd=%d submit=%u wait=%u flags=%u\n", fd, to_submit, min_complete, flags
bt 6
up
ptype *ctl
p *ctl
set $snapshot = (void*)malloc(128)
call (void*)memcpy($snapshot, ctl->sqhead, 8)
printf "SQ_COUNTERS head=%u tail=%u mask=%u\n", *(unsigned int*)$snapshot, *((unsigned int*)$snapshot+1), ctl->sqmask
call (void*)memcpy($snapshot, ctl->sqe, 128)
x/128bx $snapshot
call (void*)memcpy($snapshot, (char*)ctl->sq+8256, 8)
printf "SQ_ARRAY index0=%u index1=%u\n", *(unsigned int*)$snapshot, *((unsigned int*)$snapshot+1)
call (void)free($snapshot)
down
continue
end
break uv__iou_submit
commands
silent
printf "RING_SUBMIT state=%p\n", $x0
bt 5
continue
end
break *0x18c57d0
commands
silent
printf "ENTER_RETURN result=%ld\n", $x0
set $ring = (struct uv__iou*)$x19
printf "CQ_RING fd=%d mask=%u\n", $ring->ringfd, $ring->cqmask
set $cqcopy = (void*)malloc(32)
call (void*)memcpy($cqcopy, $ring->cqhead, 8)
printf "CQ_COUNTERS head=%u tail=%u\n", *(unsigned int*)$cqcopy, *((unsigned int*)$cqcopy+1)
call (void*)memcpy($cqcopy, $ring->cqe, 32)
x/32bx $cqcopy
call (void)free($cqcopy)
continue
end
run
