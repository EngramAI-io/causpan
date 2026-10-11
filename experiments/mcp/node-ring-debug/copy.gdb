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
call (void*)memcpy($snapshot, ctl->sqe, 128)
x/128bx $snapshot
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
run
