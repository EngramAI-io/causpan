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
x/4wx ctl->sqhead
x/16bx ctl->sqe
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
