set pagination off
set confirm off
catch syscall 425
commands
silent
printf "SETUP_STOP tid=%d x0=%ld params=%p\n", $_thread, $x0, $x1
x/30wx $x1
continue
end
run
