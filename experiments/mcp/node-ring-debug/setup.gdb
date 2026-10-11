set pagination off
set confirm off
# Binary-pinned Node 24.20.0 AArch64: setup syscall return before result validation.
break *0x18c61cc
commands
silent
printf "SETUP_RETURN fd=%d\n", $w0
p params
continue
end
run
