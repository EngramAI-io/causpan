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
# Pinned Node AArch64 epoll flush, immediately before/after syscall wrapper.
break *0x18c57b4
commands
silent
python
print("SUBMITTER pid=%d tid=%d" % (gdb.selected_thread().ptid[0], gdb.selected_thread().ptid[1]))
end
set $ring = (struct uv__iou*)$x19
set scheduler-locking on
set $copy = (void*)malloc(64)
set scheduler-locking off
set scheduler-locking on
call (void*)memcpy($copy, $ring->sqhead, 8)
set scheduler-locking off
set $head = *(unsigned int*)$copy
set $tail = *((unsigned int*)$copy+1)
printf "BATCH fd=%d head=%u tail=%u mask=%u\n", $ring->ringfd, $head, $tail, $ring->sqmask
set $n = $head
while $n != $tail
set $index = $n & $ring->sqmask
set scheduler-locking on
call (void*)memcpy($copy, (char*)$ring->sq+8256+4*$index, 4)
set scheduler-locking off
set $entry = *(unsigned int*)$copy
set scheduler-locking on
call (void*)memcpy($copy, (char*)$ring->sqe+64*$entry, 64)
set scheduler-locking off
printf "SQE index=%u opcode=%u fd=%d user_data=%llu target=%llu control=%u sqflags=%u\n", $entry, *(unsigned char*)$copy, *(int*)((char*)$copy+4), *(unsigned long long*)((char*)$copy+32), *(unsigned long long*)((char*)$copy+8), *(unsigned int*)((char*)$copy+24), *((unsigned char*)$copy+1)
set $n = (unsigned int)($n+1)
end
set scheduler-locking on
call (void)free($copy)
set scheduler-locking off
continue
end
break *0x18c57d0
commands
silent
printf "RETURN result=%ld\n", $x0
set $ring = (struct uv__iou*)$x19
set scheduler-locking on
set $copy = (void*)malloc(16)
set scheduler-locking off
set scheduler-locking on
call (void*)memcpy($copy, $ring->cqhead, 8)
set scheduler-locking off
set $head = *(unsigned int*)$copy
set $tail = *((unsigned int*)$copy+1)
printf "COMPLETIONS fd=%d head=%u tail=%u mask=%u\n", $ring->ringfd, $head, $tail, $ring->cqmask
set $n = $head
while $n != $tail
set $index = $n & $ring->cqmask
set scheduler-locking on
call (void*)memcpy($copy, (char*)$ring->cqe+16*$index, 16)
set scheduler-locking off
printf "CQE user_data=%llu result=%d flags=%u\n", *(unsigned long long*)$copy, *(int*)((char*)$copy+8), *(unsigned int*)((char*)$copy+12)
set $n = (unsigned int)($n+1)
end
set scheduler-locking on
call (void)free($copy)
set scheduler-locking off
printf "BATCH_END\n"
continue
end
catch syscall 57
commands
silent
printf "CLOSE_STOP thread=%d value=%ld\n", $_thread, $x0
continue
end

catch syscall 198 242
commands
silent
python
print("LIFECYCLE_THREAD thread=%d tid=%d" % (gdb.selected_thread().num, gdb.selected_thread().ptid[1]))
end
printf "SOCKET_STOP thread=%d syscall=%ld value=%ld\n", $_thread, $x8, $x0
continue
end

catch syscall 19 20
commands
silent
python
print("LIFECYCLE_THREAD thread=%d tid=%d" % (gdb.selected_thread().num, gdb.selected_thread().ptid[1]))
end
printf "CONTROL_FD_STOP thread=%d syscall=%ld value=%ld\n", $_thread, $x8, $x0
continue
end

# Marker writes are observed at syscall entry and accepted only on a full return.
python
import json
marker_pending = {}
end
catch syscall 64
commands
silent
python
tid = gdb.selected_thread().ptid[1]
if tid not in marker_pending:
    size = int(gdb.parse_and_eval('$x2'))
    record = None
    if 0 < size <= 4096:
        raw = bytes(gdb.selected_inferior().read_memory(int(gdb.parse_and_eval('$x1')), size))
        if raw.startswith(b'{"csp":1,'):
            record = json.loads(raw)
    marker_pending[tid] = (size, record)
else:
    size, record = marker_pending.pop(tid)
    if record is not None:
        print('MARKER_WRITE ' + json.dumps(dict(tid=tid, size=size, result=int(gdb.parse_and_eval('$x0')), marker=record), sort_keys=True))
end
continue
end

# After the final SQE store in the pinned non-inlined preparation function.
break *0x18c59bc
commands
silent
python
print("PREPARER tid=%d" % gdb.selected_thread().ptid[1])
end
printf "PREP ring_fd=%d epoll_fd=%d target=%ld control=%d user_data=%llu\n", ((struct uv__iou*)$x1)->ringfd, $w0, $x4, $w3, $x6
continue
end

# Watcher queue insertion completed; x20=watcher, x23=loop.
break *0x18b4554
commands
silent
python
print("WATCHER_THREAD tid=%d" % gdb.selected_thread().ptid[1])
end
printf "WATCHER_ENQUEUE loop=%llu watcher=%llu fd=%d pevents=%u events=%u\n", $x23, $x20, ((uv__io_t*)$x20)->fd, ((uv__io_t*)$x20)->pevents, ((uv__io_t*)$x20)->events
continue
end

# Queue links have been removed and reset; x1 still identifies the watcher.
break *0x18c8420
commands
silent
python
print("WATCHER_THREAD tid=%d" % gdb.selected_thread().ptid[1])
end
printf "WATCHER_DEQUEUE loop=%llu watcher=%llu fd=%d pevents=%u events=%u\n", $x23, $x1, ((uv__io_t*)$x1)->fd, ((uv__io_t*)$x1)->pevents, ((uv__io_t*)$x1)->events
continue
end

# The poll loop's direct preparation call after a watcher removal.
break *0x18c83f8
commands
silent
python
print("WATCHER_THREAD tid=%d" % gdb.selected_thread().ptid[1])
end
printf "WATCHER_CALL loop=%llu ring_fd=%d target=%d control=%d\n", $x23, ((struct uv__iou*)$x1)->ringfd, $w4, $w3
continue
end

break *0x18c5848
commands
silent
python
print("RETRY_THREAD tid=%d" % gdb.selected_thread().ptid[1])
end
printf "ERROR_COMPLETION ring_fd=%d user_data=%llu result=%d\n", ((struct uv__iou*)$x19)->ringfd, $x5, $w1
continue
end
break *0x18c5888
commands
silent
python
print("RETRY_THREAD tid=%d" % gdb.selected_thread().ptid[1])
end
printf "RETRY_CALL ring_fd=%d target=%d control=%d\n", ((struct uv__iou*)$x1)->ringfd, $w4, $w3
continue
end

# pevents has been updated and allocation succeeded, before queue membership check.
break *0x18b44dc
commands
silent
python
print("WATCHER_THREAD tid=%d" % gdb.selected_thread().ptid[1])
end
printf "WATCHER_UPDATE loop=%llu watcher=%llu fd=%d pevents=%u events=%u\n", $x23, $x20, ((uv__io_t*)$x20)->fd, ((uv__io_t*)$x20)->pevents, ((uv__io_t*)$x20)->events
continue
end

# Stop has unlinked/reset the watcher queue, before watcher-table removal.
break *0x18b49c0
commands
silent
python
print("WATCHER_THREAD tid=%d" % gdb.selected_thread().ptid[1])
end
printf "WATCHER_CANCEL loop=%llu watcher=%llu fd=%d pevents=%u events=%u\n", $x0, $x1, ((uv__io_t*)$x1)->fd, ((uv__io_t*)$x1)->pevents, ((uv__io_t*)$x1)->events
continue
end

# Partial stop inserted a watcher with remaining interests.
break *0x18b4a00
commands
silent
python
print("WATCHER_THREAD tid=%d" % gdb.selected_thread().ptid[1])
end
printf "WATCHER_ENQUEUE loop=%llu watcher=%llu fd=%d pevents=%u events=%u\n", $x0, $x1, ((uv__io_t*)$x1)->fd, ((uv__io_t*)$x1)->pevents, ((uv__io_t*)$x1)->events
continue
end

run
