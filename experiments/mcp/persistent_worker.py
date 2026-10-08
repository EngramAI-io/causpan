#!/usr/bin/env python3
"""Trusted IPC context adapter; offsets are workload data, never context identity."""
import array
import concurrent.futures
import json
import errno
import os
from pathlib import Path
import sys
import subprocess
import socket
import threading
import time
import uuid

SLOT_BYTE_WIDTH = 128      # Bytes per slot; matches the 128-byte record layout of slots.bin.
BACKGROUND_SLOT_INDEX = 100000  # Dedicated background-write slot past the normal slot range.
EXIT_CRASH = 23            # Deliberate bypass of finally; leaves IPC bracket open.
EXIT_FATAL = 24            # Fatal task failure exit code; bypasses normal cleanup.
rights_mode = os.environ['CAUSPAN_SCENARIO'] == 'worker-rights'
rights_leaf = rights_mode and bool(os.environ.get('CAUSPAN_WORKER_LEAF'))
fd = None if rights_leaf else os.open(sys.argv[1], os.O_RDWR)
rights_socket = socket.socket(fileno=int(os.environ['CAUSPAN_RIGHTS_FD'])) if rights_leaf else None
markers = os.open(Path(os.environ['CAUSPAN_RUN']) / 'native-events.jsonl',
                  os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
cancel_mode = os.environ['CAUSPAN_SCENARIO'] == 'worker-cancel'
failure_mode = os.environ['CAUSPAN_SCENARIO'] == 'worker-failure'
propagate = os.environ['CAUSPAN_SCENARIO'] != 'worker-unscoped'
readonly = os.open(sys.argv[1], os.O_RDONLY) if failure_mode else None
output_lock = threading.Lock()


def mark(context, kind='JS_CONTEXT', job=None):
    record = dict(csp=1, kind=kind, request=context, operation=0,
                  pointer=0, tid=threading.get_native_id(), status=0)
    if job is not None:
        record['job'] = job
    data = (json.dumps(record, separators=(',', ':')) + '\n').encode()
    if os.write(markers, data) != len(data):
        raise RuntimeError('short context marker write')


# A second persistent process is launched at startup, before request execution.
relay = os.environ['CAUSPAN_SCENARIO'] in {'worker-relay','worker-relay-fatal','worker-rights'} and not os.environ.get('CAUSPAN_WORKER_LEAF')
relay_child = None
relay_lock = threading.Lock()
relay_waiters = {}
relay_failure = None
relay_namespace = str(uuid.uuid4())
relay_sequence = 0


def read_relay_responses():
    global relay_failure
    try:
        for line in relay_child.stdout:
            response = json.loads(line)
            with relay_lock:
                future = relay_waiters.pop(response['job'])
            if response.get('error'):
                future.set_exception(RuntimeError(response['error']))
            else:
                future.set_result(response)
        raise RuntimeError('downstream worker closed')
    except Exception as error:
        with relay_lock:
            relay_failure = error
            pending = list(relay_waiters.values())
            relay_waiters.clear()
        for future in pending:
            future.set_exception(error)


if relay:
    passed = ()
    child_env = {**os.environ,'CAUSPAN_WORKER_LEAF':'1'}
    if rights_mode:
        rights_socket, child_socket = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        passed = (child_socket.fileno(),)
        child_env['CAUSPAN_RIGHTS_FD'] = str(child_socket.fileno())
    relay_child = subprocess.Popen([sys.executable,__file__,sys.argv[1]],
        stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True,bufsize=1,
        env=child_env, pass_fds=passed)
    if rights_mode:
        child_socket.close()
    relay_reader = threading.Thread(target=read_relay_responses)
    relay_reader.start()


def delegate(context, slot):
    global relay_sequence
    future = concurrent.futures.Future()
    with relay_lock:
        if relay_failure is not None:
            raise relay_failure
        relay_sequence += 1
        job = f'{relay_namespace}/{relay_sequence}'
        relay_waiters[job] = future
        mark(context, 'IPC_SEND', job)
        payload = json.dumps(dict(context=str(context),slot=slot,job=job)).encode()
        if rights_mode:
            if rights_socket.sendmsg([payload], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [fd]))]) != len(payload):
                raise RuntimeError('short descriptor job dispatch')
        else:
            relay_child.stdin.write(payload.decode()+'\n')
            relay_child.stdin.flush()
    response = future.result(timeout=30)
    if response['slot']!=slot:
        raise RuntimeError('downstream response slot mismatch')
    return response


def execute(message):
    context = int(message['context']) if propagate else 0
    slot = message['slot']
    job_fd = message.get('received_fd', fd)
    if propagate:
        mark(context, 'IPC_ENTER', message['job'])
    else:
        mark(0)
    try:
        payload = f'worker:{slot}'.encode()
        if os.environ['CAUSPAN_SCENARIO']=='worker-socketpair':
            left,right=socket.socketpair()
            try:
                socket_payload=f'worker-socket:{slot}'.encode()
                if left.sendmsg([socket_payload])!=len(socket_payload) or right.recvmsg(128)[0]!=socket_payload:
                    raise RuntimeError('socketpair payload mismatch')
            finally:
                left.close();right.close()
        time.sleep(0.002 * (slot % 5))
        target = readonly if failure_mode and slot % 2 else job_fd
        if relay:
            delegate(context,slot)
        elif os.environ['CAUSPAN_SCENARIO'] in {'worker-spawn','worker-grandchild'}:
            program=f'import os,sys; SLOT_BYTE_WIDTH={SLOT_BYTE_WIDTH}; f=os.open(sys.argv[1],os.O_RDWR); p=("worker:"+sys.argv[2]).encode(); assert os.pwrite(f,p,int(sys.argv[2])*SLOT_BYTE_WIDTH)==len(p); os.close(f)'
            command=[sys.executable,'-c',program,sys.argv[1],str(slot)]
            if os.environ['CAUSPAN_SCENARIO']=='worker-grandchild':
                command=[sys.executable,'-c','import subprocess,sys; subprocess.run(sys.argv[1:],check=True)',*command]
            subprocess.run(command,check=True)
        elif os.pwrite(target, payload, slot * SLOT_BYTE_WIDTH) != len(payload):
            raise RuntimeError('short worker write')
        if os.environ['CAUSPAN_SCENARIO']=='worker-crash':
            os._exit(EXIT_CRASH)  # Deliberately bypass finally and leave the IPC bracket open.
        time.sleep(0.003)
        if os.pread(job_fd, len(payload), slot * SLOT_BYTE_WIDTH) != payload:
            raise RuntimeError('worker payload mismatch')
        response = dict(slot=slot)
    except Exception as error:
        if failure_mode and slot % 2 and isinstance(error, OSError) and error.errno == errno.EBADF:
            response = dict(slot=slot, expected_failure=True)
        else:
            response = dict(slot=slot, error=str(error))
    finally:
        if rights_leaf:
            os.close(job_fd)
        if os.environ['CAUSPAN_SCENARIO']=='worker-fatal' or (os.environ['CAUSPAN_SCENARIO']=='worker-relay-fatal' and os.environ.get('CAUSPAN_WORKER_LEAF')):
            raise RuntimeError('injected failure during job cleanup')
        if propagate:
            mark(context, 'IPC_LEAVE', message['job'])
        mark(0)
    # Independent background effect on the SAME worker TID after every job.
    if failure_mode:
        if os.pwrite(fd, b'worker-background', BACKGROUND_SLOT_INDEX * SLOT_BYTE_WIDTH) != 17:
            raise RuntimeError('short background write')
    response['job'] = message['job']
    if os.environ['CAUSPAN_SCENARIO']=='worker-wrong-response':
        response['job'] += '/unknown'
    with output_lock:
        print(json.dumps(response), flush=True)


def check_task_failure(future):
    if future.cancelled():
        return
    error = future.exception()
    if error is not None:
        # A failed context transition cannot safely be turned into a normal reply.
        # Termination wakes all server waiters and leaves the broken bracket visible.
        try:
            os.write(2, f'fatal worker task: {type(error).__name__}: {error}\n'.encode()[:2048])
        finally:
            os._exit(EXIT_FATAL)


def messages():
    if not rights_leaf:
        for line in sys.stdin:
            yield json.loads(line)
        return
    while True:
        payload, ancillary, flags, _ = rights_socket.recvmsg(4096, socket.CMSG_SPACE(4))
        descriptors = array.array('i')
        for level, kind, data in ancillary:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                descriptors.frombytes(data)
        try:
            message = json.loads(payload)
            if flags & (socket.MSG_CTRUNC | socket.MSG_TRUNC):
                raise RuntimeError('truncated descriptor job')
            if message.get('stop'):
                if descriptors:
                    raise RuntimeError('stop message carried descriptors')
                return
            if len(descriptors) != 1:
                raise RuntimeError('job requires exactly one descriptor')
            message['received_fd'] = descriptors[0]
        except BaseException:
            for received in descriptors:
                os.close(received)
            raise
        yield message


with concurrent.futures.ThreadPoolExecutor(max_workers=1 if cancel_mode else 4) as pool:
    futures = []
    for message in messages():
        if cancel_mode:
            # A gated predecessor guarantees the new job is queued while cancel()
            # runs. This tests pre-execution cancellation, not a timing race.
            gate = threading.Event()
            futures.append(pool.submit(gate.wait))
            future = pool.submit(execute, message)
            try:
                if message['slot'] % 2:
                    if not future.cancel():
                        raise RuntimeError('queued cancellation unexpectedly lost')
                    mark(int(message['context']), 'IPC_CANCEL', message['job'])
                    with output_lock:
                        print(json.dumps(dict(slot=message['slot'], job=message['job'], cancelled=True)), flush=True)
            finally:
                gate.set()
        else:
            future = pool.submit(execute, message)
        future.add_done_callback(check_task_failure)
        futures.append(future)
    for future in futures:
        if not future.cancelled():
            future.result()
if relay_child is not None:
    if rights_mode:
        rights_socket.send(b'{"stop":true}')
    relay_child.stdin.close()
    relay_reader.join(timeout=5)
    if relay_child.wait(timeout=5)!=0:
        raise RuntimeError('downstream worker failed during shutdown')
os.close(markers)
if fd is not None:
    os.close(fd)
if rights_socket is not None:
    rights_socket.close()

if readonly is not None:
    os.close(readonly)
