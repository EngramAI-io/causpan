#!/usr/bin/env python3
"""Kernel-observed descriptor-transfer fixture; no MCP attribution claim."""
import array
import os
from pathlib import Path
import socket
import sys


def main():
    path = Path(sys.argv[1]).resolve()
    sender, receiver = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    child = os.fork()
    if child == 0:
        sender.close()
        data, ancillary, flags, address = receiver.recvmsg(128, socket.CMSG_SPACE(array.array('i').itemsize))
        assert data == b'descriptor-transfer' and not flags & socket.MSG_CTRUNC
        descriptors = array.array('i')
        for level, kind, payload in ancillary:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                descriptors.frombytes(payload)
        assert len(descriptors) == 1
        fd = descriptors[0]
        assert os.pwrite(fd, b'received-descriptor', 256) == 19
        assert os.pread(fd, 19, 256) == b'received-descriptor'
        os.close(fd)
        receiver.close()
        os._exit(0)
    receiver.close()
    # Open AFTER fork: the child cannot have inherited this descriptor.
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
    try:
        assert sender.sendmsg([b'descriptor-transfer'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [fd]))]) == 19
    finally:
        os.close(fd)
        sender.close()
    _, status = os.waitpid(child, 0)
    assert os.waitstatus_to_exitcode(status) == 0
    assert path.read_bytes()[256:275] == b'received-descriptor'


if __name__ == '__main__':
    main()
