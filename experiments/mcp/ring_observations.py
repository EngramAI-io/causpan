"""Validate trusted runtime SQE/CQE observations; not kernel syscall decoding.

Supported: one captured ring instance, unique user_data for its lifetime, single-shot READ/WRITE operations, one CQE per operation, no flags,
fixed descriptors, skipped success completions, or multishot semantics.
The adapter matches opaque user_data identity, never completion order.
"""


def join_observations(records):
    pending = {}
    completed = set()
    operations = []
    for row in records:
        identity = row.get('user_data')
        if type(identity) is not int or not 0 <= identity < 2**64:
            raise ValueError('invalid ring operation identity')
        if row.get('kind') == 'sqe':
            if type(row.get('flags')) is not int or row['flags'] != 0:
                raise ValueError('unsupported submission flags')
            if identity in pending or identity in completed:
                raise ValueError('duplicate ring operation identity in capture')
            if row.get('opcode') not in {22, 23} or type(row.get('opcode')) is not int:
                raise ValueError('unsupported ring opcode')
            for field in ['fd', 'offset', 'length']:
                if type(row.get(field)) is not int:
                    raise ValueError('noninteger submission field')
            if not -(2**31) <= row['fd'] < 2**31 or not 0 <= row['offset'] < 2**64 or not 0 <= row['length'] < 2**32:
                raise ValueError('out-of-range submission field')
            pending[identity] = row
        elif row.get('kind') == 'cqe':
            if identity not in pending:
                raise ValueError('completion has no unique pending submission')
            if type(row.get('flags')) is not int or row['flags'] != 0:
                raise ValueError('unsupported completion flags')
            result = row.get('result')
            if type(result) is not int or not -(2**31) <= result < 2**31:
                raise ValueError('invalid completion result')
            submission = pending.pop(identity)
            if result > submission['length']:
                raise ValueError('completion exceeds requested byte count')
            completed.add(identity)
            operations.append(dict(user_data=identity, opcode=submission['opcode'],
                                   fd=submission['fd'], offset=submission['offset'],
                                   requested_bytes=submission['length'], result=result,
                                   succeeded=result >= 0,
                                   evidence='trusted_runtime_submission_and_completion_observations'))
        else:
            raise ValueError('unknown ring observation kind')
    if pending:
        raise ValueError('ring operations lack completions')
    return operations


def observed_file_resource(events, pid, fd, before_ns):
    """Resolve a helper FD through an observed absolute open, conservatively.

    This is a pathname observation within a single-threaded helper, not an inode
    or open-file-description identity. Unsupported descriptor replacement loses
    the projection rather than retaining a potentially stale pathname.
    """
    import re
    if fd < 0:
        return dict(paths=[], resource_evidence=None, resource_status='invalid_descriptor')
    current=None
    for event in events:
        if event['pid']!=pid or event['timestamp_ns']>=before_ns:continue
        name=event['syscall'];result=event['return_value'];args=event['args']
        first=re.match(r'\s*(\d+)',args)
        first_fd=int(first[1]) if first else None
        if name=='close' and first_fd==fd:current=None
        if result is None and name in {
            'open','openat','openat2','socket','accept','accept4','dup','dup2','dup3',
            'fcntl','io_uring_setup','close_range','execve','execveat','unshare',
            'recvmsg','recvmmsg','socketpair','pipe','pipe2',
        }:
            # An unavailable result is not evidence of failure. It may conceal
            # replacement of the descriptor, so discard the old observation.
            current=None
        if result is None or result<0:continue
        replacement=name in {'open','openat','openat2','socket','accept','accept4','dup','dup2','dup3','io_uring_setup'} and result==fd
        replacement |= name=='fcntl' and 'F_DUPFD' in args and result==fd
        if replacement:
            current=None
            if name in {'open','openat','openat2'} and len(event['paths'])==1 and event['paths'][0].startswith('/'):
                if event.get('completion_ns') is not None and event['completion_ns']<=before_ns:
                    current=event
        if name=='close' and first_fd==fd:current=None
        if name=='close_range':
            bounds=re.match(r'\s*(\d+)\s*,\s*(\d+)',args)
            if bounds is None or int(bounds[1])<=fd<=int(bounds[2]):current=None
        if name in {'execve','execveat','unshare'}:current=None
        if name in {'recvmsg','recvmmsg','socketpair','pipe','pipe2'}:
            # Such operations can install descriptors not described by a scalar return.
            current=None
    if current is None:
        return dict(paths=[],resource_evidence=None,resource_status='unresolved_descriptor')
    return dict(paths=current['paths'],resource_evidence=current['source'],
                resource_status='observed_absolute_open_not_inode_identity')


def validate_waiting_enter(event, operation_count):
    """The scoped adapters require a fully submitted, completion-waiting batch."""
    import re
    match=re.fullmatch(r'(\d+)(?:<[^>]*>)?, (\d+), (\d+), (?:IORING_ENTER_GETEVENTS|1|0x1), NULL, 0',event['args'])
    if not match or operation_count<1 or int(match[2])!=operation_count or int(match[3])!=operation_count or event['return_value']!=operation_count:
        raise ValueError('ring enter is not a full completion-waiting batch')
    return int(match[1])


def validate_scoped_ring(setup, local):
    """Require observed execution to stay inside the helper adapter contract."""
    import re
    # Match the top-level setup flags, not nested SQ/CQ offset flags.
    if not re.match(r'\d+, \{flags=(?:0|0x0)(?:,|\})', setup['args']):
        raise ValueError('unsupported or unobserved ring setup flags')
    for event in local:
        if event['syscall'] in {'clone', 'clone3', 'fork', 'vfork', 'io_uring_register'}:
            result = event['return_value']
            if result is None or result >= 0:
                raise ValueError('ring helper changed process or registration scope')
