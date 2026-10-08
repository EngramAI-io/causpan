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
