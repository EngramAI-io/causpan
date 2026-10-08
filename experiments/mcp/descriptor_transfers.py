"""Pair fully observed, serialized Unix datagrams without reading their payloads.

Scope: traced socketpair-created SOCK_DGRAM endpoints, no reconfiguration,
no overlapping calls in either direction, complete and equal message sequences.
Linux AF_UNIX datagrams preserve order: https://man7.org/linux/man-pages/man7/unix.7.html
Unknown or ambiguous channels produce diagnostics, never guessed transfer edges.
"""
from collections import defaultdict
import re

ENDPOINT = re.compile(r'(?:UNIX|\(null\)):\[(\d+)->(\d+)\]')
SEND = {'sendmsg', 'sendto', 'write', 'writev'}
RECEIVE = {'recvmsg', 'recvfrom', 'read', 'readv'}


def pair_transfers(events):
    channels = {}
    diagnostics = []
    for event in events:
        if event['syscall'] != 'socketpair' or event['return_value'] != 0:
            continue
        if not re.match(r'AF_UNIX, SOCK_DGRAM(?:\|SOCK_CLOEXEC|\|SOCK_NONBLOCK)*, 0,', event['args']):
            continue
        endpoints = ENDPOINT.findall(event['args'])
        if len(endpoints) != 2 or endpoints[0] != endpoints[1][::-1]:
            continue
        key = tuple(sorted(endpoints[0]))
        if key in channels:
            channels[key]['errors'].append('endpoint identity reused')
        else:
            channels[key] = dict(creation=event, errors=[], flows=defaultdict(lambda: {'send':[], 'receive':[]}))
    by_inode = defaultdict(set)
    for key in channels:
        for inode in key:
            by_inode[inode].add(key)
    for keys in by_inode.values():
        if len(keys) > 1:
            for key in keys:
                channels[key]['errors'].append('endpoint inode appears in multiple channel identities')
    unsupported = {'connect','shutdown','setsockopt','sendmmsg','recvmmsg',
                   'splice','vmsplice','sendfile','copy_file_range'}
    for event in events:
        syscall = event['syscall']
        structural = re.sub(r'"(?:\\.|[^"\\])*"', '""', event['args'])
        refs = list(re.finditer(r'\d+<((?:UNIX|\(null\)):\[(\d+)(?:->(\d+))?\])>', structural))
        for ref in refs:
            affected = by_inode.get(ref[2], set()) | by_inode.get(ref[3], set())
            for key in affected:
                channel = channels[key]
                if syscall in unsupported:
                    channel['errors'].append('unsupported channel operation: '+syscall)
                if syscall in SEND | RECEIVE:
                    if ref.start() != 0:
                        channel['errors'].append('channel endpoint passed as ancillary or secondary descriptor')
                    elif ref[3] is None or tuple(sorted((ref[2], ref[3]))) != key:
                        channel['errors'].append('message channel peer identity unresolved or changed')
        if syscall.startswith('io_uring_') and not (syscall == 'io_uring_setup' and event['return_value'] is not None and event['return_value'] < 0):
            for channel in channels.values():
                channel['errors'].append('io_uring activity cannot be excluded from channel traffic')
    for event in events:
        match = re.match(r'\d+<((?:UNIX|\(null\)):\[\d+->\d+\])>', event['args'])
        if not match:
            continue
        endpoint = ENDPOINT.fullmatch(match[1]).groups()
        channel = channels.get(tuple(sorted(endpoint)))
        if channel is None:
            continue
        syscall = event['syscall']
        if syscall not in SEND | RECEIVE:
            continue
        if event['return_value'] is None:
            channel['errors'].append('message has unknown outcome')
            continue
        if event['return_value'] < 0:
            continue
        if syscall in {'sendmsg','recvmsg','sendto','recvfrom'} and not re.search(r', 0(?:, NULL, 0)?$', event['args']):
            channel['errors'].append('unsupported message flags or addressing')
        if event.get('completion_ns') is None:
            channel['errors'].append('message lacks completion timestamp')
        # Inspect flags outside quoted payloads only.
        structural = re.sub(r'"(?:\\.|[^"\\])*"', '""', event['args'])
        if re.search(r'\bMSG_(?:TRUNC|CTRUNC|PEEK)\b', structural):
            channel['errors'].append('truncated or peeked message')
        if event['timestamp_ns'] < channel['creation']['timestamp_ns']:
            channel['errors'].append('message predates observed channel creation')
        direction = 'send' if syscall in SEND else 'receive'
        flow = endpoint if direction == 'send' else endpoint[::-1]
        channel['flows'][flow][direction].append(event)
    pairs = []
    for key, channel in channels.items():
        tentative = []
        for flow, messages in channel['flows'].items():
            sends = sorted(messages['send'], key=lambda e:e['timestamp_ns'])
            receives = sorted(messages['receive'], key=lambda e:e['timestamp_ns'])
            if len(sends) != len(receives):
                channel['errors'].append('unbalanced datagram sequence')
            for sequence in [sends, receives]:
                for first, second in zip(sequence, sequence[1:]):
                    if first.get('completion_ns') is None or first['completion_ns'] >= second['timestamp_ns']:
                        channel['errors'].append('overlapping or indistinguishable message order')
            for send, receive in zip(sends, receives):
                if receive.get('completion_ns') is None or send['timestamp_ns'] > receive['completion_ns']:
                    channel['errors'].append('receive completed before send began')
                if send['return_value'] != receive['return_value']:
                    channel['errors'].append('datagram length mismatch')
                left, right = send.get('descriptor_rights'), receive.get('descriptor_rights')
                if left is None and right is None:
                    continue
                if not left or not right or any(not r['decoded'] or not r['succeeded'] or r['control_truncated'] for r in [left,right]):
                    channel['errors'].append('incomplete ancillary descriptor observation')
                    continue
                if len(left['fds']) != len(right['fds']):
                    channel['errors'].append('descriptor count mismatch')
                    continue
                for source_fd, target_fd in zip(left['fds'], right['fds']):
                    tentative.append(dict(send=send['source'], receive=receive['source'],
                        sender_pid=send['pid'], receiver_pid=receive['pid'],
                        sender_fd=source_fd, receiver_fd=target_fd,
                        channel_creation=channel['creation']['source'], endpoints=list(flow),
                        semantics='SCM_RIGHTS_open_file_description_reference',
                        scope='complete_serialized_observed_unix_datagram_channel'))
        if channel['errors']:
            diagnostics.append(dict(endpoints=list(key), reasons=sorted(set(channel['errors']))))
        else:
            pairs.extend(tentative)
    paired_sources = {pair[direction] for pair in pairs for direction in ['send','receive']}
    unpaired = [
                    event['source'] for event in events
                    if event.get('descriptor_rights') and event['descriptor_rights']['succeeded']
                    and event['source'] not in paired_sources]
    return dict(pairs=pairs, rejected_channels=diagnostics,
                unpaired_observations=unpaired, observed_datagram_channels=len(channels))


def transfer_graph(result, events, existing_ids):
    """Add transfer observations, never request-ownership assignments."""
    by_source = {e['source']:e for e in events}
    graph = []
    seen = set(existing_ids)
    for index, pair in enumerate(result['pairs']):
        for source in [pair['send'], pair['receive']]:
            identity = 'syscall:'+source
            if identity not in seen:
                event = by_source[source]
                graph.append(dict(type='node', id=identity, kind='syscall',
                    **{key:event.get(key) for key in ['timestamp_ns','duration_ns','completion_ns','pid','tid','syscall','paths','return_value','descriptor_rights']}))
                seen.add(identity)
        identity = f'descriptor-transfer:{index}'
        graph.append(dict(type='node', id=identity, kind='descriptor_transfer', **pair))
        graph.append(dict(type='edge', source='syscall:'+pair['send'], target=identity,
                          kind='descriptor_sent', evidence=pair['send']))
        graph.append(dict(type='edge', source=identity, target='syscall:'+pair['receive'],
                          kind='descriptor_received', evidence=pair['receive']))
    return graph
