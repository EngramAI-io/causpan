#!/usr/bin/env python3
"""Reconstruct causal context from ordered runtime transitions, never paths/timing windows."""
import argparse
from collections import Counter, defaultdict
import json
import hashlib
import uuid
from pathlib import Path
import re
from analyze import parse_traces, clone_has_flag

CLONE_FILES_BIT = 0x400  # Linux clone(2) flag: child shares parent's file descriptor table.
TRANSITIONS={'JS_CONTEXT','WORK_ENTER','WORK_LEAVE','DONE_ENTER','DONE_LEAVE'}
MARKER_KINDS=TRANSITIONS|{'INSTALL','INSTALL_QUEUE','SUBMIT','COMPLETE','INVARIANT_FAILURE','DUPLICATE_WORK','IPC_SEND','IPC_ENTER','IPC_LEAVE','IPC_CANCEL'}

def unique_json_object(pairs):
    result={}
    for key,value in pairs:
        if key in result:raise ValueError(f'duplicate marker field {key}')
        result[key]=value
    return result

def marker(event, run):
    """Extract and validate a native-event marker from a write syscall."""
    if event['syscall']!='write' or event['paths']!=[str(run/'native-events.jsonl')]: return None
    quoted=re.match(r'\d+<[^>]+>,\s*("(?:\\.|[^"\\])*")',event['args'])
    if not quoted: raise ValueError(f'truncated marker at {event["source"]}')
    payload=json.loads(quoted[1])
    count=re.fullmatch(r',\s*(\d+)\s*',event['args'][quoted.end():])
    length=len(payload.encode('utf-8'))
    if not count or int(count[1])!=length or event.get('return_value')!=length:
        raise ValueError(f'incomplete or failed marker write at {event["source"]}')
    data=json.loads(payload,object_pairs_hook=unique_json_object)
    if not isinstance(data,dict):raise ValueError('marker must be an object')
    integers=('csp','tid','request','operation','pointer','status')
    if any(type(data.get(key)) is not int for key in integers):
        raise ValueError(f'invalid marker integer field at {event["source"]}')
    if any(not 0<=data[key]<2**64 for key in ('request','operation','pointer')) or data['tid']<=0:
        raise ValueError(f'invalid marker identity range at {event["source"]}')
    if not isinstance(data.get('kind'),str) or data['kind'] not in MARKER_KINDS:
        raise ValueError(f'unknown marker kind at {event["source"]}')
    if data.get('csp')!=1 or data.get('tid')!=event['tid']:
        raise ValueError(f'invalid marker at {event["source"]}')
    return data

def fd_number(event):
    """Extract the primary file descriptor number from a syscall event."""
    match=re.match(r'\s*(\d+)(?:<[^>]*>)?',event['args'])
    return int(match[1]) if match else None

def close_range_has_flag(args,flag):
    """Check whether close_range args include a specific flag."""
    if flag in args:return True
    match=re.match(r'\s*\d+\s*,\s*\d+\s*,\s*(0x[0-9a-fA-F]+|\d+)',args)
    return bool(match and int(match[1],0)&{'CLOSE_RANGE_CLOEXEC':4,'CLOSE_RANGE_UNSHARE':2}[flag])

def load_request_mapping(path):
    """Load and validate the request-to-context mapping file."""
    records=[]
    seen=set()
    for line in path.read_text().splitlines():
        record=json.loads(line,object_pairs_hook=unique_json_object)
        if not isinstance(record,dict):raise ValueError('request mapping must be an object')
        context=record.get('context')
        if type(context) is not int or not 0<context<2**64 or context in seen:
            raise ValueError('invalid or duplicate context identity')
        kind=record.get('kind','request')
        if kind=='join':
            parents=record.get('parents')
            if not isinstance(parents,list) or not parents or any(type(parent) is not int or parent not in seen for parent in parents):
                raise ValueError('invalid or unobserved join parent')
            if len(parents)!=len(set(parents)):raise ValueError('duplicate join parent')
        elif kind!='request':raise ValueError('unknown mapping kind')
        seen.add(context)
        records.append(record)
    return records


def context_node(context, roots):
    """Return the graph node id for a request or join context."""
    return ('request:' if context in roots else 'join:') + str(context)


class Attributor:
    """Reconstruct causal context from ordered runtime transitions.

    Attributes syscalls to MCP request contexts by processing trace events
    and native-event markers.  Tracks IPC jobs, socket lifecycles, process
    inheritance, and runtime spans to build a complete causal provenance graph.
    """

    def __init__(self, run):
        """Create an attributor for *run* and parse all input files."""
        self.run = run
        self._initialize()

    def _initialize(self):
        """Parse input files, build ownership table, seed the provenance graph."""
        self.events, self.quality = parse_traces(self.run / 'traces')
        self.raw_mapping = load_request_mapping(self.run / 'request-map.jsonl')
        self.mapping = {r['context']: r for r in self.raw_mapping}

        # --- thread / request state ---
        self.state = {}
        self.operations = {}
        self.ipc_jobs = {}
        self.ipc_active = {}
        self.inherited = {}
        self.active_work = defaultdict(list)
        self.runtime_spans = {}
        self.span_threads = defaultdict(set)
        self.seen = defaultdict(list)
        self.errors = []

        # --- request ownership ---
        self.roots = {c: r for c, r in self.mapping.items() if r.get('kind', 'request') == 'request'}
        self.owners = {}
        for r in self.raw_mapping:
            ctx = r['context']
            if r.get('kind', 'request') == 'request':
                self.owners[ctx] = {ctx}
            elif r.get('kind') == 'join':
                parents = r.get('parents', [])
                if not parents or any(parent not in self.owners for parent in parents):
                    self.errors.append(f'unknown or cyclic join parent for context {ctx}')
                    self.owners[ctx] = set()
                else:
                    self.owners[ctx] = set().union(*(self.owners[p] for p in parents))
            else:
                self.errors.append(f'unknown context kind for {ctx}')

        if len(self.raw_mapping) != len(self.mapping) or any(type(c) is not int or c <= 0 for c in self.mapping):
            self.errors.append('invalid or duplicate context identity')

        # --- dispatch cross-check ---
        if (self.run / 'tool-calls.jsonl').exists():
            calls = list(map(json.loads, (self.run / 'tool-calls.jsonl').read_text().splitlines()))
            expected = Counter((type(c['id']).__name__, c['id'], c['tool']) for c in calls)
            mapped = Counter((type(r['rpc_id']).__name__, r['rpc_id'], r['tool']) for r in self.roots.values())
            if expected != mapped:
                self.errors.append('dispatch mappings do not match observed MCP calls')

        # --- output containers ---
        self.tagged = []
        self.graph = []
        self.executed_syscalls = set()

        # --- socket / fd-table state ---
        self.sockets = {}
        self.close_on_exec = set()
        self.fd_tables = {}
        self.socket_generation = 0
        self.socket_nodes = set()
        self.socket_parent_edges = set()
        self.connections_by_id = {}

        settings = json.loads((self.run / 'run-config.json').read_text()) if (self.run / 'run-config.json').exists() else {}
        self.session_id = settings.get('session_id', self.run.name)
        self.fd_table_serial = 0

        # --- provenance graph: request / join nodes ---
        for context, r in self.mapping.items():
            self.graph.append(dict(
                type='node', id=context_node(context, self.roots),
                kind='mcp_request' if context in self.roots else 'causal_join',
                **{k: v for k, v in r.items() if k != 'kind'}))
            if context not in self.roots:
                for parent in r.get('parents', []):
                    self.graph.append(dict(type='edge', source=context_node(parent, self.roots),
                                           target=context_node(context, self.roots), kind='joined'))

    # ---- helper: fd-table management ----------------------------------------

    def _new_fd_table(self):
        """Allocate a fresh fd-table identifier for session-scoped sharing."""
        self.fd_table_serial += 1
        return f'fdtable:{self.session_id}:{self.fd_table_serial}'

    def _fd_table(self, pid):
        """Return the fd-table id for *pid*, allocating on first use."""
        if pid not in self.fd_tables:
            self.fd_tables[pid] = self._new_fd_table()
        return self.fd_tables[pid]

    def _copy_fd_table(self, table):
        """Duplicate *table* so both copies share socket ownership; return new id."""
        copied = self._new_fd_table()
        for (table_id, number), owner in list(self.sockets.items()):
            if table_id == table:
                self.sockets[(copied, number)] = owner
                if (table_id, number) in self.close_on_exec:
                    self.close_on_exec.add((copied, number))
        return copied

    # ---- marker processing ---------------------------------------------------

    def _process_marker(self, note, event):
        """Handle one native-event marker (IPC, work lifecycle, transitions)."""
        tid = event['tid']
        kind = note['kind']
        op = note['operation']
        req = note['request']
        job = note.get('job')
        sender = self.state.get(tid, self.inherited.get(event['pid'], {}))

        if kind == 'IPC_SEND':
            if sender.get('request') != req:
                self.errors.append(f'IPC sender context mismatch for {job}')
            if not isinstance(job, str) or not job or job in self.ipc_jobs:
                self.errors.append(f'invalid or duplicate IPC job {job}')
            else:
                self.ipc_jobs[job] = dict(request=req, started=False, finished=False,
                                           sender_pid=event['pid'], sender_tid=tid)
                self.graph.append(dict(type='node', id=f'ipc:{job}', kind='ipc_job',
                                       request_context=req, sender_pid=event['pid'],
                                       sender_tid=tid, send_evidence=event['source']))
                if req:
                    parent = f'ipc:{sender["ipc_job"]}' if sender.get('origin') == 'ipc_worker' else context_node(req, self.roots)
                    self.graph.append(dict(type='edge', source=parent, target=f'ipc:{job}',
                                           kind='ipc_sent', evidence=event['source']))

        elif kind == 'IPC_CANCEL':
            work = self.ipc_jobs.get(job)
            if not work or work['started'] or work['finished'] or work['request'] != req:
                self.errors.append(f'invalid IPC cancellation {job}')
            else:
                work.update(finished=True, cancelled=True)
                self.graph.append(dict(type='node', id=f'ipc_cancel:{job}', kind='ipc_cancellation',
                                       tid=tid, evidence=event['source']))
                self.graph.append(dict(type='edge', source=f'ipc:{job}', target=f'ipc_cancel:{job}',
                                       kind='cancelled_before_execution'))

        elif kind == 'IPC_ENTER':
            work = self.ipc_jobs.get(job)
            if not work or work['started'] or work['finished'] or work['request'] != req or tid in self.ipc_active:
                self.errors.append(f'invalid IPC entry {job}')
            else:
                work.update(started=True, worker_tid=tid)
                self.ipc_active[tid] = job
            self.state[tid] = dict(request=req, operation=0, origin='ipc_worker', ipc_job=job,
                                   marker_source=event['source'])

        elif kind == 'IPC_LEAVE':
            work = self.ipc_jobs.get(job)
            if not work or self.ipc_active.get(tid) != job or self.state.get(tid, {}).get('request') != req:
                self.errors.append(f'invalid IPC leave {job}')
            else:
                work['finished'] = True
                del self.ipc_active[tid]
            self.state[tid] = dict(request=0, operation=0, origin='async_context',
                                   marker_source=event['source'])

        elif kind == 'SUBMIT':
            if op in self.operations:
                self.errors.append(f'duplicate operation {op}')
            unit = note.get('unit', 'libuv_work')
            self.operations[op] = dict(request=req, started=False, finished=False,
                                       completed=False, worker_tid=None)
            node_kind = 'execution_interval' if unit == 'span_poll' else 'async_work'
            self.graph.append(dict(type='node', id=f'work:{op}', kind=node_kind, unit=unit,
                                   request_context=req))
            if unit == 'span_poll':
                span = note['pointer']
                self.span_threads[(req, span)].add(tid)
                if span not in self.runtime_spans:
                    self.runtime_spans[span] = req
                    self.graph.append(dict(type='node', id=f'task:{span}', kind='runtime_span',
                                           request_context=req))
                    if req:
                        self.graph.append(dict(type='edge', source=context_node(req, self.roots),
                                               target=f'task:{span}', kind='created_task'))
                elif self.runtime_spans[span] != req:
                    self.errors.append(f'runtime span {span} changed identity')
                self.graph.append(dict(type='edge', source=f'task:{span}', target=f'work:{op}', kind='polled'))
            elif req:
                self.graph.append(dict(type='edge', source=context_node(req, self.roots),
                                       target=f'work:{op}', kind='submitted'))

        elif kind == 'WORK_ENTER':
            work = self.operations.get(op)
            if not work or work['request'] != req or work['started']:
                self.errors.append(f'invalid work entry {op}')
            else:
                work.update(started=True, worker_tid=tid)
            self.active_work[tid].append(op)

        elif kind == 'WORK_LEAVE':
            if not self.active_work[tid]:
                self.errors.append(f'work leave without enter on TID {tid}')
            else:
                finished = self.active_work[tid].pop()
                if finished in self.operations:
                    self.operations[finished]['finished'] = True

        elif kind == 'COMPLETE':
            work = self.operations.get(op)
            if not work or work['completed'] or work['request'] != req:
                self.errors.append(f'invalid completion {op}')
            else:
                work.update(completed=True, status=note['status'])

        elif kind in {'INVARIANT_FAILURE', 'DUPLICATE_WORK'}:
            self.errors.append(kind)

        if kind in TRANSITIONS:
            if tid in self.ipc_active:
                self.errors.append(f'context transition inside IPC job {self.ipc_active[tid]}')
            origin = 'worker' if kind == 'WORK_ENTER' else 'completion' if kind == 'DONE_ENTER' else 'async_context'
            self.state[tid] = dict(request=req, operation=op, origin=origin,
                                   marker_source=event['source'])

    # ---- trace (non-marker) syscall processing ------------------------------

    def _process_trace(self, event):
        """Handle one trace syscall event: socket lifecycle, clones, file I/O."""
        # Exclude instrumentation output itself from attributed effects.
        if any(path in {str(self.run / 'request-map.jsonl'), str(self.run / 'native-events.jsonl')}
               for path in event['paths']):
            return

        tid = event['tid']
        context = self.state.get(tid, self.inherited.get(event['pid'], {}))
        request = context.get('request', 0)
        fd = fd_number(event)
        table = self._fd_table(tid)
        key = (table, fd) if fd is not None else None
        socket_state = self.sockets.get(key) if key else None
        pid = event['pid']

        # --- socket creation ---
        if event['syscall'] == 'socket' and event['return_value'] is not None and event['return_value'] >= 0:
            fd = event['return_value']
            key = (table, fd)
            self.socket_generation += 1
            socket_state = dict(requests=set(),
                                id=f'connection:{pid}:{fd}:{self.socket_generation}')
            self.sockets[key] = socket_state
            self.close_on_exec.discard(key)
            if 'SOCK_CLOEXEC' in event['args']:
                self.close_on_exec.add(key)
            self.connections_by_id[socket_state['id']] = socket_state
            if request:
                socket_state['requests'].update(self.owners.get(request, {request}))

        # --- accept / accept4 ---
        elif event['syscall'] in {'accept', 'accept4'} and event['return_value'] is not None and event['return_value'] >= 0:
            listener = self.sockets.get(key) if key else None
            fd = event['return_value']
            key = (table, fd)
            self.socket_generation += 1
            socket_state = dict(requests=set(),
                                id=f'connection:{pid}:{fd}:{self.socket_generation}')
            self.sockets[key] = socket_state
            self.close_on_exec.discard(key)
            if event['syscall'] == 'accept4' and 'SOCK_CLOEXEC' in event['args']:
                self.close_on_exec.add(key)
            self.connections_by_id[socket_state['id']] = socket_state
            if request:
                socket_state['requests'].update(self.owners.get(request, {request}))
            if listener:
                self.socket_nodes.add(socket_state['id'])
                self.graph.append(dict(type='node', id=socket_state['id'], kind='network_connection',
                                       pid=pid, fd=fd))
                self.graph.append(dict(type='edge', source=listener['id'], target=socket_state['id'],
                                       kind='accepted_connection', evidence=event['source']))
                self.graph.append(dict(type='edge', source='syscall:' + event['source'],
                                       target=socket_state['id'], kind='accepted'))

        # --- connect ---
        elif event['syscall'] == 'connect' and fd is not None:
            if socket_state is None:
                self.socket_generation += 1
                socket_state = dict(requests=set(),
                                    id=f'connection:{pid}:{fd}:{self.socket_generation}')
                self.sockets[key] = socket_state
                self.connections_by_id[socket_state['id']] = socket_state
            if request:
                socket_state['requests'].update(self.owners.get(request, {request}))

        # --- dup ---
        elif event['syscall'] in {'dup', 'dup2', 'dup3'} and fd is not None and event['return_value'] is not None and event['return_value'] >= 0:
            destination = (table, event['return_value'])
            if not (event['syscall'] in {'dup2', 'dup3'} and fd == event['return_value']):
                self.sockets.pop(destination, None)
                self.close_on_exec.discard(destination)
                if socket_state:
                    self.sockets[destination] = socket_state
                if socket_state and event['syscall'] == 'dup3' and 'O_CLOEXEC' in event['args']:
                    self.close_on_exec.add(destination)

        # --- fcntl ---
        elif event['syscall'] == 'fcntl' and fd is not None and event['return_value'] is not None and event['return_value'] >= 0:
            if 'F_DUPFD' in event['args']:
                destination = (table, event['return_value'])
                self.sockets.pop(destination, None)
                self.close_on_exec.discard(destination)
                if socket_state:
                    self.sockets[destination] = socket_state
                if socket_state and 'F_DUPFD_CLOEXEC' in event['args']:
                    self.close_on_exec.add(destination)
            elif 'F_SETFD' in event['args']:
                if 'FD_CLOEXEC' in event['args']:
                    self.close_on_exec.add(key)
                else:
                    self.close_on_exec.discard(key)

        # --- close_range ---
        elif event['syscall'] == 'close_range' and event['return_value'] == 0:
            if close_range_has_flag(event['args'], 'CLOSE_RANGE_UNSHARE'):
                table = self._copy_fd_table(table)
                self.fd_tables[tid] = table
            descriptor_range = re.match(r'\s*(\d+)\s*,\s*(\d+)', event['args'])
            if descriptor_range:
                first, last = map(int, descriptor_range.groups())
                descriptors = [item for item in self.sockets if item[0] == table and first <= item[1] <= last]
                if close_range_has_flag(event['args'], 'CLOSE_RANGE_CLOEXEC'):
                    self.close_on_exec.update(descriptors)
                else:
                    for descriptor in descriptors:
                        self.sockets.pop(descriptor, None)
                        self.close_on_exec.discard(descriptor)
            socket_state = None

        # --- clone / fork / vfork ---
        elif event['syscall'] in {'clone', 'clone3', 'fork', 'vfork'} and (event['return_value'] or 0) > 0:
            child = event['return_value']
            if clone_has_flag(event['args'], 'CLONE_FILES'):
                self.fd_tables[child] = table
            else:
                self.fd_tables[child] = self._copy_fd_table(table)

        # --- unshare ---
        elif event['syscall'] == 'unshare' and event['return_value'] == 0:
            flags = event['args'].strip()
            if 'CLONE_FILES' in flags or (re.fullmatch(r'0x[0-9a-fA-F]+|\d+', flags) and int(flags, 0) & CLONE_FILES_BIT):
                self.fd_tables[tid] = self._copy_fd_table(table)

        # --- exec ---
        elif event['syscall'] in {'execve', 'execveat'} and event['return_value'] == 0:
            table = self._copy_fd_table(table)
            self.fd_tables[tid] = table
            for descriptor in [item for item in self.close_on_exec if item[0] == table]:
                self.sockets.pop(descriptor, None)
                self.close_on_exec.discard(descriptor)

        # --- socket I/O updates ownership ---
        if socket_state and event['syscall'] in {'read', 'readv', 'recvfrom', 'recvmsg',
                                                  'write', 'writev', 'sendto', 'sendmsg'}:
            socket_state['requests'].update(
                self.owners.get(request, {request}) if request else ())

        # --- close ---
        if socket_state and event['syscall'] == 'close' and key and event['return_value'] == 0:
            self.sockets.pop(key, None)
            self.close_on_exec.discard(key)

        # --- graph: connection node ---
        if socket_state and socket_state['id'] not in self.socket_nodes:
            self.socket_nodes.add(socket_state['id'])
            self.graph.append(dict(type='node', id=socket_state['id'], kind='network_connection',
                                   pid=pid, fd=fd))

        # --- graph: ownership edges ---
        if socket_state:
            for parent in sorted(socket_state['requests']):
                relation = (parent, socket_state['id'])
                if relation not in self.socket_parent_edges:
                    self.socket_parent_edges.add(relation)
                    self.graph.append(dict(type='edge', source=context_node(parent, self.roots),
                                           target=socket_state['id'], kind='connected',
                                           evidence=event['source']))

        # --- graph: socket-effect edge + unscoped-read attribution ---
        if socket_state:
            if event['syscall'] in {'read', 'readv', 'recvfrom', 'recvmsg',
                                    'write', 'writev', 'sendto', 'sendmsg'}:
                self.graph.append(dict(type='edge', source=socket_state['id'],
                                       target='syscall:' + event['source'],
                                       kind='socket_effect', evidence=event['source']))
            if not request and len(socket_state['requests']) == 1 and event['syscall'] in {'read', 'readv', 'recvfrom', 'recvmsg'}:
                request = next(iter(socket_state['requests']))
                context = dict(request=request, operation=0, origin='socket_lifecycle',
                               marker_source=self.session_id + ':' + socket_state['id'])

        # --- clone: process inheritance ---
        if event['syscall'] in {'clone', 'clone3', 'fork', 'vfork'} and (event['return_value'] or 0) > 0 \
           and not clone_has_flag(event['args'], 'CLONE_THREAD'):
            child = event['return_value']
            self.inherited[child] = dict(request=context.get('request', 0), operation=0,
                                         origin='process_inheritance', marker_source=event['source'])
            self.graph.append(dict(type='node', id=f'process:{child}', kind='child_process', pid=child))
            if context.get('request'):
                if context.get('origin') == 'ipc_worker':
                    spawn_parent = f'ipc:{context["ipc_job"]}'
                elif context.get('origin') == 'process_inheritance':
                    spawn_parent = f'process:{event["pid"]}'
                elif context.get('operation'):
                    spawn_parent = f'work:{context["operation"]}'
                else:
                    spawn_parent = context_node(context['request'], self.roots)
                self.graph.append(dict(type='edge', source=spawn_parent, target=f'process:{child}',
                                       kind='spawned', evidence=event['source']))

        # --- per-syscall row ---
        request = request or context.get('request', 0)
        request_ids = [self.roots[parent]['rpc_id'] for parent in sorted(self.owners.get(request, set()))]
        candidate_ids = []
        if socket_state and len(socket_state['requests']) > 1 and not context.get('request'):
            candidate_ids = [self.roots[parent]['rpc_id'] for parent in sorted(socket_state['requests'])]

        if request_ids:
            attribution = 'multi_parent' if len(request_ids) > 1 else 'bound'
        elif context.get('request') == 0:
            attribution = 'no_request_context'
        else:
            attribution = 'unknown'

        row = dict(**event, context=request,
                   request_ids=request_ids,
                   request_id=request_ids[0] if len(request_ids) == 1 else None,
                   ipc_job=context.get('ipc_job'),
                   operation=context.get('operation', 0),
                   origin=context.get('origin', 'unobserved'),
                   context_evidence=context.get('marker_source'),
                   connection_id=socket_state['id'] if socket_state else None,
                   candidate_request_ids=candidate_ids,
                   attribution=attribution)
        self.tagged.append(row)

        if request or socket_state:
            event_id = 'syscall:' + event['source']
            self.graph.append(dict(type='node', id=event_id, kind='syscall',
                                   timestamp_ns=event['timestamp_ns'],
                                   pid=pid, tid=tid, syscall=event['syscall'],
                                   paths=event['paths'], return_value=event['return_value']))
            if request and event_id not in self.executed_syscalls:
                if row['origin'] == 'ipc_worker':
                    parent = f'ipc:{row["ipc_job"]}'
                elif row['origin'] == 'process_inheritance':
                    parent = f'process:{pid}'
                elif row['operation']:
                    parent = f'work:{row["operation"]}'
                else:
                    parent = context_node(request, self.roots)
                self.graph.append(dict(type='edge', source=parent, target=event_id, kind='executed',
                                       evidence=row['context_evidence']))
                self.executed_syscalls.add(event_id)

    # ---- retroactive socket-read binding -------------------------------------

    def _bind_socket_reads(self):
        """Resolve unscoped socket reads retroactively; returns count of resolved reads."""
        retroactive = 0
        for row in self.tagged:
            connection_id = row.get('connection_id')
            if not connection_id or row['syscall'] not in {'read', 'readv', 'recvfrom', 'recvmsg'}:
                continue
            if row['context'] and row['origin'] != 'socket_lifecycle':
                continue
            if row['attribution'] not in {'no_request_context', 'unknown', 'ambiguous_resource'} \
               and row['origin'] != 'socket_lifecycle':
                continue

            connection = self.connections_by_id.get(connection_id)
            request_contexts = sorted(connection['requests']) if connection else []
            if not request_contexts:
                continue

            request_ids = [self.roots[c]['rpc_id'] for c in request_contexts]
            row['context_evidence'] = self.session_id + ':' + connection_id
            row['origin'] = 'socket_lifecycle'
            retroactive += 1

            if len(request_contexts) == 1:
                row['context'] = request_contexts[0]
                row['request_ids'] = request_ids
                row['request_id'] = request_ids[0]
                row['attribution'] = 'bound'
            else:
                row['context'] = 0
                row['request_ids'] = []
                row['request_id'] = None
                row['candidate_request_ids'] = request_ids
                row['attribution'] = 'ambiguous_resource'
        return retroactive

    # ---- invariant validation -----------------------------------------------

    def _validate_invariants(self):
        """Cross-check markers against the native log and verify operation / IPC completeness."""
        expected = defaultdict(list)
        for note in map(json.loads, (self.run / 'native-events.jsonl').read_text().splitlines()):
            expected[note['tid']].append(note)
        if dict(expected) != dict(self.seen):
            self.errors.append('marker stream differs from native log (capture loss or corruption)')
        for key in ['unparsed', 'orphan_resumed', 'incomplete_at_eof', 'non_timestamp_lines']:
            if self.quality.get(key):
                self.errors.append(f'parser quality {key}={self.quality[key]}')
        for op, work in self.operations.items():
            if work.get('status') == 0 and not (work['started'] and work['finished']):
                self.errors.append(f'operation {op} completed without observed execution bracket')
            if work.get('status') == -125 and work['started']:
                self.errors.append(f'cancelled operation {op} was executed')
        if self.ipc_active or any(not job['finished'] for job in self.ipc_jobs.values()):
            self.errors.append('unfinished IPC jobs')
        if any(self.active_work.values()):
            self.errors.append('unclosed worker execution context')
        unfinished = [op for op, w in self.operations.items() if not w['completed']]
        if unfinished:
            self.errors.append(f'{len(unfinished)} operations lack completion')

    # ---- output writing ------------------------------------------------------

    def _write_outputs(self, tagged, graph, report):
        """Write causal-attribution.jsonl, provenance.jsonl, and causal-report.json."""
        def write(name, rows):
            (self.run / name).write_text(''.join(json.dumps(r) + '\n' for r in rows))

        write('causal-attribution.jsonl', tagged)

        resources = {}
        for node in list(graph):
            if node.get('kind') != 'syscall':
                continue
            for path in node['paths']:
                rid = 'resource:' + str(len(resources)) if path not in resources else resources[path]
                if path not in resources:
                    resources[path] = rid
                    graph.append(dict(type='node', id=rid, kind='observed_resource', name=path,
                                      identity='pathname_or_fd_annotation'))
                syscall = node['syscall']
                success = node['return_value'] is not None and node['return_value'] >= 0
                if syscall in {'read', 'pread64', 'readv', 'recvfrom', 'recvmsg'} and success:
                    kind = 'read_from'
                elif syscall in {'write', 'pwrite64', 'writev', 'sendto', 'sendmsg'} and success:
                    kind = 'wrote_to'
                elif success:
                    kind = 'referenced'
                else:
                    kind = 'attempted_access'
                graph.append(dict(type='edge', source=node['id'], target=rid, kind=kind,
                                  semantics='resource_observation_not_data_dependency'))

        for record in graph:
            for field in ['id', 'source', 'target']:
                if field in record:
                    record[field] = self.session_id + ':' + record[field]
            record['session_id'] = self.session_id

        write('provenance.jsonl', graph)

        report['analysis_id'] = uuid.uuid4().hex
        report['output_sha256'] = {
            name: hashlib.sha256((self.run / name).read_bytes()).hexdigest()
            for name in ['causal-attribution.jsonl', 'provenance.jsonl']
        }
        temporary = self.run / 'causal-report.json.tmp'
        temporary.write_text(json.dumps(report, indent=2) + '\n')
        temporary.replace(self.run / 'causal-report.json')

    # ---- public entry point --------------------------------------------------

    def attribute(self):
        """Run the full attribution pipeline.  Returns the causal report dict."""
        retroactive = 0

        for event in self.events:
            note = marker(event, self.run)
            tid = event['tid']
            if note:
                self.seen[tid].append(note)
                kind = note['kind']
                op = note['operation']
                req = note['request']
                if req and req not in self.mapping:
                    self.errors.append(f'unknown request context {req}')
                self._process_marker(note, event)
                continue
            self._process_trace(event)

        retroactive = self._bind_socket_reads()

        # Socket-effect edges retain ownership evidence; discard any earlier singleton
        # execution edge that a later shared owner has made unjustified.
        lifecycle_events = {'syscall:' + row['source'] for row in self.tagged
                            if row['origin'] == 'socket_lifecycle'}
        self.graph = [record for record in self.graph
                       if not (record.get('kind') == 'executed' and record.get('target') in lifecycle_events)]

        for row in self.tagged:
            if row.get('connection_id'):
                row['connection_id'] = self.session_id + ':' + row['connection_id']

        self._validate_invariants()

        # Evaluation sidecar — consulted only after inference, never changes assignments.
        oracle = {r['source']: r for r in map(json.loads, (self.run / 'attribution.jsonl').read_text().splitlines())}
        selected = [r for r in self.tagged if r['source'] in oracle]
        score = Counter()
        per_request = Counter()
        for evt in selected:
            truth = oracle[evt['source']]['oracle_request_id']
            score['events'] += 1
            score[evt['attribution']] += 1
            for request_id in evt['request_ids']:
                per_request[str(request_id)] += 1
            if truth is not None:
                score['oracle_labelled'] += 1
                score['oracle_correct' if evt['request_id'] == truth else 'oracle_wrong'] += 1
        if score['oracle_wrong']:
            self.errors.append(f'{score["oracle_wrong"]} independent path-oracle disagreements')

        report = dict(
            valid=not self.errors,
            errors=self.errors,
            attribution_model='causal-context-v2',
            requests=len(self.roots),
            joins=len(self.mapping) - len(self.roots),
            operations=len(self.operations),
            operations_started=sum(w['started'] for w in self.operations.values()),
            operations_cancelled=sum(w.get('status') == -125 for w in self.operations.values()),
            ipc_jobs=len(self.ipc_jobs),
            ipc_cancelled=sum(w.get('cancelled', False) for w in self.ipc_jobs.values()),
            inherited_processes=len(self.inherited),
            runtime_spans=len(self.runtime_spans),
            retroactive_socket_reads=retroactive,
            migrating_request_spans=sum(req != 0 and len(tids) > 1 for (req, span), tids in self.span_threads.items()),
            markers=sum(map(len, self.seen.values())),
            parser=self.quality,
            all_event_status=dict(Counter(e['attribution'] for e in self.tagged)),
            fixture_score=dict(score),
            fixture_events_per_request=dict(per_request),
        )

        if self.errors:
            # Fail closed: retain tentative diagnostics but never publish as valid bindings.
            for row in self.tagged:
                row['attribution'] = 'invalid_capture'
                row['request_id'] = None
                row['request_ids'] = []
                row['context'] = None
            self.graph = []

        self._write_outputs(self.tagged, self.graph, report)

        print(json.dumps(report, indent=2))
        if self.errors:
            raise RuntimeError('; '.join(self.errors))
        if score['oracle_wrong']:
            raise RuntimeError(f'{score["oracle_wrong"]} oracle disagreements')
        return report


# ---- public wrapper ---------------------------------------------------------

def attribute(run):
    """Thin wrapper: invalidate previous results, then delegate to Attributor."""
    report_path = run / 'causal-report.json'
    report_path.write_text(json.dumps({'valid': False, 'errors': ['analysis in progress']}) + '\n')
    (run / 'causal-attribution.jsonl').write_text('')
    (run / 'provenance.jsonl').write_text('')
    try:
        return Attributor(run).attribute()
    except Exception as error:
        report = json.loads(report_path.read_text())
        report['valid'] = False
        if str(error) not in report.setdefault('errors', []):
            report['errors'].append(str(error))
        (run / 'provenance.jsonl').write_text('')
        (run / 'causal-attribution.jsonl').write_text('')
        report.pop('output_sha256', None)
        report_path.write_text(json.dumps(report, indent=2) + '\n')
        raise


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('run', type=Path)
    attribute(p.parse_args().run.resolve())
