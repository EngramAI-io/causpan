# Runtime attribution: experimental results

The prototype now connects MCP request identities to captured Linux syscalls through
runtime execution context. It has been exercised with a real Codex agent and the
official filesystem MCP server, and with controlled Node and Rust/Tokio MCP servers.
This is an executable research mechanism, not a complete security provenance system.

## What the experiments established

| Experiment | Observation |
| --- | --- |
| Serial official filesystem requests | All 16 labelled filesystem events fit one request window. |
| Concurrent official filesystem requests | All 128 labelled events had ambiguous request windows. |
| Real LLM agent with runtime instrumentation | All 16 selected filesystem events were bound; the unique-path oracle independently checked 8. |
| Fresh real-agent rerun after terminal-trace fix | The Codex agent completed four MCP calls (two reads, one write, one read-back); all 16 selected events were bound and all 8 unique-path oracle labels were correct. One child trace ended in blocked `epoll_pwait` followed by explicit SIGTERM during process-group teardown; the parser now reports this as `terminal_interrupted` rather than false truncation. See [agent follow-up evidence](../experiments/mcp/evidence/agent-followup.json). |
| Forged MCP context metadata | At concurrency 32, string JSON-RPC IDs remained intact and all 192 request I/O events matched the byte-offset oracle despite every tool call carrying forged owner metadata; 12 background events remained separate. See [spoof-resistance evidence](../experiments/mcp/evidence/spoofed-context.json). |
| Detached Node work | 192 request I/O events occurred after their MCP responses; all were correctly attributed. |
| Shared work with one scalar owner | Two batched writes lost 30 of 32 expected request-parent edges. |
| Shared work with explicit context joins | Node and Tokio each recovered all 32 edges with no extra parents; each scalar control missed 30. |
| Node regression matrix | 120/120 runs passed capture validation and applicable independent oracles. |
| Post-descriptor Node matrix | A fresh 36-run matrix passed at concurrency 1, 8, and 32 across read, nested async work, child processes, dedicated TCP, and shared TCP. All reports and applicable independent scores were valid after adding `fcntl(F_DUPFD*)` aliasing and `close_range` invalidation. See [matrix evidence](../experiments/mcp/evidence/postfd-matrix.json). |
| Analyzer graph-build optimization | Replacing a per-syscall full-graph scan with a target set retained separate execution and socket-effect edges and cut c32 subprocess case elapsed time from 38.0/38.6 seconds to 6.5/7.3 seconds. All four post-change c32 subprocess/shared-TCP cases passed; the two timing pairs are single observations. See [performance evidence](../experiments/mcp/evidence/analyzer-performance.json). |
| Tokio regression matrix | 48/48 runs passed; 959 request-owned runtime spans migrated between kernel threads. |
| Tokio stress matrix | 12/12 runs passed at concurrency 128, checking 10,496 request I/O events and 2,602 migrating request-owned spans. |
| Node batch stress | All 512 parent edges recovered across five shared writes at concurrency 128. |
| Tokio join matrix | 6/6 runs passed at concurrency 1, 8, and 32 with one and four blocking workers. |
| Tokio registry regressions | 14/14 runs passed after the new request registry, covering ordinary reads, nested work, detached work, children, cancellation, and failures. |
| TCP lifecycle | 6/6 dedicated-connection runs passed across concurrency 1, 8, and 32. The original run attributed 16/16 request writes and later reads; reused or shared sockets remain candidates. |
| Inbound accepted TCP | Live MCP calls received independent TCP clients at concurrency 1, 8, and 32. Connection-history recovery attributed 1, 8, and 32 earlier unscoped reads respectively; all 2, 16, and 64 read/write payload checks passed exactly with no extra candidates. The initial run failed precisely on the inbound read before the request-scoped response write. See [inbound evidence](../experiments/mcp/evidence/inbound-network.json). |
| Shared inbound stream | Eight, 32, 128, and 256 concurrent MCP calls shared one accepted TCP connection. Each run produced one aggregate `read` with exactly 8, 32, 128, or 256 request candidates; all response writes were individually bound. All 9, 33, 129, and 257 payload checks passed with no extra candidates. Query traversal reaches every candidate request node. See [shared inbound evidence](../experiments/mcp/evidence/inbound-network-shared.json). |
| Final-tree shared inbound stress | Repeated the 256-call case after the parser fix: 257/257 payload checks passed, with exactly 256 candidates on the aggregate read and no extra candidate edges. See [final stress evidence](../experiments/mcp/evidence/inbound-shared-c256-final.json). |
| Descriptor-table regression run | Fresh concurrency-32 child-process and inbound-network runs passed after descriptor table identity changes: the file oracle checked 64 request events with no mismatches, and inbound TCP passed 64/64 payload checks. A live Linux `clone3(CLONE_FILES)` probe confirmed a child-created socket descriptor remained visible to the parent; synthetic trace regressions check attribution’s shared-table and copied-table behavior. See [spawn evidence](../experiments/mcp/evidence/clonefd-spawn-c32.json), [network evidence](../experiments/mcp/evidence/clonefd-inbound-c32.json), and [live probe evidence](../experiments/mcp/evidence/clone-files-live.json). |
| MCP `CLONE_FILES` workload | Added a dedicated tool whose C helper clones with `CLONE_FILES`, creates a socket and writes its request slot in the child, then verifies both from the parent. At concurrency 8 (two batches) and 32, 16/32 calls produced 32/64 expected file events, all of which were bound to the correct request, and no oracle mismatches occurred. See [MCP probe evidence](../experiments/mcp/evidence/clone-files-mcp.json). A fresh concurrency-32 run after fixing helper failure handling again attributed all 64 request offset events correctly, with six background events kept separate. Injecting a child write failure through `/dev/full` now returns an error instead of hanging; [failure-path evidence](../experiments/mcp/evidence/clone-files-helper-failures.json) also records invalid-slot checks. |
| Outbound regression after connection-history change | A fresh concurrency-32 multiplexed run passed all 33 payload checks with no extra candidates and required no retroactive socket reads; see [run evidence](../experiments/mcp/evidence/network-postretro-regression.json). |
| Multiplexed TCP | 6/6 runs passed candidate coverage at concurrency 1, 8, and 32. At concurrency 32, 128 request writes and four aggregate reads produced 192 extra candidate edges; no response contributor was missed. Per-event oracle labels and candidate sets are preserved in [multiplexed TCP evidence](../experiments/mcp/evidence/multiplexed-network-events.json). |
| Current-tree multiplexed TCP check | A fresh instrumented concurrency-8 run passed all 9 independent payload coverage checks with no extra candidate edges; see [run evidence](../experiments/mcp/evidence/current-network-check.json). |
| Syscall filter comparison | At the same 8-way, 16-call filesystem workload, `trace=all` captured 6,230 calls versus 4,025 for the default filter (54.8% more); fixture labels and bindings were unchanged. |

The matrices vary concurrency (1, 8, 32) and worker-pool size (1, 4), with
two batches per run. Node repeats each configuration twice. Tokio uses two async
workers and one repetition. Both cover shared and unique reads, shared-descriptor
I/O, nested scopes, detached work, child processes, cancellation, and failed writes.
Node additionally covers filesystem edits/renames. Both runtimes now support
explicitly joined batches; the original Tokio matrix predates that adapter.
The [batch comparison](../experiments/mcp/evidence/batch-comparison.json) preserves
both scalar failures and successful joins. The controlled Tokio batch tool waits
for an explicit batch width: a 15 ms timer initially produced only singleton
writes under tracing overhead, so that first run did not test shared work.
The checked-in [matrix evidence](../experiments/mcp/evidence/runtime-matrices.json)
contains per-case reports. Full traces and code snapshots are local under
`results/mcp/matrix-v3` and `results/mcp/tokio-matrix-v1`.

The default capture filter is `%file,%process,%desc,%network`. It excludes other
syscall classes. On the paired filesystem run, unfiltered capture added 2,205
calls (mostly runtime and synchronization work) without changing the 64 selected
fixture file events. See [capture scope evidence](../experiments/mcp/evidence/capture-scope.json).
`strace-all` is available for experiments that need a wider syscall view.

Some earlier matrix reports used the v1 label `background` for any zero-context
state. Attribution v2 reports that case as `no_request_context`: the runtime
evidence says no MCP request was active but does not prove the operation was an
intentional background task. Independent offset oracles still verify that these
events have no request parent in the controlled workloads. The default filter
also means these counts do not describe every syscall in the process.
Startup events and work outside an observed scope can remain unknown. Shared reads
without distinguishable effects have structural checks but no unique-path accuracy
oracle. Byte offsets and known write payloads supply independent labels in the
controlled tests; the attributor does not use them to infer ownership.

## Implemented mechanism

1. The server assigns an internal context to each accepted `tools/call` request.
   Client metadata is not accepted as attribution authority. String and integer
   JSON-RPC IDs are preserved, and duplicate IDs are rejected within the session.
2. Runtime instrumentation carries that context across execution handoffs.
   Node uses async context plus libuv work submission/execution hooks. Tokio uses
   a `tracing_subscriber` layer, instrumented request futures, and Tokio's runtime
   spans, including ordinary `tokio::fs` blocking tasks.
3. Bounded marker writes and application syscalls are captured together by strace.
   Per-thread execution scopes bind each observed syscall to its active context.
   Child processes inherit their initiating context at an observed process fork.
4. Explicit joins represent work shared by several requests. The graph retains
   every parent, rather than selecting one request arbitrarily.
5. The analyzer checks marker completeness, balanced execution, request mappings,
   parser losses, and independent fixture oracles. Invalid analyses clear their
   published graph and bindings. Queries verify published output hashes.

The graph distinguishes requests, joined contexts, runtime work, execution
intervals, processes, syscalls, network connections, and observed resources.
A single request can own a later socket read through its traced `connect`; if a
second request uses that same connection, later unscoped reads become candidate
sets with `ambiguous_resource` status, never a copied singleton owner. The live
TCP run and a reuse regression verify this behavior. See the
[network comparison](../experiments/mcp/evidence/network-comparison.json). Resource observation edges
are not data-flow edges: reading and later writing the same path does not by itself
prove a data dependency. Tokio task spans and individual polls are separate nodes.
Its current markers record poll execution, not a complete queue lifecycle; an
aborted task that never polls has no execution interval.

The syscall model also tracks successful `accept`/`accept4` returns as distinct
connections and links them to an observed listener. A regression test exercises
request-scoped writes on an accepted socket followed by a context-free read.
Socket identity also survives `dup`, `dup2`, `dup3`, and `fcntl(F_DUPFD*)`; a test
closes the original descriptor before reading through its duplicate. Successful
`close_range` calls invalidate the affected descriptors, with a regression for
subsequent regular-file fd reuse. Descriptor-table state is copied across
ordinary process creation and shared across decoded `CLONE_FILES` clone/clone3
flags; regressions verify both child-to-parent visibility and independent close
behavior. Numeric clone3 flags are decoded for `CLONE_FILES` and `CLONE_THREAD`.
Close-on-exec state is tracked for sockets created with `SOCK_CLOEXEC`, accepted
with `accept4`, duplicated with `dup3`/`F_DUPFD_CLOEXEC`, changed with
`F_SETFD`, and marked with `close_range(CLOSE_RANGE_CLOEXEC)`. A successful exec
removes those descriptors; when the descriptor table was shared, the executing
process first receives a copied table, matching Linux exec behavior. A regression
checks numeric `close_range` flags and descriptor reuse after exec. Table identity is tracked per Linux TID, including `unshare(CLONE_FILES)` and
`close_range(CLOSE_RANGE_UNSHARE)`; synthetic regressions ensure a thread’s
unshare-and-close leaves a peer’s descriptor intact. Unknown syscall returns
do not count as successful descriptor mutations. The final two live MCP
regressions passed 64 request file-event checks and 33 shared-stream payload
checks; [lifecycle evidence](../experiments/mcp/evidence/fdtable-lifecycle.json)
records their source hashes and the preceding runs. Some less common
FD-producing syscalls and numeric flag encodings remain unmodeled. The modeled
semantics follow the Linux manuals for [execve](https://man7.org/linux/man-pages/man2/execve.2.html)
and [close_range](https://man7.org/linux/man-pages/man2/close_range.2.html).
For accepted sockets, a second pass also considers later request-owned effects on
the same connection when assigning an earlier unscoped read. An exclusive
connection can supply one owner; a reused connection stays a candidate set. Live
MCP-over-stdio tests exercised dedicated inbound TCP clients at concurrency 1, 8,
and 32, and one shared inbound connection at concurrency 8, 32, 128, and 256. The
outbound multiplexed-stream matrix remains a separate experiment.

## Failures that shaped the implementation

The first network capture had request-owned TCP writes but zero-context reads and failed its independent oracle. The socket lifecycle bridge corrected it. Two earlier shared-socket attempts failed due to harness defects (wrong scenario dispatch, then a one-message echo server); both are preserved in the network comparison evidence.


Nested Node scopes originally erased the outer context on exit. Restoring a stack
fixed the independent shared-descriptor test. The optimized Node binary also
inlines one libuv submission path, so hooking only `uv__work_submit` missed
`uv_queue_work`; a second verified hook fixed cancellation and failure probes.
Child writes initially remained unknown until process-inheritance edges were
added. Heavy process-spawn tests exposed strace restart records that the parser
did not recognize; those runs failed closed and passed after the parser fix.

The scalar batching counterexample remains a deliberate failing experiment.
Context propagation alone cannot discover that a write represents several
requests. The batching integration must supply the contributing contexts.

## Reproduce

The Python harness currently has 26 passing regression tests; the Rust runtime library has 3 focused tests. The original 212 matrix cases and the fresh 36-case post-descriptor matrix are preserved separately, in addition to the live inbound dedicated- and shared-connection runs.

See [environment setup](mcp-experiment.md) for Node, npm, strace, and agent setup.
The scope comparison with related kernel provenance and agent observability work is in
[related systems](related-systems.md); those systems were not benchmarked in this repository.
From the repository root:

```bash
python3.11 -m unittest discover -s experiments/mcp -p 'test_*.py'
cargo test -p causpan-runtime
python3.11 experiments/mcp/build_tokio.py
python3.11 experiments/mcp/run.py --runtime tokio --mode replay --scenario detached --instrumented --seccomp --concurrency 8 --pool-size 4 --batches 2 --output results/mcp/my-tokio-run
python3.11 experiments/mcp/query.py results/mcp/my-tokio-run --request 3 --fixture-only
python3.11 experiments/mcp/render.py results/mcp/my-tokio-run
python3.11 experiments/mcp/run.py --runtime node --mode replay --scenario network-inbound --instrumented --seccomp --concurrency 32 --pool-size 8 --batches 1 --output results/mcp/my-inbound-run
python3.11 experiments/mcp/run.py --runtime node --mode replay --scenario network-inbound-shared --instrumented --seccomp --concurrency 32 --pool-size 16 --batches 1 --output results/mcp/my-shared-inbound-run
python3.11 experiments/mcp/run.py --runtime node --mode replay --scenario clone-files --instrumented --seccomp --concurrency 32 --pool-size 16 --batches 1 --output results/mcp/my-clone-files-run
```

Output directories must be new. Each run preserves its configuration, source
snapshot, manifest, protocol records, traces, attribution, and evaluation reports.
The build helper records executable and source hashes; subsequent runs reject
stale builds with that manifest. Older captures include executable hashes and
source snapshots but do not prove those sources produced that executable.
The earlier real-agent captures remain available. A later agent attempt hit the
account usage limit before tool execution; it is recorded as failed and was not
replaced with scripted replay.

## Limits and next research questions

The Node native hook is restricted to the verified AArch64 Node 24.20.0 executable
and libuv 1.52.1. It installs before server work starts; it is not a general late
attach mechanism. The Tokio bridge is source-level and requires the pinned
runtime's tracing support plus `tokio_unstable`. Arbitrary executors, custom native
threads, long-lived child request channels, and cross-host calls need additional
handoff adapters. Socket ownership assumes an exclusive connection until another
request is observed using it; TLS/HTTP2 stream IDs, shared socket reads, implicit
connection pools, and multi-process descriptor transfer require protocol-aware
provenance adapters. Kernel PID reuse, inode identity, io_uring, and distributed
clock/identity lifetimes are not fully modeled.

Instrumentation and marker files are trusted. A compromised server can forge or
omit userspace evidence; these experiments do not provide a tamper-resistant
security boundary. eBPF capture was not executed on this host. CamFlow and
OpenTelemetry were not benchmarked, so the results establish limitations of the
implemented PID/window baselines, not comparative claims about those systems.
The collector probe found no effective Linux capabilities, `perf_event_paranoid=2`,
and root-only syscall tracepoint access under `/sys/kernel/tracing`; `perf trace`
failed with permission denied. This host therefore cannot validate an eBPF or
perf-tracepoint collector without an external privilege/configuration change.

Tracing is expensive. In one randomized 20-run benchmark after TID caching and
strace seccomp filtering, median traced execution was 0.689 seconds without the
bridge versus 7.569 seconds with it (10.98x). Capture-off medians were 0.533 and
0.541 seconds on a noisy shared host; that small sample does not establish
negligible instrumentation overhead. A lower-overhead collector and sustained
throughput measurements remain necessary.

The original Rust workload/evaluator is a separate early scaffold. Its baselines
still need an oracle-isolation audit; its scores should not be combined with the
MCP matrix. Use the MCP pipeline for the results above.

The smoke script was rerun after making its outputs unique and failure-sensitive.
It captured 193 syscalls for four ground-truth operations. Its legacy evaluator
matched all four with the oracle-assisted PID strategy and none with PID/TID or
temporal-window strategies: ground truth ran on a different worker TID from the
actual file syscalls, and the evaluator keys those baselines by the ground-truth
TID. This is consistent with the scaffold warning above and is not MCP pipeline
accuracy evidence. The local run is preserved under `results/mcp/smoke-test.*`.

## Persistent shared-worker IPC experiment

A new `worker_slot` tool uses one Python child launched before any MCP request,
with four reused pool threads. The server sends its internally allocated context
alongside the job over private stdin; the worker writes checked context markers
on its executing TID and resets context to zero in `finally`. The slot is only
workload data. Attribution does not inspect the slot; the offset oracle scores
it afterwards.

At concurrency 16 across two batches, `worker-unscoped` completed all tool calls
but left all 64 request file events without an identity. Its capture is valid;
the manifest records failure because the exact-attribution oracle rejects those
missing bindings. With `worker-context`, all 64 events were correctly attributed.
At concurrency 64 across two batches, string RPC IDs and forged client context
metadata, all 256 request events were correctly attributed and 14 background
events remained separate. See [reports and worker reuse observations](../experiments/mcp/evidence/persistent-worker.json).

Reproduce with:

```bash
python3.11 experiments/mcp/run.py --runtime node --mode replay --scenario worker-context --instrumented --seccomp --concurrency 64 --pool-size 4 --batches 2 --string-ids --spoof-context --output results/mcp/my-worker-context
# Expected oracle failure: identical workload without the context handoff.
python3.11 experiments/mcp/run.py --runtime node --mode replay --scenario worker-unscoped --instrumented --seccomp --concurrency 16 --pool-size 4 --batches 2 --output results/mcp/my-worker-unscoped
```

This closes the tested file-execution boundary for a cooperative, persistent
worker. It does not attribute individual messages in shared IPC reads, add
explicit enqueue/dequeue edges to the graph, authenticate a malicious worker,
or cover worker cancellation, crashes, nested dispatch, or kernel-only capture.
Those remain separate experiments and implementation work.

### Persistent worker failure and context reset

The `worker-failure` scenario alternates normal read/write jobs with writes to a
read-only descriptor (expected `EBADF`). Every job then resets context and writes
a background slot on the same worker TID. At concurrency 32 across three batches,
all 144 request events were correctly attributed, including 48 failed writes.
All 96 worker background writes had no request identity; another 25 server
background events also remained separate. The oracle checks expected failure
from the input slot and scenario, verifies each response, and requires one
background event per completed job on each worker thread. Deliberately injecting
a stale background request or removing a worker background event caused scoring
to fail. See [failure/reset evidence](../experiments/mcp/evidence/persistent-worker-failure.json).

```bash
python3.11 experiments/mcp/run.py --runtime node --mode replay --scenario worker-failure --instrumented --seccomp --concurrency 32 --pool-size 4 --batches 3 --output results/mcp/my-worker-failure
```

This covers caught job exceptions and thread reuse. Abrupt worker death and
cancellation are not covered by this experiment.

### Explicit IPC job provenance

The adapter now emits checked `IPC_SEND`, `IPC_ENTER`, and `IPC_LEAVE` markers
using a server-assigned job ID separate from both request context and oracle slot.
The analyzer validates unique sends, matching entry contexts, single execution,
matching worker exit, and completed brackets. It inserts an `ipc_job` node between
the request and worker syscalls. Missing or inconsistent lifecycle records invalidate
the capture. These are trusted application handoff records, not kernel proof of
message delivery or byte-level IPC dependencies.

A fresh `worker-failure` run at concurrency 32 across two batches passed: 64 job
nodes, 64 request-to-job edges with matching context, and 96 job-to-file-syscall
edges (including 32 failed writes). All 64 post-job worker background writes
remained unscoped. [Graph and scoring evidence](../experiments/mcp/evidence/persistent-worker-ipc.json)
records these checks. IDs currently assume one emitting dispatcher per session;
multiple dispatcher namespaces, abrupt exits, and cancellation need further work.

### IPC lifecycle integrity regressions

Synthetic traces with matching marker-log copies now exercise missing sends,
duplicate sends/entries/exits, mismatched request contexts, wrong-thread exits,
missing exits, and a context switch away and back during execution. The last
case initially passed incorrectly: checking only entry and exit missed a
misattributed middle effect. The analyzer now rejects runtime context transitions
inside an active IPC job. This adapter currently supports flat worker jobs;
nested execution requires an explicit stack model before it can be accepted.
All eight invalid variants clear published bindings and the graph. This detects
internal inconsistencies, not a malicious producer forging a consistent history.

All 28 regression tests passed. A fresh concurrency-16, two-batch failure run
also passed with 32 IPC jobs, 48 correctly attributed request events (16 failed
writes), and all 32 same-thread background writes unscoped. See
[integrity evidence](../experiments/mcp/evidence/persistent-worker-integrity.json).

### Dispatcher identity

The emitting server now prefixes its monotonically increasing bigint job counter
with a randomly generated dispatcher UUID. Job nodes preserve the observed sender
PID/TID and send marker source. This avoids ordinary counter reuse across dispatcher
instances; it is not sender authentication. A synthetic two-dispatcher trace checks
that identical local counters remain separate and bind to different requests.
A live single-dispatcher run with string RPC IDs and forged client metadata passed
all 128 request events, with 64 distinct job nodes carrying sender evidence and
25 background events separate. See [namespace evidence](../experiments/mcp/evidence/persistent-worker-namespace.json).
Actual concurrent multi-dispatcher integration remains untested.

### Negative-control isolation

Removed an experiment-specific analyzer exception that accepted a zero-context
IPC entry after a nonzero send in `worker-unscoped`. Every recorded handoff now
requires exact context equality regardless of scenario. The negative control
omits context/job fields and IPC lifecycle markers entirely, retaining only
zero-context worker execution markers. A regression verifies that changing the
scenario name cannot permit a mismatched entry.

Fresh concurrency-16, two-batch runs preserve the comparison: the unscoped
capture is valid with zero IPC jobs and 64 request events missing identity
(expected oracle failure); strict propagation yields 32 validated IPC jobs and
64/64 correctly attributed request events. All 29 regression tests pass.
[Strict-control evidence](../experiments/mcp/evidence/persistent-worker-strict-control.json)
contains both runs, including the intentionally failed oracle report.

### Abrupt worker death

`worker-crash` exits the child with status 23 immediately after a request write,
bypassing context cleanup. The server now remembers a terminal worker failure
and immediately rejects subsequent jobs instead of enqueueing them on a dead
pipe. At concurrency 8 across two batches, all 16 worker calls returned errors;
the longest took 0.396 seconds. Eight jobs had been sent before death.
The normal run records failure because tool errors are deliberately present.
Running attribution separately on that preserved capture reports `unfinished
IPC jobs` and publishes neither bindings nor a graph. See
[crash evidence](../experiments/mcp/evidence/persistent-worker-crash.json).

```bash
# Both commands are expected to exit nonzero.
python3.11 experiments/mcp/run.py --runtime node --mode replay --scenario worker-crash --instrumented --seccomp --concurrency 8 --pool-size 4 --batches 2 --output results/mcp/my-worker-crash
python3.11 experiments/mcp/attribute.py results/mcp/my-worker-crash
```

This validates conservative rejection and caller cleanup. It does not yet salvage
valid earlier jobs from a partially failed capture or support worker restart.

### Sender context consistency

The attributor now checks that an `IPC_SEND` context matches the context already
observed on the sender TID (including supported process inheritance). Matching
send/receive records alone previously allowed a different known request, or a
sender with no observed context, to claim a job. Both synthetic regressions first
reproduced this gap and now invalidate the capture. Trusted instrumentation is
still required: this is consistency validation, not authentication.

A fresh concurrency-32 two-batch run with string request IDs and forged client
metadata passed all 64 IPC jobs and all 128 request file events; 37 background
events remained unscoped. All 29 regression tests passed, including eleven invalid
IPC variants. See [sender evidence](../experiments/mcp/evidence/persistent-worker-sender.json).

### Querying the IPC evidence chain

The query traversal now includes `ipc_sent` edges. Previously the newly added
IPC graph was correct but a syscall explanation stopped at its job node, omitting
the originating request. A regression checks the request/job/syscall chain and
excludes unrelated requests. Against the saved sender-validation run, all 128
worker file-event explanations reached exactly their attributed request.
[Query evidence and example](../experiments/mcp/evidence/persistent-worker-query.json)
include the observed send and execution marker references. All 30 tests pass.

```bash
python3.11 experiments/mcp/query.py results/mcp/worker-sender-checked-c32 --request '"request-3"' --fixture-only
```

### Queued worker cancellation

`worker-cancel` uses one persistent worker thread and a gated predecessor so
alternate queued futures can be cancelled deterministically before execution.
The receiver emits `IPC_CANCEL` only after `Future.cancel()` succeeds. The analyzer
validates the sent identity, requires no prior execution/completion, closes the
job, and records a `cancelled_before_execution` edge. Entry after cancellation
and cancellation after entry invalidate capture in synthetic regressions.

At concurrency 32 across two batches, 32 jobs were cancelled with zero oracle
file events and no execution edges; the other 32 produced 64 correctly attributed
file events. All 34 background events remained unscoped. All 31 tests passed.
[Cancellation evidence](../experiments/mcp/evidence/persistent-worker-cancel.json)
contains the capture reports and graph checks.

```bash
python3.11 experiments/mcp/run.py --runtime node --mode replay --scenario worker-cancel --instrumented --seccomp --concurrency 32 --pool-size 4 --batches 2 --output results/mcp/my-worker-cancel
```

This is receiver-side queued-future cancellation, not an MCP cancellation
notification experiment. Cancellation races, already-running cancellation,
receiver authentication, and query display of requests with no syscalls remain
open. The graph contains cancellation records, but the current query starts from
syscalls and does not yet surface those records for an empty request.

### Cancellation query visibility

Request queries now retain the request, IPC jobs, and cancellation outcomes even
when the selected syscall list is empty. Event queries still follow only the
selected event's evidence. Against the saved cancellation run, all 32 cancelled
requests returned exactly their own request and one cancellation outcome. A CLI
query with `--request 4 --fixture-only` returned no fixture effects and the
explicit cancellation chain. [Query evidence](../experiments/mcp/evidence/persistent-worker-cancel-query.json)
records that example. All 32 regression tests passed. This resolves the query
visibility limitation above without treating absent syscalls as proof of cancellation.

### Consolidated worker regression matrix

All 18 fresh runs passed across `worker-context`, `worker-failure`, and
`worker-cancel`, concurrency 1/16/64, two repeats, and two batches per run.
Two captures ran concurrently. Underlying manifests, independent scores, causal
reports, and attribution/graph hashes were rechecked after completion.
Across the matrix, 1458 request file events were correctly
attributed, including 162 failed syscalls;
162 cancelled jobs had no expected file effects.
The analyzer validated 972 IPC jobs with
162 terminal cancellations. This is a controlled replay
matrix, not an additional real-LLM or kernel-only evaluation.
[Consolidated evidence](../experiments/mcp/evidence/persistent-worker-matrix.json)
retains per-run reports and source manifests.

```bash
python3.11 experiments/mcp/matrix.py --runtime node --scenarios worker-context,worker-failure,worker-cancel --concurrency 1,16,64 --pools 4 --repeats 2 --jobs 2 --batches 2 --seccomp --output results/mcp/my-worker-matrix
```

### Child processes launched by persistent worker jobs

`worker-spawn` has each IPC job launch a short-lived Python child that writes its
slot; the persistent worker reads the value back. A concurrency-16 two-batch run
correctly attributed all 64 request file events, but graph inspection showed the
child spawn edge skipped the IPC job. That edge now originates at the active IPC
job. A fresh run again passed all 64 file events, and all 32 child writes have a
queryable request → IPC job → child process → syscall chain with exactly the
correct request. All 32 regression tests passed.
[Spawn-chain evidence](../experiments/mcp/evidence/persistent-worker-spawn.json)
retains both runs and one full example chain.

```bash
python3.11 experiments/mcp/run.py --runtime node --mode replay --scenario worker-spawn --instrumented --seccomp --concurrency 16 --pool-size 4 --batches 2 --output results/mcp/my-worker-spawn
```

This covers one-shot children launched inside an established worker job; it does
not establish handoff into a second persistent worker or arbitrary nested IPC.

### Grandchild process ancestry

Spawn edges now preserve the active parent process when the spawning execution
itself inherited request context; they also preserve active async-work nodes.
The `worker-grandchild` scenario launches an intermediary Python child, which
launches the writer grandchild. At concurrency 8 across two batches, all 32
request file events were correctly attributed. Each of the 16 grandchild writes
has exactly one request, one IPC job, and both intervening process nodes in its
query chain. All 32 regression tests passed. See
[grandchild evidence](../experiments/mcp/evidence/persistent-worker-grandchild.json).

```bash
python3.11 experiments/mcp/run.py --runtime node --mode replay --scenario worker-grandchild --instrumented --seccomp --concurrency 8 --pool-size 4 --batches 2 --output results/mcp/my-worker-grandchild
```

These remain short-lived process trees; PID reuse and reparented long-lived
service dispatch are outside the evidence provided by this run.

The process-chain behavior also has a synthetic regression in `test_ipc.py`:
an IPC worker clones a child, that child clones a grandchild, and the grandchild
writes while inheriting the request. The test verifies both request attribution
and the exact IPC-job → child → grandchild edges, plus the worker's unscoped
post-job effect. All 33 regression tests pass after adding this case.

### Marker write integrity

Marker decoding now requires the captured write's requested byte count and return
value to equal the complete decoded payload length. Previously marker JSON/TID
and log agreement were checked without independently checking syscall success.
Synthetic failed and short marker writes now invalidate capture even with a
matching separate log record. All 33 tests pass. A fresh concurrency-16 two-batch
worker run also passes with 64 correctly attributed request events and 39
background events separate. [Integrity evidence](../experiments/mcp/evidence/marker-write-integrity.json)
records the run. This checks captured marker consistency; it is not authentication
of the marker producer.

### Shared connection across multiple batches

Marker-integrity regressions passed Node and Tokio slots, spawn, and joined-batch
workloads (six cases). A seventh, Node shared inbound networking with two batches,
exposed a harness bug: each batch opened a new socket while the server retained
the first socket. The harness now reuses one socket across all batches.

That repair exposed a real attribution gap: the second inbound read retained
only the first batch's previously observed owners. The final lifecycle pass now
refreshes ambiguous and lifecycle-derived reads from the full connection history,
and removes stale singleton execution edges. The fresh two-batch run covers all
18 payload events, with 16 exact writes and two ambiguous reads. There are 16
extra candidate edges: both reads conservatively include all 16 calls. This is
candidate coverage, not exact message attribution. All 33 tests pass; the socket
reuse regression now expects earlier lifecycle singletons to become ambiguous
when the same connection later has additional owners.
[Evidence](../experiments/mcp/evidence/shared-network-multibatch.json) preserves
both failed runs and the successful repair, plus the cross-runtime matrix.

A follow-up with concurrency 1 across three batches validates the singleton-to-
shared transition on one live connection. All six payload events were covered:
three writes exact, three reads ambiguous with all three requests as candidates
(six extra candidate edges). Each read query reaches all three candidates and
has no stale singleton execution edge. See [singleton-reuse evidence](../experiments/mcp/evidence/shared-network-singleton-reuse.json).

### Socket annotation parsing

The FD annotation parser previously ended at the first `>` and truncated TCP
endpoint arrows. It now recognizes bracketed socket annotations through their
closing delimiter, including nested IPv6 address brackets. A regression checks
IPv4 and IPv6 and keeps payload text out of paths. All 34 tests passed. A fresh
shared-network run preserved complete TCP endpoint annotations and covered all
six payload events (four exact writes, two ambiguous reads, four extra candidate
edges). [Annotation evidence](../experiments/mcp/evidence/socket-annotation.json)
records the parsed endpoint text and reports. Descriptor identity still comes
from lifecycle tracking, not the endpoint string.

### Message-syscall resource annotations

`sendto`, `recvfrom`, `sendmsg`, and `recvmsg` now preserve the first FD's annotation;
`dup2` also joins the existing descriptor-operation parser set. Resource graph
edges classify successful message receives/sends as reads/writes rather than
generic references. A live standalone Python socketpair probe captured all four
message syscalls. This host's strace emitted `(null):[inode->inode]` annotations;
the parser now retains them intact without inventing a protocol name or treating
path-like payload text as a resource. All 35 tests pass.
[Probe evidence](../experiments/mcp/evidence/socket-message-annotations.json)
includes source, raw-trace hashes, and parsed events. This does not establish
socketpair endpoint lifecycle attribution or SCM_RIGHTS descriptor transfer.

### MCP worker socketpair messages

`worker-socketpair` creates a socketpair inside each instrumented job, sends and
receives a slot-labelled message with `sendmsg`/`recvmsg`, then performs the usual
file write/read. At concurrency 32 across two batches, the independent oracle
verified all 128 message syscalls and 128 file events against their requests.
The graph contains 128 corresponding message read/write resource edges. All 35
tests pass. [Evidence](../experiments/mcp/evidence/persistent-worker-socketpair.json)
also preserves the initial failed run: a workload variable overwrote job metadata,
preventing completion records and triggering the client timeout. The corrected
workload keeps socket payload and job metadata separate.

```bash
python3.11 experiments/mcp/run.py --runtime node --mode replay --scenario worker-socketpair --instrumented --seccomp --concurrency 32 --pool-size 4 --batches 2 --output results/mcp/my-worker-socketpair
```

These messages are attributed through the executing IPC job, not socketpair
lifecycle inference. Shared endpoints across requests, message causality across
processes, and SCM_RIGHTS remain untested. Unhandled worker-future exceptions
outside the job's catch block currently rely on the client timeout; prompt fatal
error reporting remains a harness improvement to make.

### Prompt reporting of unexpected worker-task failures

Each submitted worker future now has a completion callback that detects uncaught
exceptions, emits a bounded stderr diagnostic, and terminates the worker with
status 24. The existing server failure handler rejects pending and future calls.
This covers exceptions outside the ordinary job catch block, including failed
cleanup; it does not manufacture a successful provenance exit marker.

`worker-fatal` injects an exception during cleanup before `IPC_LEAVE`. In a live
concurrency-8, two-batch experiment, all 16 calls returned errors within 0.72
seconds. The attributor reports unfinished IPC jobs and clears both published
outputs. Normal worker and queued-cancellation regression runs passed, as did all
35 tests. [Evidence](../experiments/mcp/evidence/persistent-worker-fatal.json)
includes the failed capture and successful regression runs. This resolves the
60-second timeout limitation observed during initial socketpair development.

```bash
# Expected failed run, followed by expected attribution rejection.
python3.11 experiments/mcp/run.py --runtime node --mode replay --scenario worker-fatal --instrumented --seccomp --concurrency 8 --pool-size 4 --batches 2 --output results/mcp/my-worker-fatal
python3.11 experiments/mcp/attribute.py results/mcp/my-worker-fatal
```

### Two persistent workers in a relay

`worker-relay` starts a second Python worker at startup. Each first-stage job
forwards its internal request context with a fresh dispatcher-namespaced job ID;
a separate response reader resolves waiting jobs. The second worker writes and
reads the slot, and the first worker verifies it with another read. Both workers
reuse four execution threads across calls. IPC send edges now originate at the
active parent job when dispatch happens inside an IPC execution bracket.

At concurrency 16 over two batches, all 96 request file events were correct.
At concurrency 64 over two batches with string RPC IDs and forged client context
metadata, all 384 events were correct. Every downstream write (32 and 128,
respectively) has exactly one correct request and both IPC job nodes in its
query chain. All 36 tests pass, including a synthetic parent-job regression.
[Relay evidence](../experiments/mcp/evidence/persistent-worker-relay.json) retains
both runs and their independently scored results.

```bash
python3.11 experiments/mcp/run.py --runtime node --mode replay --scenario worker-relay --instrumented --seccomp --concurrency 64 --pool-size 4 --batches 2 --string-ids --spoof-context --output results/mcp/my-worker-relay
```

This covers cooperative cross-process relay on one host. Nested execution on the
same thread, worker restart, cancellation propagation across the relay, and
byte-level IPC message causality remain separate gaps.

A downstream cleanup-failure variant (`worker-relay-fatal`) also ran at
concurrency 8 across two batches. All 16 calls returned errors, including calls
submitted after downstream death; the maximum observed latency was 1.291
seconds. Attribution rejected unfinished downstream IPC jobs and published no
bindings or graph. [Relay failure evidence](../experiments/mcp/evidence/persistent-worker-relay-fatal.json)
preserves the failed capture and separate attribution rejection. All 36 tests
passed after the relay additions. Recovery/restart and cancellation across stages
remain unimplemented.

### Internal identities for worker replies

Both server-to-worker and relay response routing now use the internal job ID;
slot values are checked separately for consistency. Even the unscoped negative
control carries a transport job ID, but still carries no request context and
emits no IPC lifecycle records. Normal, queued-cancellation, and relay runs at
concurrency 16 across two batches passed after this change, as did all 36 tests.

`worker-wrong-response` deliberately returns unknown job IDs. All 16 calls in a
two-batch concurrency-8 run failed with an unexpected-response error. The initial
eight jobs had already executed, however: separate attribution analysis is valid
and retains their 16 file effects. The overall experiment manifest remains failed
because MCP tool responses failed. This demonstrates why a tool error must not
be interpreted as proof of no kernel effects. [Response identity evidence](../experiments/mcp/evidence/worker-response-identities.json)
retains the failed run and successful regressions. The standard query still
requires a complete experiment manifest; inspecting valid captures of failed
workloads currently requires direct artifact inspection.

### Querying effects of failed workloads

`query.py --allow-failed-workload` now permits a terminal failed workload when its
attribution report remains valid and both published artifacts match their hashes.
Failed independent oracle checks still block the query. Output explicitly carries
`workload_status`, `workload_error`, and `attribution_valid`. Running this against
the wrong-response experiment exposes request 3's two file effects despite its
MCP error. The same flag rejects the relay crash's incomplete capture. CLI
regressions also reject changed output, missing hashes, and failed oracle scores.
[Query evidence](../experiments/mcp/evidence/failed-workload-query.json) contains
the failed-workload example and invalid-capture rejection.

```bash
python3.11 experiments/mcp/query.py results/mcp/worker-wrong-response-c8 --request 3 --fixture-only --allow-failed-workload
```

### Marker schema validation

Marker decoding now requires an object with integer version, TID, request,
operation, pointer, and status fields; identity counters must fit unsigned 64-bit
ranges. Unknown marker kinds and duplicate JSON fields are rejected. This avoids
Python's boolean/integer and float/integer equality silently accepting malformed
context identities, and avoids ignoring an unknown transition. All 38 tests
passed. Fresh Node relay and Tokio slot runs passed with 48 and 96 correctly
attributed request events respectively. [Schema evidence](../experiments/mcp/evidence/marker-schema.json)
retains both captures' reports. The schema remains a consistency boundary for
trusted producers, not an authentication mechanism.

### Request-map and join schema

Mapping records now reject duplicate JSON fields, duplicate/out-of-range context
IDs, and join parents that are non-integers, repeated, or not previously defined.
This prevents boolean and floating-point parents from aliasing integer contexts.
Malformed mappings invalidate output before inference. All 39 tests pass. A fresh
concurrency-16 two-batch joined workload preserved all 32 expected parent edges
with no false or missing parents across its two aggregate writes. See
[mapping evidence](../experiments/mcp/evidence/mapping-schema.json).

### Fresh real-agent validation after worker and schema changes

A new Codex LLM-agent run used the official filesystem MCP server to read two
fixtures, write a summary, and read the summary back. All four tool calls
completed without errors. The analyzer bound all 16 selected filesystem events;
the independent unique-path oracle confirmed all eight events it could label.
The summary path is reused across write/read calls, so those effects are not
independently labelled by this oracle. The PID baseline left all 16 events
ambiguous; request-window correlation left the eight uniquely labelled events
ambiguous too. A blocked syscall interrupted at shutdown was recorded as one
`terminal_interrupted` event, with raw trace retained.
[Real-agent evidence](../experiments/mcp/evidence/agent-post-worker-and-schema.json)
contains tool-call details, reports, source manifest, and agent-log hash.
This validates the current filesystem-agent path; the persistent-worker studies
remain controlled MCP replay rather than LLM-directed worker experiments.

### Real-agent relay exposed worker initialization and shutdown regressions

The first real LLM-directed relay experiment (`agent-worker-relay`) failed because
current `persistent_worker.py` did not initialize its file and marker descriptors.
Inspection also found an undefined slot-width constant inside the separately
executed child program. Both are repaired. A process-level regression test now
executes ordinary, child, grandchild, and relay workers and checks payloads and
balanced IPC markers. All 40 tests pass. Six fresh traced replay cases (ordinary,
cancel, failure, child, grandchild, relay; concurrency 8, two batches) pass their
independent oracles.

The second agent run (`agent-worker-relay-fixed`) completed four worker calls and
the barrier without tool errors, but attribution correctly rejected the entire
capture: one background libuv operation lacked completion. Its twelve selected
worker effects are therefore **not a valid attribution result**. The experiment's
terminal barrier now stops the periodic background producer before draining its
work; this does not relax incomplete-capture rejection. A further real-agent run
is being evaluated. Failed-run logs, source snapshots, and replay reports are
preserved in [regression evidence](../experiments/mcp/evidence/worker-initialization-regression.json).

The drained run (`agent-worker-relay-drained`) passed capture integrity and the
independent offset oracle: 12/12 request file effects correct, 661/661 background
effects correctly unassigned, eight completed IPC jobs. Each of the four leaf
writes has a queryable chain containing exactly one MCP request and two IPC jobs.
The actual LLM calls did **not** overlap; concurrency evidence remains supplied
by replay. This advances the persistent-worker path from replay-only to actual
LLM-directed MCP validation. See [agent relay evidence](../experiments/mcp/evidence/agent-worker-relay.json).

### Terminal-barrier regression matrix

All 28 captures passed across seven worker scenarios, concurrency 1 and 32, two
repeats, and two batches. Independent oracles confirmed 1,782 request file effects
and 7,655 background effects; additionally 264 socket-message events passed their
token oracle. There were 66 queued cancellations and 66 expected failed syscalls.
Every attribution output hash was revalidated after the matrix completed.
[Matrix evidence](../experiments/mcp/evidence/worker-terminal-barrier-matrix.json)
contains individual reports and source manifests. All 41 tests pass, including
process-level worker execution and agent-validation rejection cases.

### Descriptor transfer baseline: SCM_RIGHTS

A new standalone kernel probe opens a file **after** forking, sends its descriptor
through an AF_UNIX datagram socket with `SCM_RIGHTS`, and has the receiver write
and read through its newly received descriptor. Opening after fork rules out
inherited access to that descriptor. The capture confirms four selected events:
`sendmsg`, `recvmsg`, `pwrite64`, `pread64`; file content checks pass.

The parser correctly assigns only the socket as the resource accessed by
send/receive, avoiding a false claim that sending a descriptor writes file data.
However, the passed descriptor appears only in raw ancillary arguments. There is
no structured transfer edge or open-file-description identity in current output.
Also, this blocking `recvmsg` starts before the sender's `sendmsg`; entry timestamp
ordering is insufficient for transfer pairing. A future implementation needs
completion-aware lifecycle handling and must avoid identifying a transfer solely
by pathname or descriptor number. This is a standalone gap demonstration, not a
new MCP attribution success. [Probe evidence](../experiments/mcp/evidence/scm-rights-probe.json)
retains selected parsed events, source, parser quality, and raw trace hashes.

The parser now retains `duration_ns` from strace `-T` and `completion_ns` as entry
wall timestamp plus elapsed duration, at capture precision. Missing durations and
unknown/restarted returns have no asserted completion time. Existing attribution
ordering is unchanged: this metadata is groundwork, not a transfer matcher. A
regression test covers a resumed blocking receive, untimed calls, and restart
returns; all 42 tests pass. Re-parsing the real probe confirms send entry falls
inside the receive interval. See [completion evidence](../experiments/mcp/evidence/scm-rights-completion-times.json).

Ancillary decoding now preserves local `SCM_RIGHTS` descriptor numbers, direction,
syscall success, decode completeness, and control truncation as structured event
metadata. It strips payload strings and FD annotations before decoding control
syntax; tests reject control-looking payloads and flag incomplete descriptor
lists. Failed send attempts are explicitly unsuccessful observations. The real
probe decodes sender FD 4 and receiver FD 3. No send/receive pairing or request
ownership is inferred from these numbers. [Decoding evidence](../experiments/mcp/evidence/scm-rights-decoding.json)
records this incremental result. Timing and ancillary metadata also accompany
syscall graph nodes. All 44 tests pass.

Fresh replay validation after timing metadata passed 96/96 relay file effects and
286 background effects. After ancillary metadata was added, a fresh socketpair
MCP run passed 64 file effects, 64 socket-message effects, and 126 background
effects. Output hashes were rechecked. [Regression reports](../experiments/mcp/evidence/completion-ancillary-regression.json)
retain source manifests for both versions. Descriptor-transfer pairing remains
unimplemented; the next experiment should carry per-job descriptors across the
persistent-worker boundary, separating explicit request propagation from resource
transfer provenance.

### MCP jobs carrying SCM_RIGHTS descriptors to persistent workers

`worker-rights` extends the controlled relay: each downstream job travels as a
Unix datagram with one file descriptor. The receiving persistent process never
opens `slots.bin`; its worker uses and closes the per-job descriptor. Internal
job context travels with the dispatch, independently of file offsets. The normal
attributor does not decode workload JSON payloads for ownership.

The first concurrency-16, two-batch capture passed 96 request file effects and
243 background effects, with 64 completed IPC jobs. A new independent descriptor
oracle confirms 32 successful cross-process transfers, 64 receiver file effects
using the observed received descriptors, and zero receiver opens of the target.
It checks that effects follow receive completion and that sender attribution
matches the independently known slot request. Receiver `recvmsg` itself occurs on
an unscoped dispatcher; this is not claimed to have request ownership.

[Baseline evidence](../experiments/mcp/evidence/worker-rights-baseline.json)
preserves reports. This establishes request attribution across descriptor
handoffs using explicit context propagation, **not** general resource-transfer
provenance. The graph still lacks paired send/receive descriptor-transfer edges.
The new oracle is integrated into the harness, matrix reports, and query gates;
negative tests reject missing observations, wrong descriptors/owners, premature
effects, and independent target opens. All 45 tests pass.

The follow-up descriptor matrix passed all four cases (concurrency 1 and 32,
two repeats, two batches): 132 transfers and 264 receiver file effects. A further
concurrency-64 run with string request IDs and spoofed client context passed 128
transfers, 256 receiver file effects, and all 384 total request file effects;
the receiver again had zero opens of the target. No capture used client context
as identity authority. [Matrix evidence](../experiments/mcp/evidence/worker-rights-matrix.json)
contains individual reports and source manifests; matrix output hashes were
revalidated.

### Conservative kernel-observed descriptor-transfer provenance

A new matcher pairs descriptor sends/receives on observed AF_UNIX SOCK_DGRAM
socketpairs using endpoints, ordered complete message sequences, syscall intervals,
and ancillary descriptor lists. It never reads workload JSON, slots, or payload
identities. Linux documents Unix datagrams as reliable and ordered, and SCM_RIGHTS
as transfer of an open-file-description reference: [unix(7)](https://man7.org/linux/man-pages/man7/unix.7.html).

The matcher rejects whole channels when observed message calls overlap, lack
completion times, have unequal counts/lengths, truncate/peek, reuse endpoint
identities, or use unsupported reconfiguration/message operations. This is scoped
to complete observed channels in the traced process tree; it does not establish
absence of untraced participants or io_uring traffic. Stream ancillary boundaries
and general descriptor-table/OFD lifetime tracking remain unresolved.

A fresh concurrency-32 capture produced 64 transfer nodes and 192 correct request
file effects. The independent payload oracle then verified all 64 inferred
send/receive/descriptor pairs. Receive-event queries expose the sender's request
ancestry through transfer edges while retaining an empty request assignment for
the unscoped receiving dispatcher. All 64 queries were checked. Transfer edges
express resource handoff, not execution ownership or subsequent file dataflow.
[Evidence](../experiments/mcp/evidence/descriptor-provenance-c32.json) preserves
reports and query checks. The scorer was strengthened after capture; its current
hash is recorded separately from the capture snapshot. All 48 tests pass.

The four-case transfer-provenance matrix (concurrency 1 and 32, two repeats,
two batches) passed all 132 inferred pairs and 264 receiver file effects. Output
hashes were revalidated. A negative control removed one successful send from the
parsed events of the 64-transfer capture, leaving raw evidence unchanged. The
matcher rejected the entire channel, emitted zero pairs, and retained 127
unpaired ancillary observations. Reports now explicitly list unpaired successful
observations, including unsupported channel types, so missing coverage is visible.
[Matrix and negative-control evidence](../experiments/mcp/evidence/descriptor-provenance-matrix.json)
records reports, mutation, and matcher hash. The unpaired-observation report field
was added after these captures; the negative-control record identifies that newer
matcher separately.

### Descriptor observability audit: important scope correction

Adversarial tests exposed two ways the earlier matcher could overlook channel
activity: a socket in a secondary syscall operand (such as splice's output), and
a socket annotation containing only the local inode without its peer. Both now
reject affected channels. Reused endpoint inodes across channel identities,
ancillary export of channel endpoints, and observed io_uring activity also reject
pairing. Payload text cannot forge those structural observations. All 53 tests
pass.

The earlier descriptor captures contain successful `io_uring_setup` and
`io_uring_enter` calls. Their independently checked pairs remain historical
experimental results, but they do **not** establish complete channel observability
under the stricter matcher. Re-evaluation now emits zero transfer pairs for those
captures. Request attribution of observed effects remains separately evaluated;
this does not claim visibility into ring submissions.

`UV_USE_IO_URING=0` did not eliminate rings on this host's Node/libuv 1.52.1; the
failed control `rights-no-uring-c16` is preserved. The current experimental
`--disable-io-uring` flag instead injects ENOSYS at `io_uring_setup` through strace,
with the intervention recorded in the manifest and exact trace command. This is
an intentionally constrained baseline, not support for io_uring attribution.
A fresh constrained concurrency-16 capture verified all 32 transfer pairs and 96
request file effects. Its only ring calls were failed setup attempts; no
successful setup or enter calls were observed. New causal reports explicitly
count ring setup/enter calls and state that submissions are not decoded.
[Audit evidence](../experiments/mcp/evidence/descriptor-observation-audit.json)
retains original reports, ring events, and results under the stricter matcher.

The stricter matcher then passed two fresh constrained cases (concurrency 1 and
32, two batches): 66 transfer pairs and 132 receiver effects, all independently
verified. Both reports show zero successful ring setups and zero enter calls;
output hashes were revalidated. [Constrained matrix evidence](../experiments/mcp/evidence/rights-denied-uring-matrix.json)
records the injected baseline explicitly. This does not close the io_uring gap.

### io_uring: demonstrated effects absent from the syscall list

`io_uring_probe.c` uses the kernel API directly (no liburing dependency), submits
two seven-byte writes at offsets 0 and 128, and an invalid-FD read, in one batch.
The full strace capture shows setup and one `io_uring_enter` returning three;
it contains **zero direct write/pwrite syscalls to the target file**. Independent
file-content checks nevertheless confirm both writes. The application reads three
CQEs: failure `user_data=103, result=-EBADF` arrives before successes 101 and 102,
although submission order was 101, 102, 103. Four repeat captures reproduced this.

This is a concrete completeness gap, not merely missing request labels: the
logical kernel I/O operations do not appear as corresponding file-write syscalls
in this collector. Linux describes the submission/completion queues and warns
that completion order need not equal submission order: [io_uring(7)](https://man7.org/linux/man-pages/man7/io_uring.7.html).

A small `ring_observations.py` adapter now joins trusted SQE/CQE observations by
opaque operation ID. It rejects duplicate/missing identities, unsupported opcodes
or flags, impossible byte counts, and incomplete completions. The prototype
supports one ring instance, unique IDs for its captured lifetime, and single-shot
READ/WRITE only. `inspect_ring_probe.py` corroborates the runtime observations
against their exact traced write bytes, checks the kernel submission count, and
independently validates final file contents. Failure invalidates its report.
These are **trusted runtime observations**, not strace decoding of shared ring
memory. No kernel worker TID or MCP request attribution is claimed yet.

[Repeat evidence](../experiments/mcp/evidence/io-uring-gap.json) includes source,
binary/adapter/inspector hashes, raw trace hashes, exact commands, reports, and
out-of-order completion results. All 55 tests pass. The next integration must
carry MCP identity into each submitted ring operation and retain per-operation
completion evidence without inventing a corresponding write syscall.
