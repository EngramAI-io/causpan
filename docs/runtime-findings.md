# Runtime attribution: experimental results

The prototype now connects MCP request identities to captured Linux syscalls through
runtime execution context. It has been exercised with a real Codex agent
(`codex-cli 0.160.1`, model `gpt-6-astra`, reasoning effort `low`,
configured in `~/.codex/config.toml`) and the
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

### MCP request identity linked to individual ring operations

The controlled `uring_slot` MCP tool now starts one hashed C helper per request.
Each helper creates one ring and submits two writes plus an intentionally invalid
read to the shared `slots.bin`, at independently assigned fixture offsets. The
existing runtime/process bridge supplies request identity; the ring adapter does
not inspect tool arguments or derive ownership from file offsets.

The adapter corroborates helper observations against complete traced stdout
writes, validates submission/completion identity and timing around `io_uring_enter`,
checks the kernel submission count, and requires consistent inherited request
context. Provenance uses separate `ring_operation` nodes with submission and
completion evidence edges. It does not fabricate corresponding write syscalls.
`kernel_worker_tid` remains unknown. The helper build hash is checked against the
run configuration; missing, malformed, or inconsistent evidence invalidates capture.

A concurrency-8 two-batch run attributed 48 operations to 16 MCP calls: 32 writes
and 16 expected failed reads. Each of the 16 request queries exposed exactly its
three ring operations and one request ancestor. [Initial evidence](../experiments/mcp/evidence/mcp-ring-c8.json)
contains reports and query checks. The independent oracle checks operation offsets,
owners, completion results, and file contents after inference.

The four-case replay matrix (concurrency 1 and 16, two repeats, two batches) passed
204 operations across 68 calls: 136 writes and 68 expected failed reads. A further
concurrency-32 run with string request IDs and spoofed client context passed all
192 operations across 64 calls. [Matrix evidence](../experiments/mcp/evidence/mcp-ring-matrix.json)
preserves reports and source manifests; output hashes were revalidated.
All 56 tests pass, including malformed helper evidence and context/timing failures.

This remains a trusted one-request/one-helper/one-ring adapter. It does not yet
support requests sharing one ring, reused user_data, multishot requests, SQPOLL,
registered resources, or decoding the unrelated Node/libuv ring traffic. The
kernel-side completeness gap remains visible rather than being declared solved.

### Actual LLM agent invokes the ring workload

The actual Codex LLM agent completed four `uring_slot` calls and a final barrier,
using MCP without shell operations. The run passed capture validation and the
independent oracle: 12 attributed ring operations, eight successful writes, and
four expected invalid-FD reads. Each request query exposes exactly its three ring
operations. The tool calls did not overlap; replay supplies concurrency coverage.
[Agent evidence](../experiments/mcp/evidence/agent-ring.json) retains call intervals,
query checks, transcript hash, reports, and source manifest. This confirms the
real-agent path for the scoped helper adapter; it does not extend its runtime or
kernel observability guarantees.

### Multiple MCP requests share one persistent io_uring

`uring-shared` starts a C worker before any request and keeps one ring open across
batches. The server sends internal IPC job identities and contexts separately
from workload slots. Under each verified IPC preparation context, the worker
records three SQEs; it then leaves that context. One context-free
`io_uring_enter` submits the entire batch. CQEs are recorded by the unscoped
completion dispatcher and joined by operation identity, not completion order.
IPC brackets describe the preparation task, not the lifetime of the async I/O.

The first concurrency-8 run passed 48 operations across 16 requests. Each of its
two batch syscalls submitted 24 operations belonging to eight requests, while the
syscall itself retained no single execution owner. Every request query exposed
only its own three operations and its own request ancestor, despite sharing the
batch syscall. [Initial shared-ring evidence](../experiments/mcp/evidence/shared-ring-c8.json)
contains these checks and reports.

The adapter verifies a single observed worker/ring, build identity, exact sidecar
bytes against traced writes, unique per-SQE IPC ownership, per-batch kernel
submission counts, SQE/CQE timing, and absence of context leakage on batch enter
and completion dispatch. It still trusts the cooperating runtime's SQE/CQE
observations; no kernel worker identity is claimed. Queue IDs are unique for the
captured ring lifetime. Fixed batch width is an experimental coordination rule;
partial batches at EOF fail, and arbitrary arrivals, cancellation, SQPOLL,
registered resources, multishot operations, and unrelated runtime rings remain
outside this adapter. All 57 tests pass, including malformed shared-ring evidence.

The six-case shared-ring matrix (concurrency 1, 16, 64; two repeats; three batches)
passed 1,458 operations across 486 requests: 972 writes and 486 expected failed
reads. A separate concurrency-32, three-batch run with string request IDs and
spoofed client context passed all 288 operations. [Matrix evidence](../experiments/mcp/evidence/shared-ring-matrix.json)
contains reports and manifests; matrix output hashes were revalidated.

A maximum-width run (128 requests per batch, four batches) passed 1,536 operations
across 512 requests. Captured setup parameters show 512 SQ entries and 1,024 CQ
entries, so both queues wrapped during the run. All 1,536 operation IDs were
unique. Each of the four batch syscalls submitted 384 operations owned by 128
requests, without gaining a single execution owner. All 1,024 writes and 512
expected failed reads passed the independent oracle. [Wraparound evidence](../experiments/mcp/evidence/shared-ring-wraparound.json)
records queue sizes, batch checks, reports, and source manifest.

### Shared-ring batch-boundary audit and conditional baselines

The adapter now requires each batch's SQE preparation to follow observed ring
setup and the preceding batch's completed CQE observations. Missing CQE timing
or overlapping preparation is rejected. A fresh concurrency-16, three-batch run
passed all 144 operations after this tightening. Negative tests cover inter-batch
overlap and untimed completion observations; all 58 tests pass.

`ring_baselines.py` measures ownership **given the already enumerated ring
operations and their associated enter syscall**. It does not pretend a syscall-
only collector discovers those operations. For the fresh 48-request run, the
worker-lifetime PID candidate set contains 48 requests for every operation;
request-window correlation narrows that to 16. Both cover the correct owner but
leave all 144 operations ambiguous, with respectively 6,768 and 2,160 extra
candidate edges. The context adapter assigns all 144 correctly under its trust
assumptions. A sequential three-request control yields nine exact request-window
assignments, demonstrating when that weaker baseline is sufficient.
[Baseline evidence](../experiments/mcp/evidence/shared-ring-baselines.json) preserves
both reports, manifests, and the baseline scorer hash. These are internal
conditional baselines, not measured results for CamFlow or other external systems.

### Ring resource observations and first-class operation queries

The query audit found that `--fixture-only` could hide shared-ring effects:
context-bearing SQE/CQE witness writes target a sidecar outside the fixture,
while the actual writes have no corresponding file-write syscalls. Ring nodes
now carry a conservative pathname projection from a preceding observed absolute
open in the scoped single-threaded helper. Descriptor close/replacement or
unsupported installation loses the projection; invalid descriptors remain
explicitly unresolvable. This is an observed opening pathname, **not** inode/OFD
identity, rename tracking, or a file-content dependency claim.

`ring_resource_observed` edges retain the source open syscall. Request queries
select ring operations separately from syscall events, including when filtering
by fixture path. `--operation FULL_NODE_ID` inspects a ring operation directly;
unknown IDs fail. Results expose a separate `ring_operations` array and a count
of operations omitted by the fixture filter, rather than silently losing them.
The failed invalid-FD reads have no fixture path and remain accessible directly.

Two fresh cases (per-request helper and persistent shared ring, concurrency 4,
two batches each) passed 48 total ring operations. All 16 request fixture queries
returned exactly two writes, explicitly omitted one invalid-FD read, and retained
the corresponding open evidence. Direct failed-operation queries also passed.
[Query evidence](../experiments/mcp/evidence/ring-resource-queries.json) contains
reports, checks, and query hash; output hashes were revalidated. All 60 tests
pass, including descriptor replacement/reuse and CLI operation selection.

### Descriptor reuse between ring preparation and submission

The new `uring-reuse` scenario prepares SQEs using the descriptor for `slots.bin`,
then closes it and opens `replacement.bin` on the same descriptor before submitting.
In the concurrency-8, two-batch capture, all 32 writes affected the replacement
file; resolving resources when preparing the SQE would have retained the wrong
opening pathname. The adapters now resolve ordinary descriptors at the observed
submission boundary. All 48 operations retained the correct request owners,
including 16 expected invalid-descriptor read failures.
[Reuse evidence](../experiments/mcp/evidence/ring-fd-reuse.json) preserves the
per-operation preparation-versus-submission comparison.

Both ring adapters also require a full submission and a full waiting GETEVENTS
enter; partial submissions, partial waits, and unsupported enter flags fail
closed. This boundary is justified only for the controlled single-threaded
helpers, without SQPOLL, fixed-file registration, or concurrent descriptor-table
mutation. It is not a general kernel file-reference acquisition observation.

A fresh three-scenario regression matrix (per-request, shared, and descriptor
reuse; concurrency 4, two batches) passed all 72 operations across 24 requests:
48 successful writes and 24 expected failed reads. Output hashes were revalidated
before preserving [matrix evidence](../experiments/mcp/evidence/ring-submission-resource-matrix.json).
All 62 unit tests passed, including descriptor reuse and rejected partial enters.

The follow-up resource audit also found that a descriptor-mutating syscall with
an unavailable return value could leave an earlier open projection intact.
Unknown results now invalidate that projection instead of being treated like
failed calls. Regression cases cover `dup2`, `close_range`, `recvmsg`, and `openat`;
all 63 tests pass. This is a conservative evidence-loss rule, not a claim that
those syscalls succeeded.

### Explicit enforcement of the ring helper execution contract

The adapter audit found that rejecting unsupported enter flags did not also
verify setup flags. Both adapters now require explicitly observed zero setup
flags and reject successful or unresolved process creation and ring registration
inside the helper. This prevents accepting an observed SQPOLL or expanded
process/registration scope under assumptions made for a single-threaded ordinary
ring. Failed calls do not imply a scope change. These checks strengthen the
trusted-helper contract; they do not establish immunity to hidden activity or
replace kernel memory observation.

A fresh concurrency-8, two-batch matrix across per-request, shared, and reuse
scenarios passed 144 operations from 48 requests: 96 successful writes and 48
expected failures. [Evidence](../experiments/mcp/evidence/ring-scope-validation.json)
preserves reports and source identities, with output hashes revalidated. All 64
unit tests pass, including top-level setup-flag parsing and unknown-result scope
changes.

### Sparse arrivals in the shared-ring worker

`--ring-idle-ms N` enables partial batch flushing after N milliseconds without
another ready job. Zero retains the fixed-batch control. The worker disables
stdio read-ahead so polling sees the next complete dispatcher line; this is a
trusted newline-delimited protocol, not a timeout guarantee for malformed or
partially delivered lines. Each flushed batch still drains before the next.

A direct process check sent three sequential jobs to a width-eight worker,
waiting for each response before sending the next. All three partial batches
completed (nine operations), with expected file bytes. A full MCP capture with
width eight, two batches and a 10 ms idle interval passed all 48 operations from
16 requests. [Capture evidence](../experiments/mcp/evidence/shared-ring-idle.json)
preserves reports and source hashes. All 64 existing tests pass. Real-agent sparse
arrival coverage is the next step; the direct check alone does not establish it.

### Actual LLM agent with sparse shared-ring requests

The agent harness now accepts `uring-shared` with a positive idle-flush interval
and validates the ring's output bytes in addition to exactly four unique worker
calls and a final barrier. An actual agent run with batch capacity eight and a
10 ms idle interval completed four calls, producing four partial batches and 12
correctly attributed operations (eight writes and four expected failed reads).
All four request queries returned exactly their own three operations. Output
hashes were revalidated; [agent evidence](../experiments/mcp/evidence/agent-shared-ring.json)
preserves reports, query checks, batch membership, and the agent-log hash.

The agent's final text claimed concurrency, but protocol request/response
intervals show **zero overlapping pairs**. This run proves sparse sequential
agent requests through a persistent ring, not concurrent agent issuance. The
replay captures remain the concurrency evidence. There were no shell commands
or calls to other servers. All 65 tests pass, including shared-ring agent output
and duplicate-call validation.

### Measured staggered arrivals and variable ring batches

Shared-ring replay now supports `--request-stagger-ms`, recorded in the manifest.
Two fresh width-eight, two-wave captures with a 10 ms idle flush passed all 96
operations across 32 requests. Scheduling delays are experimental inputs, not
claims about actual concurrency. The evidence gives:

| Arrival spacing | Overlapping request pairs | Peak active requests | Requests per observed batch |
|---|---:|---:|---|
| 50 ms | 28 | 5 | 1, 1, 1, 1, 1, 2, 1, 2, 1, 5 |
| 2 ms | 56 | 8 | 2, 6, 8 |
| Actual agent | 0 | 1 | 1, 1, 1, 1 |

`ring_arrivals.py` computes these values from protocol monotonic intervals and
validated graph batches, requiring complete runs, passing independent scores,
and matching output digests. The 50 ms result shows that spacing greater than
the idle timeout does not guarantee single-request batches: queued arrivals and
capture/runtime scheduling affect what the worker observes. No simultaneous
kernel execution claim follows from overlapping MCP intervals.
[Arrival evidence](../experiments/mcp/evidence/ring-arrivals.json) preserves the
reports, manifests, and reporter hash. Both replay cases retain exact ownership
through irregular batch sizes.

### External ring-memory collection: host restriction observed

A new standalone probe stops the helper after publishing SQEs and after the
completion-waiting enter, exposing mapping addresses and layout offsets to its
parent. `ring_memory_probe.py` attempts external snapshots and has an initial
ordinary SQE/CQE decoder. This is deliberately separate from MCP attribution;
cooperative stops and helper-supplied mapping metadata remain assumptions.

The first live attempt failed before decoding: `/proc/PID/mem` returned EIO for
the ring mapping. A follow-up diagnostic tested SQ, CQ, and SQE mappings via both
that interface and `process_vm_readv`. All ring reads failed (EIO and EFAULT,
respectively), while both methods successfully read 16 bytes from ordinary
executable memory in the same child. Thus general parent-child read permission
was not sufficient for these ring mappings on this host. This result does not
establish the precise kernel implementation cause or apply to all kernels.
[Failure evidence](../experiments/mcp/evidence/ring-memory-access.json) preserves
per-mapping results and source/binary identities. The decoder is not validated
by this failed capture and is not used to claim new attribution coverage.

Reproduce with `python3.11 experiments/mcp/ring_memory_probe.py NEW_DIRECTORY`;
on this host it fails at the snapshot. `ring_memory_access.py NEW_DIRECTORY`
then runs the two-method diagnostic against the built helper. Diagnostic output
filenames require a fresh directory for each attempt. A future collection path
must address mapping access or obtain observations at another trusted boundary.

### Exported ring descriptor: negative control

The next probe attempted SCM_RIGHTS export of the helper's ring descriptor so
that the parent could mmap the actual ring, avoiding process-memory reads.
`sendmsg` failed with EINVAL before the first snapshot stop. A same-helper control
exported an ordinary file over the identical socket/message construction and
successfully delivered one descriptor. The ring-specific failure is therefore
not explained by a universally broken ancillary-message construction. This is
an observed host restriction, not a claim about all kernel versions.
[Control evidence](../experiments/mcp/evidence/ring-export-controls.json) records
both outcomes and helper identities. `ring_memory_probe.py --export-ring
NEW_DIRECTORY` preserves the failed attempt; no external-memory attribution
coverage is claimed. The probe now also records a reaped child's exit status in
its subprocess handle so failure cleanup does not attempt to signal it again.

The remaining collection choices include a collector-created inherited ring,
an in-process raw snapshot bridge, and privileged kernel observation. Each has
a different deployment/trust boundary; these failed external-read paths do not
invalidate the existing trusted runtime SQE/CQE attribution experiments.

### Successful raw-memory observation with a collector-created inherited ring

The next deployment model creates and maps the ring in a parent before forking
the worker. The parent retains its own valid shared mappings, so it does not
need process-memory access or SCM_RIGHTS transfer. At cooperative worker stops,
it snapshots SQ counters/array, SQEs, and the completed CQ. The Python decoder
reads the binary layouts and joins user_data independently of the worker's JSON
records, then compares them as a separate consistency check.

The first live capture decoded three operations correctly: two seven-byte
writes and one EBADF read. Completion order was 103, 101, 102, rather than
submission order. Final file bytes matched both writes. Mutation checks rejected
an invalid SQ mask, overfull pending count, and out-of-range SQ array index.
[Evidence](../experiments/mcp/evidence/inherited-ring-memory.json) preserves raw
snapshot hashes, helper/decoder identities, operations, and negative checks.

Reproduce with `python3.11 experiments/mcp/inherited_ring_probe.py NEW_DIRECTORY`.
This is successful external raw-ring observation under a collector-created,
fork-inherited deployment model. It still uses cooperative stops and supplied
layout metadata, is limited to ordinary little-endian SQE/CQE layouts, and does
not yet establish MCP ownership, arbitrary existing-ring collection, or kernel
worker identity. The existing request attribution adapter does not consume
these snapshots yet.

Raw snapshot decoding now rejects missing, negative, boolean, unaligned,
overlapping, or out-of-bounds layout fields and truncated buffers before reading
records. New synthetic tests explicitly exercise 32-bit counter wrap and SQ array
indirection rather than assuming sequential SQE positions. A fresh inherited-ring
capture still passed all three operations after these checks; its
[evidence](../experiments/mcp/evidence/inherited-ring-validated.json) records the
updated decoder identity. All 67 tests pass. MCP integration remains outstanding.

The inherited-ring collector now captures strace for both processes and verifies
one setup in the collector, a successful fork to the submitting worker, and one
full waiting enter referencing the inherited descriptor. It checks exact snapshot
write lengths and requires SQ/SQE snapshot writes before enter and CQ snapshot
writes after enter completion. A fresh live run passed these lifecycle checks
and all three decoded operations. [Lifecycle evidence](../experiments/mcp/evidence/inherited-ring-lifecycle.json)
includes the distinct collector/submitter PIDs, trace source references, and trace
hashes. This supplies observed process/syscall ancestry for the raw snapshots;
it is still a standalone experiment, not yet a request-context integration.

### First MCP integration of inherited-ring snapshots

The new `uring-memory` replay scenario allocates a separate snapshot directory
per tool call. Its collector forks the submitting worker; the existing runtime
process bridge supplies request ownership across both generations. The adapter
decodes actual SQ/SQE/CQ snapshots, verifies their traced write sizes/order,
compares decoded operations with the runtime witnesses, and records snapshot
hashes and collector identity on each ring node.

The first capture correctly failed closed because stderr metadata was split
across writes. Reassembling the complete traced byte stream repaired that input
handling. A fresh concurrency-two, two-batch capture passed four MCP requests,
12 operations, eight writes, and four expected failed reads. All 67 tests pass.
[Evidence](../experiments/mcp/evidence/mcp-ring-memory.json) preserves the failed
attempt's error alongside the fresh passing reports and source identities.

Reproduce with `python3.11 experiments/mcp/run.py --scenario uring-memory
--instrumented --concurrency 2 --batches 2 --output NEW_DIRECTORY` (on one line).
This first integration still trusts the collector and supplied layout metadata;
it is not generic asynchronous kernel tracing. Further negative tests and
explicit snapshot graph edges are outstanding.

Raw-memory MCP provenance now contains explicit `ring_snapshot` nodes, traced
`ring_snapshot_written` edges, and `ring_memory_observed` edges to operations.
Request queries traverse these ancestors. A fresh concurrency-four, two-batch
capture passed 24 operations from eight requests; all eight queries retained
exactly three operations and three snapshot nodes. An SQE-opcode mutation in a
captured snapshot was rejected as disagreeing with runtime witnesses, then the
original snapshot was restored. [Graph evidence](../experiments/mcp/evidence/mcp-ring-memory-graph.json)
preserves these checks and capture identities; output hashes were revalidated.
All 67 tests pass. This mutation check establishes consistency checking, not
protection against a cooperating collector falsifying both evidence streams.

The raw-memory adapter now verifies that collector setup/fork and snapshot writes
carry the same inherited request context as the submitting worker. It requires
lifecycle/snapshot timing, rejects symlinked snapshot paths, and applies the
unsupported registration/process-change checks to the collector except for its
one expected worker fork. A fresh eight-request run passed all 24 operations
under these stronger gates. [Capture evidence](../experiments/mcp/evidence/mcp-ring-memory-context.json)
retains reports and source identities. [Mutation checks](../experiments/mcp/evidence/ring-memory-context-mutations.json)
confirm rejection of lost setup context, changed snapshot context, and missing
snapshot timing. These checks constrain the observed cooperative chain; they do
not authenticate a malicious collector or make filesystem snapshots immutable.

Snapshot integrity is now checked again when querying provenance. Previously,
valid graph hashes did not establish that referenced snapshot files still had
the recorded bytes. Queries now reject missing, changed, symlinked, or out-of-run
snapshot paths. A real capture query passed, rejected an appended snapshot byte,
and passed after restoration. [Query evidence](../experiments/mcp/evidence/snapshot-query-integrity.json)
records this sequence and the query implementation hash. All 68 tests pass,
including missing-file and symlink cases. Hash consistency is not cryptographic
authentication of the collector, and concurrent filesystem mutation remains
outside the immutable-capture assumption.

### Raw-memory attribution under concurrent request pressure

A concurrency-32, two-batch `uring-memory` replay with string request IDs and
spoofed client context passed 64 requests and 192 operations: 128 writes and 64
expected failed reads. All 64 request evidence chains selected exactly three
operations and three snapshots, and all snapshot/output hashes were validated.
[Pressure evidence](../experiments/mcp/evidence/ring-memory-c32-spoof.json)
preserves checks, reports, and source identities. This tests isolation across
many per-request collector/worker pairs, not a shared concurrent raw-memory ring.

The actual LLM-agent raw-memory run also passed: four unique MCP calls followed
by barrier, 12 operations, eight writes and four expected failures. All four
queries retained three operations and three snapshots; protocol intervals showed
zero overlapping pairs. [Agent evidence](../experiments/mcp/evidence/agent-ring-memory.json)
preserves validated reports, source identities and agent-log hash. This adds real
agent execution to the cooperative raw-memory path; concurrent coverage comes
from replay. All 68 tests pass.

The raw decoder audit found auxiliary SQE bytes were previously omitted from the
normalized record without validation. Inspecting the local Linux UAPI layout
confirmed these include I/O priority, operation-specific flags, buffer selection,
personality, and additional union fields. The scoped decoder now requires these
bytes to be zero, matching the controlled helper's construction, and rejects
nonzero values rather than silently erasing unsupported semantics. Nine byte
mutation positions are covered by regression subtests; all 69 tests pass. A fresh
live inherited-ring capture also passed its three operations and syscall
lifecycle checks. [Evidence](../experiments/mcp/evidence/inherited-ring-aux-validation.json)
preserves the new decoder identity. This is an explicit scope gate, not support
for the rejected operation modes.

### Ring coverage reports distinguish evidence methods and unknown work

Reports now count attributed operations by observation method and separately
count enter calls with/without attributed operations. The legacy
`submissions_decoded: false` is explicitly defined as lack of generic kernel
submission decoding, avoiding confusion with scoped raw-snapshot decoding.
A fresh four-request capture passed 12 raw-memory operations tied to four enter
calls; eight other enter calls had no attributed operations. Those eight are
not asserted to be eight missing I/Os: enters can submit, wait, or perform ring
control work, so no total-operation denominator is available.
[Coverage evidence](../experiments/mcp/evidence/ring-coverage-report.json) preserves
the reports and identities. All 70 tests pass, including one enter carrying
multiple operations and rejection of references to absent enter evidence.

Inspecting the eight uncovered enters in the coverage capture found positive
submission counts in all eight, with return values summing to **17 accepted
submissions**. All originated in the Node server process (including one separate
thread), rather than the per-request C collectors. Their opcodes, completions,
and request ownership are not decoded. This narrows the next collection target
to the server's own rings without claiming a specific libuv callsite from PID
alone. [Inspection evidence](../experiments/mcp/evidence/uncovered-ring-submissions.json)
records each source/TID, requested count, and accepted count.

Coverage reporting now exposes those per-enter details and sums observed
uncovered accepted submissions. This count does not establish successful I/O,
completion identities, or a universal operation denominator; SQPOLL and activity
outside decoded capture still matter. All 70 tests pass.

### Static inventory for native Node ring instrumentation

The installed binary retains local symbols for `uv__iou_submit`, ring setup/
enter/register wrappers, `uv__io_poll`, and filesystem preparation routines
including read/write, close, open, statx, and rename. A reproducible inventory
script (`inspect_node_rings.py OUTPUT`) records the executable hash, runtime
versions, symbol addresses, and bounded disassembly hashes.
[Inventory evidence](../experiments/mcp/evidence/node-ring-symbols.json) pins this
inspection to the actual installed binary.

The `uv__iou_submit` disassembly begins by loading a ring-state pointer and
publishing an incremented counter with `stlr`, then conditionally invokes a
syscall. Its entry is not the conventional stack-frame prologue used by the
existing work-submit hook. Consequently, reusing that patching scheme without
instruction/ABI analysis would be unsafe. This is a static candidate inventory,
not proof those symbols explain the captured 17 submissions. The next native
extension needs verified ring-state layout and dynamic callsite evidence before
it can make attribution claims.

### Dynamic Node ring callsites under GDB

A controlled Node workload opened, read, and closed a file three times under
GDB. Symbol breakpoints expanded to optimized inline locations. The initial
probe printed argument registers and produced incorrect arguments there; those
values are not evidence. The corrected probe used debugger-resolved named
arguments. All three observed enter calls requested two submissions/two
completions and came from `uv__epoll_ctl_flush`, including delayed-task, main-loop,
and tracing-shutdown stacks. No `uv__iou_submit` breakpoint fired in this run.

A second run printed the live `struct uv__iou` layout and state from the caller:
SQ/CQ counter pointers, masks, mappings, sizes, ringfd, and in-flight count were
available through debug information. Both corrected runs exited normally.
[Dynamic evidence](../experiments/mcp/evidence/node-ring-dynamic-callsites.json)
preserves logs, workload/debugger script hashes, and the executable identity.
Reusable scripts live under `experiments/mcp/node-ring-debug`; run GDB in batch
mode with `-x callsites.gdb` (or `layout.gdb`), followed by `--args node
workload.cjs FILE`, using full paths as needed.

This establishes actual epoll-control batching in this standalone workload.
It does not retroactively classify all 17 unknown MCP-capture submissions or
attribute their owners. It also shows why a generic entry-register hook cannot
be inferred from optimized symbolic breakpoints. Native collection should target
the verified control-batch boundary separately from filesystem SQE preparation.

### Debugger-assisted in-process copy of native Node SQEs

Direct GDB examination of the live ring mapping failed with `Cannot access
memory`, despite readable `uv__iou` state. A second controlled probe invoked
`malloc`, `memcpy`, and `free` inside the stopped target to copy 128 bytes from
its SQE mapping into ordinary memory. That copy succeeded at three epoll-flush
breakpoints and the workload exited normally. Six copied SQE slots contained
opcode 29; the records preserve raw fd/off/len/user_data fields.
[Evidence](../experiments/mcp/evidence/node-ring-inferior-copy.json) includes
script/log hashes and decoded candidates. Reusable `memory.gdb` and `copy.gdb`
probes preserve both paths.

This is a promising cooperative observation boundary, not a passive collector.
The probe reads the first two slots, so pending SQ array/counter membership and
CQ completions still need validation before treating them as submitted
operations. Inferior allocator calls may deadlock in other workloads and alter
execution. No new MCP ownership coverage is claimed by these candidate records.

The debugger copy probe now also snapshots SQ head/tail counters from each
observed native control ring. All three enters had head 0, tail 2, mask 255:
two pending entries, agreeing with their requested submission counts. The
workload exited normally. [Pending-count evidence](../experiments/mcp/evidence/node-ring-pending.json)
preserves the observations and probe/log hashes. SQ array indirection is still
uncaptured, so these counters do not alone prove that the first two copied SQE
slots are the exact pending operations. CQE validation also remains outstanding.

The setup-layout probe exposed another optimized-code limitation. Entry-local
`params` values at `uv__iou_init` were uninitialized and must not be used as kernel
layout evidence. Address breakpoints at the standalone function's setup-return
and success branch did not fire, although the workload exited normally. The
compiler also provides inline instances (GDB reports multiple symbol locations),
so the standalone addresses are not sufficient capture points. The attempted
`node-ring-debug/setup.gdb` script is retained as a diagnostic, not a validated
layout collector. Capturing the setup syscall return independently of inline
function placement is still required before validating SQ array membership.

### Native SQ array membership verified in the same capture

GDB syscall catchpoints for setup (AArch64 syscall 425) captured entry and return
parameter blocks, avoiding optimized function placement. Paired per debugger
thread and parameter address, all three successful setups returned 256 SQ / 512
CQ entries, zero setup flags, and SQ array offset 8256. The same capture copied
the array through inferior memory: each observed batch had head 0, tail 2, mask
255, and array entries [0, 1]. Thus the two copied SQE slots per batch are now
verified pending queue members for this run, rather than guessed first slots.
[Evidence](../experiments/mcp/evidence/node-ring-array-verified.json) preserves
setup results, checks and script/log hashes. The workload exited normally.
Completion identity/results and MCP request ownership remain unobserved by this
native debugger path. The fixed offset in the diagnostic is checked against
that run's kernel-returned parameters; it is not a portable layout assumption.

### Native control-ring submissions matched to completions

A binary-specific breakpoint immediately after the epoll-flush enter syscall
copies CQ counters and two CQEs before libuv consumes them. In the live controlled
run, each of the three enters returned 2; each matching ring had CQ head 0/tail 2.
The new bounded log inspector joins the six pending SQEs to CQEs by user_data,
rejecting duplicate or unknown completions, count/window mismatches, and partial
enters. [Completion evidence](../experiments/mcp/evidence/node-ring-completions.json)
records all six identity/result pairs and the log hash. All six results were zero.

This validates native control-ring operation/completion observation in this
first-batch workload. The debugger script remains pinned to the inspected binary,
uses target-side memory copies, and does not infer MCP ownership. Setup-return
metadata is captured in the log but the completion inspector's scope is the
bounded SQ/CQ join, not a general setup/lifetime verifier. Broader queue windows,
repeated identity lifetimes, and request-context integration remain outstanding.

The native completion inspector now explicitly requires observed SQ counters,
CQ ring identity, and CQ counters in addition to array, bytes, and enter return.
A missing CQ identity line previously could go unnoticed; the new gate rejects
it. Regression tests also cover out-of-order identity matching, partial enter,
changed array, duplicate completion identity, and abnormal exit. All 71 tests
pass, and the existing live six-operation log passes the stronger validator
([revalidation](../experiments/mcp/evidence/node-ring-completions-validated.json)).

### Repeated native ring windows: first-batch collector limit confirmed

A new loopback-network workload completed four checked request/response
connections under the native debugger probe. It produced 14 enters requesting
23 submissions, including batches of one, two, and four and a main ring advancing
SQ/CQ heads from zero through 19. The process exited normally. The bounded
first-batch inspector rejected the capture at the four-entry batch, as intended.
[Window evidence](../experiments/mcp/evidence/node-ring-network-windows.json)
records counts, source hashes, and rejection.

The probe's fixed first-slot dumps are stale/incomplete for these later windows;
only the counter/enter observations are valid here. Generalizing collection must
copy queue entries selected by the current head, mask, and SQ array and distinguish
reused user_data across completed lifetimes. This is concrete evidence for that
next implementation, not a successful 23-operation attribution result.

### Native queue-indexed collection across repeated batches

`windows.gdb` now copies each SQ array entry selected by the current head/mask,
then the corresponding SQE, and copies CQEs at the current CQ head/mask after
enter. The loopback workload passed 14 serialized batches with 23 identity-matched
operations across one-, two-, and four-entry windows. `inspect_native_windows.py`
requires matching enter counts, CQ windows, and unique pending/completion IDs
within each batch. Identity reuse after completed batches is permitted.
[Window results](../experiments/mcp/evidence/node-ring-windows.json) retain all
operations and queue positions plus the raw-log hash.

This removes the stale first-slot assumption. The experimental script still uses
the previously measured 8256-byte SQ array offset and fixed capacities; the new
inspector explicitly does not verify setup layout or ring lifetime. It supports
serialized batches only and does not yet supply MCP ownership. These deployment
and observation assumptions must be closed before production integration.

### Native SQ/CQ physical wraparound

The loopback workload now accepts a bounded connection count. A fresh 140-
connection debugger capture passed 422 serialized batches and 567 submission/
completion joins; the busiest ring advanced its queue tail to 563. This exceeds
both observed SQ capacity 256 and CQ capacity 512, exercising physical slot
wraparound with current-head/mask copying. [Wrap evidence](../experiments/mcp/evidence/node-ring-wrap.json)
preserves batch positions, operations, and collector/workload hashes. Synthetic
regression also covers unsigned 32-bit counter wrap and identity reuse after a
completed batch, plus rejected partial returns and mismatched completion IDs.
All 72 tests pass. Native capture still has the documented fixed-layout,
cooperative-debugger, and serialized-batch restrictions; no MCP owner is inferred.

Native debugger capture now has a reproducible runner:
`python3.11 experiments/mcp/run_native_ring_debug.py NEW_DIRECTORY --connections 8`.
It rejects a Node executable whose SHA-256 differs from the inspected binary,
snapshots scripts, records source/output identities, and kills the experiment
process group on timeout. A fresh run passed 26 batches and 39 joins
([runner evidence](../experiments/mcp/evidence/native-ring-runner.json)). Binary
pinning prevents accidental address reuse across builds; it does not validate
kernel layout, remove inferior-call effects, or establish request ownership.

The native runner now captures setup syscall entry/return parameter blocks in
the same session and requires layout validation before accepting batch joins.
It checks capacities, zero setup flags, SQ array offset, counter offsets, CQE
offset, matching parameter addresses, and setup evidence for every batch ring;
reused setup FD numbers are rejected as unsupported. A fresh eight-connection
run passed 26 batches/39 joins with these gates. Changing the captured array
offset was rejected. [Layout-checked evidence](../experiments/mcp/evidence/native-ring-layout-checked.json)
records reports, source hashes and mutation result. All 72 tests pass. This
closes the fixed-offset assumption for accepted runner captures, while full ring
lifetime tracking and MCP ownership remain outstanding.

Native batch validation now requires each previously seen ring's SQ head to equal
the preceding drained tail, and CQ head to match the current SQ head under the
single-completion-per-operation contract. Gaps, overlaps, or shifted completion
windows fail closed. A fresh 12-connection run passed these checks; the earlier
567-operation wrap capture also revalidated. [Continuity evidence](../experiments/mcp/evidence/native-ring-continuity.json)
preserves the fresh reports and source hashes. All 73 tests pass, including
omitted-batch and shifted-CQ negatives. This detects internal gaps between
observed batches; it does not prove observation of all activity before the first
batch or after the last, nor support arbitrary multishot rings.

Native epoll SQE records now include the target descriptor and control operation,
separate from the epoll descriptor. A fresh eight-connection capture passed 39
joins with 31 ADD and eight MOD operations. Every record retained its target FD;
unsupported control values fail validation. [Target evidence](../experiments/mcp/evidence/native-ring-targets.json)
preserves results and source identities. All 74 tests pass. These descriptor
numbers are resource references, not stable OFD identities or request owners;
connecting them to lifecycle/context evidence remains necessary. Legacy logs
without target fields remain readable but do not gain inferred target metadata.

Native batch records now include the debugger's selected inferior PID and Linux
LWP/TID at the submission breakpoint. A fresh eight-connection run retained
thread identities for all 26 batches/39 joins, spanning two submitting threads.
[Thread evidence](../experiments/mcp/evidence/native-ring-thread-identity.json)
preserves the complete results and collector identities. These are userspace
submitter TIDs, not kernel I/O-worker TIDs, and they do not establish a request
owner. Legacy captures without this record remain explicitly null. All 74 tests
pass; request-context joining still requires a compatible observation stream.

Setup validation now retains each successful return's log position and requires
it to precede the corresponding batch. Previously the whole-log setup inventory
could satisfy a batch with future evidence. The 39-operation thread-identity
capture revalidated; moving a batch ahead of its setup was rejected with
`ring setup follows batch`. [Ordering evidence](../experiments/mcp/evidence/native-ring-ordering.json)
preserves the check. All 74 tests pass. This closes a chronology gap without
claiming full descriptor-close/reuse lifecycle observation.

Native batch parsing now enforces submission → return → CQ window → completion
ordering. Duplicate returns, missing returns/windows, SQEs after return, and
orphan batch ends are rejected instead of being accepted through final counts or
failing with incidental Python errors. Regression tests cover these phases;
all 75 tests pass. The 39-operation capture revalidated with layout checks
([phase evidence](../experiments/mcp/evidence/native-ring-phase-validation.json)).

Native SQE text records now retain submission flags explicitly. The scoped
validator rejects nonzero flags rather than erasing them during normalization.
A fresh capture passed 39 joins with zero flags on every SQE
([flag evidence](../experiments/mcp/evidence/native-ring-flags.json)); a nonzero-
flag mutation is rejected by regression tests. All 76 tests pass. Older logs
remain readable without inventing a flags value; they do not gain this check
retroactively. Other unrecorded auxiliary SQE fields remain a native-collector
scope limitation, distinct from the stricter controlled raw-snapshot decoder.

Native CQ validation now rejects nonzero completion flags and out-of-range
result/identity fields. This enforces the single-shot completion contract instead
of accepting richer modes merely because user_data matches. The 567-operation
wrap capture revalidated under the stricter gate
([CQ evidence](../experiments/mcp/evidence/native-ring-cqe-flags.json)); nonzero
flags and invalid ranges have regression coverage. All 77 tests pass. This is
not multishot support, nor a change to the unresolved MCP ownership boundary.

Native reports now separate successful joins from completion outcomes. Auditing
the 39-operation target capture found 31 zero results and eight -17 results;
each negative ADD was followed by a successful MOD on the same numeric target.
[Outcome evidence](../experiments/mcp/evidence/native-ring-outcomes.json) preserves
those eight sequences and the log identity. Thus 39 validated joins never meant
39 successful effects. Repeated target numbers alone do not establish stable
resource identity or descriptor reuse; lifecycle capture is still needed before
assigning request ownership. All 77 tests pass after adding outcome summaries.

Native debugger capture now includes close syscall entry/return catchpoints
(AArch64 syscall 57). A fresh eight-connection run retained 39 ring joins and
46 successful paired closes, with per-thread entry/return log positions
([close evidence](../experiments/mcp/evidence/native-ring-close-observed.json)).
This supplies a same-stream lifecycle observation for subsequent descriptor
analysis. Creation/installation events and close-to-operation joining are not
implemented yet, so repeated numeric targets still do not imply stable resources
or request owners. The runner manifest pins the augmented debugger script.

### Successful closes separate repeated native target references

`native_close_epochs.py` correlates target references with paired successful
close observations in the same validated debugger log. Targets 22, 23, and 24
appeared across respectively six, five, and five intervals separated by observed
successful closes. None of the 39 references overlapped an unresolved captured
close. [Close-interval evidence](../experiments/mcp/evidence/native-close-epochs.json)
retains line references and all close outcomes.

This rules out treating those numeric target values as uninterrupted descriptor
lifetimes. The intervals are deliberately not resource/OFD identities: installs,
duplication, transfers, close_range, and failed-close effects remain untracked.
The analysis assumes the controlled process's shared descriptor table and makes
no request ownership claim. Reproduce with `python3.11
experiments/mcp/native_close_epochs.py CAPTURE/debugger.log` on one line.

Native capture now observes socket and accept4 entry/return stops (AArch64 198
and 242), alongside close and ring batches. The fresh eight-connection run
passed 39 joins and recorded 17 successful socket installations, with syscall,
returned FD, and log positions ([installation evidence](../experiments/mcp/evidence/native-socket-installs.json)).
This supplies creation observations for the loopback targets; other descriptor
installation mechanisms remain uncaptured. No stable OFD or MCP owner is inferred
from these records yet. The same-run pairing of installs, closes, and target
references is the next attribution step.

The scoped native socket-lifetime analyzer now links 33 of 39 epoll target
references to observed socket/accept4 installations and leaves six unresolved.
Any observed close attempt invalidates the projection before its return, avoiding
stale links on interrupted/failed closes; a later installation gets a distinct
identity. [Lifetime evidence](../experiments/mcp/evidence/native-socket-lifetimes.json)
contains all installation and reference positions. Regression covers reuse,
failed-close invalidation, and incomplete lifecycle pairs; all 78 tests pass.
These links are scoped observations in the controlled workload: unobserved dup,
SCM_RIGHTS, close_range, or other replacement activity remains outside coverage.
They are not general OFD identities and do not yet assign MCP request owners.

The socket projection now abstains when an installation returns the same FD
while another thread's close of that number remains unresolved. Such an overlap
cannot safely be ordered using return events alone. A regression demonstrates
that the installation remains recorded but its resource projection is rejected.
The live socket-installation capture revalidated
([evidence](../experiments/mcp/evidence/native-socket-lifetimes-revalidated.json));
all 79 tests pass. This conservative rule does not replace complete descriptor
mutation capture or establish kernel file-reference acquisition order.

A second lifecycle-overlap regression covers a close that starts and finishes
inside a socket-installation syscall interval. Checking only currently pending
closes at installation return missed this ordering. The analyzer now retains
close-entry positions and rejects the ambiguous projection in either ordering.
The live capture revalidated ([interval evidence](../experiments/mcp/evidence/native-socket-intervals.json));
all 80 tests pass. Rejection is conservative because observed syscall boundaries
do not reveal exact descriptor installation/acquisition instants.

The native runner now automatically generates socket-lifetime analysis and hashes
that artifact in its manifest. The first integrated run failed when another
thread hit a catchpoint during an injected `free` call; the failed manifest/log
are preserved. Scheduler locking now surrounds only injected malloc/memcpy/free
calls, with normal scheduling restored afterward. A fresh run passed 55 joins,
linking 49 targets and leaving six unresolved
([integrated evidence](../experiments/mcp/evidence/native-ring-integrated-lifetimes.json)).
This workaround increases scheduling perturbation and can still deadlock if an
inferior allocator needs a lock held by a stopped thread; the runner's timeout
remains essential. It is experimental collection, not a production-safe hook.


### Native eventfd installation evidence

Added eventfd2/epoll_create1 syscall stops (19/20 verified against local AArch64
asm-generic headers), preserving the original socket-only report. A fresh
12-connection capture completed with 55 operations in 38 batches. The new
resource report links 52 targets: 49 socket installations and three eventfds.
The socket-only report still leaves six unknown, so previous metrics retain
their meaning. Resource links invalidate on close attempts and reject observed
overlapping closes; unobserved replacement mechanisms remain a limitation.
No request ownership is inferred. Three targets still lack installation evidence.
Evidence: `experiments/mcp/evidence/native-ring-control-links.json`.
Validation: all 11 native collector/lifecycle tests pass, including control
installation opt-in and close invalidation; live runner completed successfully.


### Native ring capture during MCP protocol dispatch

`run_native_ring_debug.py --mcp-replay` now runs a real SDK Client/McpServer
pair over InMemoryTransport with the existing trusted request instrumentation.
Four sequential roundtrip tools returned contexts 1–4 and verified network
payloads. The fresh snapshotted capture decoded 23 operations in 14 batches,
with 20 observed resource installation links and three unresolved targets.
Request maps, native markers, responses and debugger logs are preserved and
hashed in `evidence/native-ring-mcp-replay.json`. This is deterministic replay,
not an LLM experiment or stdio transport capture. Markers and ring observations
are still separate timelines; no per-operation MCP ownership is claimed.
The next integration boundary is trusted context observation at resource creation
and ring preparation, distinguishing it from unowned event-loop submission.


### Submission-time context is insufficient for native MCP ring ownership

The debugger now captures marker write entry buffers and full-write return values
alongside native ring batches. `native_marker_timeline.py` checks exact equality
with the native marker log, validates marker thread identity, and records the
most recent execution context on each submitting thread. In the four-call MCP
replay, all 282 markers matched. Thirteen batches had explicit context zero;
one startup batch preceded any context observation. Thus submission-time request
context cannot attribute these 23 epoll operations. This is measured evidence for
tracking resource creation/operation preparation separately from ring submission.
It does not prove which request owns each operation. Marker producers are trusted;
this experimental join does not independently authenticate the marker file FD.
Evidence: `experiments/mcp/evidence/native-ring-marker-timeline.json`.

Reproduce the analysis with:
`python3 experiments/mcp/native_marker_timeline.py results/mcp/native-ring-marker-timeline`.
The first analyzer execution hit Python 3.6's missing `str.removeprefix`; replacing
it with prefix slicing allowed the same preserved capture to validate successfully.


### Resource creation restores ancestry across unowned ring submission

Added Linux-TID mappings at debugger descriptor-installation stops and joined
validated request markers to socket creation entry/return. The analyzer follows
observed descriptor installation identities to epoll SQEs, retaining close/reuse
invalidation. In a fresh four-call MCP replay, 12 of 23 operations have resource
creation ancestry: three each for contexts 1–4. Four have explicit unowned
creation context, and seven have unknown creation context or no installation
link. All 13 post-instrumentation submission batches still have context zero.
These are ancestry edges, not assertions that resource creators own every later
operation. Shared-resource request use and operation-preparation context remain
open. Tests exercise context reset, FD reuse, missing thread identities, and
entry/return context disagreement; all 13 native tests pass.
Evidence: `experiments/mcp/evidence/native-ring-resource-context.json`.
Analyze with `native_resource_context.py RUN_DIRECTORY` after a current native
MCP replay capture. Marker-log equality is validated before ancestry is emitted.


### Concurrent native MCP resource ancestry

Added bounded concurrent SDK calls and a workload overlap counter. Two fresh
16-call, concurrency-eight captures completed; the integrated runner now emits
and hashes the ancestry report automatically. Each capture decoded 71 operations
in 22 batches. The observed maximum active tool count was eight. Six batches each
contained resource ancestry from eight distinct requests; each request retained
three links (48 total). Sixteen operations had unowned resource creation context,
seven were unknown. All 21 post-instrumentation batches submitted with context
zero. A batch-level single-request label cannot represent this measured mixing.
This validates resource ancestry preservation under concurrent dispatch, not an
independent oracle for ownership of all operations. All 13 native tests pass.
Evidence: `experiments/mcp/evidence/native-ring-mcp-concurrent.json`.


### Separate socket oracle checks inferred native ancestry

The MCP replay now assigns client tokens, records outgoing RPC ID/token pairs,
and independently records each connected client socket's numeric descriptor.
`score_native_resources.py` recomputes inference without reading this oracle,
then compares request-linked targets against the token/socket records. A fresh
16-call concurrency-eight run checked 48 claimed ancestry links with zero
mismatches and coverage of all 16 requests. Swapping the first two sockets in a
copy of the oracle produced six mismatches, demonstrating request-swap detection.
This validates client-socket creation ancestry only: the oracle does not establish
ownership of all kernel effects, and numeric descriptors cannot distinguish two
same-number incarnations inside one request. Node's private socket handle is
used only by this controlled evaluation, not by inference.
Evidence: `experiments/mcp/evidence/native-ring-resource-oracle.json`.


### Native MCP ancestry stress and automatic oracle gate

The runner now snapshots the oracle scorer, emits its report and hash, and fails
if a claimed link mismatches or any request lacks a correct client-resource link.
A 160-request run with concurrency 16 decoded 647 operations in 182 batches.
All 480 claimed request ancestry links passed the separate socket oracle, covering
all 160 requests. The capture exercises repeated descriptor installations and
SQ/CQ physical queue wrap; exact per-ring tails and reuse counts are preserved
in `experiments/mcp/evidence/native-ring-mcp-stress.json`. This does not extend
the claimed relation beyond resource-creation ancestry or make the debugger a
production collector. Full Python 3.11 experiment suite: 83 tests passed.


### Native SQE preparation also occurs outside request execution

Disassembly of the pinned `uv__epoll_ctl_prep` places the final user_data store at
0x18c59b8; the next instruction 0x18c59bc retains ring pointer x1, epoll FD w0,
target x4, control w3 and user_data x6. A breakpoint there captured all 71
preparations in a 16-call concurrency-eight MCP replay. Joining ring/user_data
identities and checking target/control/epoll fields matched every observed SQE.
Sixty-nine preparations had context zero and two startup preparations had no
observed context. Resource ancestry scoring still passed. Thus moving context
capture from submission to SQE preparation is insufficient for this runtime;
propagation must start earlier, such as when a watcher update is enqueued.
Evidence: `experiments/mcp/evidence/native-ring-preparation.json`; analyzer:
`native_preparation.py RUN_DIRECTORY`. This is a pinned debugger experiment,
not a portable runtime adapter or a claim of complete causal ownership.

### Request context survives watcher queue insertion

Pinned disassembly of `uv__io_start` shows watcher queue insertion completed at
0x18b4554, with watcher pointer x20 and loop pointer x23. A breakpoint records
those identities, the target FD, and requested/current event masks. In a fresh
16-call concurrency-eight replay, 32 insertion events retained request context
(two per call), 16 had explicit context zero, and one preceded context observation.
The existing 71-operation capture and 48-link resource ancestry oracle passed.
This provides an earlier propagation boundary than SQE preparation, where context
was already zero. It does not yet establish a watcher-to-SQE edge: updates may
coalesce, and stop/restart/close paths and pointer lifetimes need observation.
Evidence: `experiments/mcp/evidence/native-ring-watcher-enqueue.json`.
Reproducible analysis: `native_watcher_context.py RUN_DIRECTORY`.


### Watcher insertion/removal episodes locate context loss

Pinned `uv__io_poll` disassembly identifies 0x18c8420 immediately after unlinking
and resetting watcher queue links: x1 is the watcher, x23 the loop. Added removal
observations and a scoped loop/pointer/FD episode matcher. The fresh concurrent
16-call capture matched 49 insertion/removal episodes: 32 request-scoped
insertions (two per request), 16 explicit unowned insertions, one with unknown
context. All 49 removals had context zero. Six removals lacked observed insertions
and remain unresolved. Missing removals and changed descriptors are recorded as
gaps rather than silently preserving identities. Fifteen native tests pass.
Evidence: `experiments/mcp/evidence/native-ring-watcher-queue.json`.
The matcher is not a general watcher lifetime proof: stop/close paths and
coalesced updates still need capture before claiming operation ownership.


### Watcher queue ancestry reaches individual native SQEs

A breakpoint at the pinned poll-loop call instruction 0x18c83f8 connects the
preceding removal to its preparation arguments. The analyzer checks loop/FD at
removal-to-call, ring/target/control at call-to-preparation, then uses validated
ring/user_data preparation-to-SQE joins. A fresh 16-call replay connected 55 of
71 operations to poll-loop removals. Thirty-two retain request insertion ancestry
(two per call); all 32 target/request pairs agree with the separate socket oracle.
Sixteen links have unowned insertion context and seven unknown. Sixteen other
preparations are outside this poll call site and receive no watcher ancestry.
This is stronger than creator-only ancestry but remains nonexclusive: coalesced
updates, stop/close lifecycle and retry ancestry need further observation.
Evidence: `experiments/mcp/evidence/native-ring-watcher-operations.json`.
Analyzer: `native_watcher_operations.py RUN_DIRECTORY`.


### Failed completion to retry ancestry

Pinned flush disassembly exposes the failing completion's user_data at 0x18c5848
and its retry preparation call at 0x18c5888. Capturing both establishes a direct
ADD/-EEXIST-to-MOD transition, checked against decoded CQEs and preparation
arguments. A fresh 16-call concurrent capture produced 16 validated retries,
one per request. Every retry target/request pair matched the separate socket
oracle. These edges recover the 16 preparations outside the normal poll call
site while retaining their failed-operation source. Combined with the 32 direct
request-scoped watcher links, this supplies queue ancestry for 48 operations.
It still does not prove exclusive ownership when watcher updates coalesce, and
other error/retry paths are not supported. Evidence:
`experiments/mcp/evidence/native-ring-retry-ancestry.json`; analyzer:
`native_retry_ancestry.py RUN_DIRECTORY`.


### Typed native-ring provenance graph

Added `native_graph.py`, consolidating validated request markers, watcher queue
episodes, preparation/SQE joins, CQEs and retry triggers into typed nodes/edges.
A fresh integrated concurrent capture contains 16 request nodes and 71 ring
operations; each request reaches exactly three operations, including its retry.
The runner now snapshots graph analyzers, builds `native-graph.json`, and records
its hash in the manifest. Inference excludes the independent socket oracle,
which continues to pass 48 resource/request checks in this capture.
Reachability denotes observed ancestry, not exclusive ownership: incomplete
coalescing/lifetime observation remains explicit, and this native evidence graph
has not yet been merged into the existing strace attribution graph.
Evidence: `experiments/mcp/evidence/native-ring-graph.json`.


### Observing updates while a watcher is queued

Added a pinned breakpoint at 0x18b44dc, after pevents changes and successful
watcher-array allocation but before queue membership handling. The fresh
16-call workload generated 65 update observations, none inside an already
observed queued episode. Therefore this live workload does not test coalescing.
The queue analyzer now retains intermediate update records and the graph can
attach additional request parents through those records; a synthetic two-context
update test checks retention. All 16 native tests pass. This synthetic evidence
must not be presented as live shared-watcher coverage; a workload deliberately
updating the same watcher from different requests is still required.
Evidence: `experiments/mcp/evidence/native-ring-watcher-updates.json`.


### Shared watcher workload exposes unobserved stop removals

Added `--shared-watcher` (requires all calls in one concurrent batch). The first
two attempts failed because readStart on an unconnected socket returned -107;
both failed manifests are preserved. The corrected workload establishes one
socket before requests, then each tool synchronously calls readStop/readStart
and awaits the same verified network payload. Eight requests overlapped; the
capture decoded 12 operations. It observed no intermediate queued updates,
but eight replacements without observed removal and seven removals without
observed insertion. Only context 8's final insertion survived to a matched queue
episode. This is a stop/restart workload, not evidence of coalescing. Observing
uv__io_stop is the next necessary boundary. The shared socket is created before
requests, so the creator-only oracle's all-request coverage requirement is
intentionally inapplicable in this mode; mismatches still reject the run, and
its score reports actual coverage rather than claiming every request covered.
Evidence: `experiments/mcp/evidence/native-ring-shared-watcher.json`.


### Stop-path cancellation separates abandoned watcher episodes

Added an observation at 0x18b49c0 after uv__io_stop unlinks/resets the queue.
The analyzer retires pending episodes as canceled rather than letting them reach
later poll removals. The first analysis failed due to an incorrect startswith
edit; its failed manifest is preserved in native-ring-watcher-stop. After fixing
that error, all 17 native tests passed and a fresh shared-watcher capture passed.
The detailed cancellation counts and remaining unmatched removals are preserved
in `experiments/mcp/evidence/native-ring-watcher-stop.json`. Cancellation is a
runtime queue fact, not evidence that the request had no other kernel effects.


### Canceled episodes remain queryable without false kernel links

Native graphs now retain canceled insertion/update nodes and cancellation actors,
with terminal canceled_before_poll edges. A fresh eight-request shared-watcher
capture passed. `query_native_graph.py RUN --rpc-id 1` validates the manifest graph
hash and source capture hashes before returning request ancestry. Request queries
and a rejected marker-file mutation are preserved in
`experiments/mcp/evidence/native-ring-cancellation-graph.json`. Cancellation
nodes intentionally have no edge to subsequent ring operations. A request with
no reachable ring operation may still have other effects outside this graph.


### Partial-stop insertion closes a non-startup queue gap

Pinned uv__io_stop disassembly has another insertion path when event interests
remain. Added observation at 0x18b4a00 after queue links are stored (loop x0,
watcher x1). A fresh eight-request shared-watcher run now matches five poll
episodes, retains eight cancellations, and leaves six startup removals without
observed insertion, down from seven. A fresh 16-request concurrency-eight
regression also passed the runner and resource oracle; its exact queue counts
are saved with the shared workload in
`experiments/mcp/evidence/native-ring-partial-stop.json`. Startup initialization
and inlined insertion paths still require observation. This change adds observed
evidence rather than assigning missing startup owners by inference.


### Native provenance reaches the ring submission syscall

Graphs now include observed io_uring_enter batches and their returns, with ring
FD, SQ head/tail, submitting TID and independently observed execution context.
Each operation points to its submission through submitted_by. The direction is
intentional: following a request's ancestry to a shared syscall must not then
fan out into unrelated SQEs from other requests. In a fresh 16-call concurrent
capture, every request still reached exactly three operations; eight requests
reached the same submission nodes. This preserves the many-request-to-one-syscall
relationship without collapsing operation identities. These are debugger-observed
submission calls, not kernel worker execution records.
Evidence: `experiments/mcp/evidence/native-ring-submission-graph.json`.


### Independent graph ancestry scoring

Added a graph scorer that traverses request ancestry and compares reached SQE
targets with the separately recorded RPC/token/socket oracle. The runner now
writes/hashes graph-score.json and rejects mismatches; ordinary per-request
socket runs also require every request covered. A fresh 16-request concurrent
capture passed 48 graph links. Swapping request 1 and 2's graph parents produced
six mismatches, testing the graph rather than only resource-creation analysis.
Shared-descriptor tokens cannot disambiguate requests targeting the same socket;
that mode retains this explicit limitation and reports actual request coverage.
Evidence: `experiments/mcp/evidence/native-ring-scored-graph.json`.


### Shared-descriptor oracle detects a swap that FD scoring misses

The controlled shared-socket workload now separately records each token's
successful readStop/readStart sequence and descriptor. A scoped oracle checks
that only the final request's update reaches ring operations in this single
synchronous batch; earlier updates are superseded. The fresh eight-call capture
passed. Swapping request 1 and 8 graph parents still passed numeric-FD scoring
(all share one socket), but the sequence oracle detected two request-survival
mismatches. The runner includes this check and hashes its input. This evaluates
queue survival for this workload, not general shared-stream effect ownership.
Evidence: `experiments/mcp/evidence/native-ring-shared-action-oracle.json`.


### Shared-sequence oracle scheduling check

The shared workload now schedules an immediate callback at the first action and
records whether it has executed for every stop/start. The scorer rejects missing
turn evidence or actions after that boundary rather than assuming a synchronous
batch. A fresh eight-request capture passed with all 16 actions before the
boundary and zero graph mismatches. Regression tests verify same-FD parent-swap
detection and rejection of split/incomplete action sequences. Full experiment
suite: 89 tests passed. Older action-oracle captures lack the new turn field and
must not be presented as passing this stricter scorer.
Evidence: `experiments/mcp/evidence/native-ring-shared-turn-checked.json`.


### External stdio MCP replay under the native collector

Added --mcp-stdio: an external Python JSON-RPC client initializes the SDK stdio
server, issues bounded concurrent tool calls, validates responses and closes
stdin for orderly shutdown. Dedicated inherited pipes separate inferior MCP
stdout from GDB diagnostics. The initial attempt replaced Node arguments with
GDB run redirections and never launched the script; after correcting the run
command, a fresh four-call concurrency-two capture passed: 24 operations in 11
batches, 12 graph ancestry links checked with zero mismatches. Full protocol
messages and failure evidence are preserved in
`experiments/mcp/evidence/native-ring-stdio.json`. This closes native stdio replay
integration, but the client is deterministic, not an LLM agent. Shared-watcher
stdio mode is intentionally unsupported pending scheduling-specific validation.
