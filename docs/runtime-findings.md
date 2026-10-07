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
| Descriptor-table regression run | Fresh concurrency-32 child-process and inbound-network runs passed after descriptor table identity changes: the file oracle checked 64 request events with no mismatches, and inbound TCP passed 64/64 payload checks. A live Linux `clone3(CLONE_FILES)` probe confirmed a child-created socket descriptor remained visible to the parent; synthetic trace regressions check attribution’s shared-table and copied-table behavior. Full MCP-server operation through `CLONE_FILES` is still untested. See [spawn evidence](../experiments/mcp/evidence/clonefd-spawn-c32.json), [network evidence](../experiments/mcp/evidence/clonefd-inbound-c32.json), and [live probe evidence](../experiments/mcp/evidence/clone-files-live.json). |
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
