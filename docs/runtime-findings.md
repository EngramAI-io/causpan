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
| Detached Node work | 192 request I/O events occurred after their MCP responses; all were correctly attributed. |
| Shared work with one scalar owner | Two batched writes lost 30 of 32 expected request-parent edges. |
| Shared work with explicit context joins | Node and Tokio each recovered all 32 edges with no extra parents; each scalar control missed 30. |
| Node regression matrix | 120/120 runs passed capture validation and applicable independent oracles. |
| Tokio regression matrix | 48/48 runs passed; 959 request-owned runtime spans migrated between kernel threads. |
| Tokio stress matrix | 12/12 runs passed at concurrency 128, checking 10,496 request I/O events and 2,602 migrating request-owned spans. |
| Node batch stress | All 512 parent edges recovered across five shared writes at concurrency 128. |

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

These counts describe the selected fixtures, not every syscall in the process.
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
intervals, processes, syscalls, and observed resources. Resource observation edges
are not data-flow edges: reading and later writing the same path does not by itself
prove a data dependency. Tokio task spans and individual polls are separate nodes.
Its current markers record poll execution, not a complete queue lifecycle; an
aborted task that never polls has no execution interval.

## Failures that shaped the implementation

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

See [environment setup](mcp-experiment.md) for Node, npm, strace, and agent setup.
From the repository root:

```bash
python3.11 -m unittest discover -s experiments/mcp -p 'test_*.py'
cargo test -p causpan-runtime
python3.11 experiments/mcp/build_tokio.py
python3.11 experiments/mcp/run.py --runtime tokio --mode replay --scenario detached --instrumented --seccomp --concurrency 8 --pool-size 4 --batches 2 --output results/mcp/my-tokio-run
python3.11 experiments/mcp/query.py results/mcp/my-tokio-run --request 3 --fixture-only
python3.11 experiments/mcp/render.py results/mcp/my-tokio-run
```

Output directories must be new. Each run preserves its configuration, source
snapshot, manifest, protocol records, traces, attribution, and evaluation reports.
The build helper records executable and source hashes; subsequent runs reject
stale builds with that manifest. Older captures include executable hashes and
source snapshots but do not prove those sources produced that executable.
The latest additional agent attempt hit the account's usage limit before tool
execution; it is recorded as failed, not substituted with scripted replay. The
earlier successful real-agent captures remain available.

## Limits and next research questions

The Node native hook is restricted to the verified AArch64 Node 24.20.0 executable
and libuv 1.52.1. It installs before server work starts; it is not a general late
attach mechanism. The Tokio bridge is source-level and requires the pinned
runtime's tracing support plus `tokio_unstable`. Arbitrary executors, custom native
threads, long-lived child request channels, and cross-host calls need additional
handoff adapters. Kernel PID reuse, inode identity, io_uring, and distributed
clock/identity lifetimes are not fully modeled.

Instrumentation and marker files are trusted. A compromised server can forge or
omit userspace evidence; these experiments do not provide a tamper-resistant
security boundary. eBPF capture was not executed on this host. CamFlow and
OpenTelemetry were not benchmarked, so the results establish limitations of the
implemented PID/window baselines, not comparative claims about those systems.

Tracing is expensive. In one randomized 20-run benchmark after TID caching and
strace seccomp filtering, median traced execution was 0.689 seconds without the
bridge versus 7.569 seconds with it (10.98x). Capture-off medians were 0.533 and
0.541 seconds on a noisy shared host; that small sample does not establish
negligible instrumentation overhead. A lower-overhead collector and sustained
throughput measurements remain necessary.

The original Rust workload/evaluator is a separate early scaffold. Its baselines
still need an oracle-isolation audit; its scores should not be combined with the
MCP matrix. Use the MCP pipeline for the results above.
