# Current attribution coverage

This is a measured research prototype, not a completed universal attributor.
Read [runtime findings](runtime-findings.md) for failures and detailed experiments,
and [experiment instructions](mcp-experiment.md) to reproduce captures. Evidence
is scoped to the source hashes and binaries recorded by each run; a historical
passing report does not validate later edits.

| Boundary | Evidence and current behavior |
| --- | --- |
| Actual LLM → official filesystem MCP → Node/libuv → syscall | [Fresh agent run](../experiments/mcp/evidence/agent-post-worker-and-schema.json): four successful calls; 16 selected effects bound, eight independently labelled unique-path effects correct. Reused summary-path effects lack that independent oracle. |
| Actual LLM → MCP → two persistent worker processes → syscall | [Agent relay](../experiments/mcp/evidence/agent-worker-relay.json): 12 file effects correct, eight IPC jobs; each leaf write reaches one request through two jobs. Calls were sequential. |
| Concurrent persistent workers, cancellation, failures, descendants | [Worker matrix](../experiments/mcp/evidence/persistent-worker-matrix.json), [initialization regression](../experiments/mcp/evidence/worker-initialization-regression.json), and detailed findings. Runtime context is carried by internal job identities, not workload slots or client-supplied context. |
| Shared TCP connection across requests | [Multi-batch](../experiments/mcp/evidence/shared-network-multibatch.json) and [singleton reuse](../experiments/mcp/evidence/shared-network-singleton-reuse.json): conservative candidate ownership, including extra candidates. Stream byte-range attribution is unresolved. |
| Descriptor transfer between persistent workers | [Observability audit](../experiments/mcp/evidence/descriptor-observation-audit.json): 32 pairs verified with ring creation explicitly denied. Earlier captures contain undecoded io_uring activity and now cause pairing abstention. Receive ancestry is separate from execution ownership; general FD/OFD lifetimes remain open. |
| Shared operation with multiple request parents | [Join schema](../experiments/mcp/evidence/mapping-schema.json): explicit join parents survive validation; malformed mappings invalidate capture. |
| io_uring operations | [Actual-agent ring run](../experiments/mcp/evidence/agent-ring.json): 12 ring operations correctly attributed across four MCP calls using trusted helper SQE/CQE observations. Agent path uses one process/ring per request; arbitrary runtime and kernel-side decoding remain open. |
| Multiple requests sharing one io_uring | [Shared-ring matrix](../experiments/mcp/evidence/shared-ring-matrix.json) and [queue wraparound](../experiments/mcp/evidence/shared-ring-wraparound.json): verified per-operation ownership across unscoped batch submission/completion. Trusted cooperating worker, fixed batches, single-shot READ/WRITE; not arbitrary ring traffic. |
| Failed MCP response after successful effects | [Response identities](../experiments/mcp/evidence/worker-response-identities.json): tool failure does not imply no effects. Failed workloads require explicit query opt-in; invalid capture remains unqueryable. |
| Missing markers or runtime completions | Strict capture invalidation; bindings and graph are cleared. [Recent agent failures](../experiments/mcp/evidence/worker-initialization-regression.json) show that successful tool responses alone do not establish trustworthy attribution. |

The "Actual LLM" agent traces throughout this document were produced by
Codex CLI 0.160.1 with model `gpt-6-astra` (reasoning effort `low`,
from `~/.codex/config.toml`).

The attribution mechanism combines internally assigned MCP contexts, runtime
execution brackets, libuv work identities, explicit IPC dispatch/receive brackets,
and process/descriptor lifecycle evidence. `query.py` exposes the evidence chain;
independent workload oracles evaluate attribution without supplying identities to
inference. Instrumentation and marker producers remain trusted.

Remaining work includes a runnable kernel collector with lower overhead, broader
runtime adapters, stronger process/resource identities, exact attribution on
multiplexed network streams, general descriptor-transfer and OFD lifetime tracking, io_uring, and mmap-mediated
activity. eBPF has not been executed on this host because the required privileges
are unavailable. The current strace path has substantial measured overhead.
Existing external provenance systems have not been benchmarked head-to-head here;
architectural comparisons must not be presented as measured failures.

The immediate experimental priority is to extend one unsupported boundary at a
time with an independent oracle, demonstrate the current gap, then add propagation
or represent ambiguity explicitly. Repeat live integration captures after changes
to worker setup, embedded programs, runtime hooks, or shutdown behavior: unit
coverage alone missed the worker initialization regression.

Descriptor reuse before ring submission is now covered by `uring-reuse`:
32 writes in the dedicated capture resolved to the replacement file, where
preparation-time resolution would have pointed to the original. The neighboring
three-scenario regression passed 72 operations. Resource resolution remains a
scoped opening-path observation at submission, not a general inode/OFD identity
mechanism; partial submission/wait patterns are rejected.

Actual-agent shared-ring coverage now includes four sparse sequential requests
through one persistent worker: 12 operations, four partial batches, and exact
per-request queries. Protocol timestamps establish zero overlap despite the
agent's textual concurrency claim; controlled replay supplies concurrent cases.

Raw-memory MCP coverage: `uring-memory` uses collector-created, fork-inherited
rings and cooperative stops to decode actual SQE/CQE snapshots. A concurrency-32
capture passed 192 operations across 64 requests with string IDs and spoofed
context; each request retained its three operations and snapshots. This remains
per-request-ring collection with a trusted collector, not arbitrary ring capture
or kernel worker attribution. Queries verify snapshot hashes as well as graph
hashes. An actual-agent run also passed four sequential requests and 12 operations, with exact snapshot-bearing queries.


Native Node ring coverage now includes a binary-pinned AArch64 debugger collector
that reads actual SQ/CQ windows around libuv epoll flushes. The latest
[control-descriptor capture](../experiments/mcp/evidence/native-ring-control-links.json)
joined 55 operations across 38 batches in a 12-connection workload. Observed
socket/accept4 installations explain 49 targets; eventfd2 installations explain
three more. Three targets remain unresolved. These are resource installation
links, not MCP request ownership or general OFD identities. Earlier queue-wrap
experiments decoded 567 operations. This native branch remains separate from the
MCP attribution graph: it needs trusted request-context integration and an
explicit representation of shared event-loop work. The collector injects memory
copies under GDB, is intrusive and binary-specific, and may deadlock on allocator
locks despite scheduler locking and a bounded runner timeout.


Native MCP integration now has deterministic SDK replay at concurrency 16:
[160-request stress evidence](../experiments/mcp/evidence/native-ring-mcp-stress.json)
records 647 decoded operations and 480 independently checked client-resource
ancestry links, covering every request with zero mismatches. The runner checks
marker-log equality and scores against a separate token/socket oracle. Native
submission context alone remained unowned in earlier concurrent captures;
resource creation supplies ancestry without claiming ownership of all later
operations. Shared-resource use, operation-preparation context, native stdio/LLM
integration, and a less intrusive collector remain open.


Native graphs now expose request → watcher episode → SQE → completion ancestry,
explicit ADD/EEXIST retry edges, and many-request io_uring_enter submissions.
Cancellation nodes retain abandoned updates without linking them to later kernel
operations. `query_native_graph.py` verifies graph/capture hashes. Per-request
socket graph ancestry has an independent target oracle; shared stop/restart
workloads additionally check update survival, including an event-loop boundary
check. See [shared-sequence evidence](../experiments/mcp/evidence/native-ring-shared-turn-checked.json).
This remains deterministic in-memory MCP replay, with trusted intrusive GDB
instrumentation. Startup insertions, general coalescing/lifetimes, lower-overhead
collection, native stdio/LLM integration, and merging native/strace graphs remain
unfinished. Graph reachability is ancestry, not exclusive kernel-effect ownership.
