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
| io_uring operations | [Direct ring probe](../experiments/mcp/evidence/io-uring-gap.json): two verified writes absent from the syscall list, out-of-order completions, and a trusted runtime SQE/CQE joiner. MCP context integration and kernel-side decoding remain open. |
| Failed MCP response after successful effects | [Response identities](../experiments/mcp/evidence/worker-response-identities.json): tool failure does not imply no effects. Failed workloads require explicit query opt-in; invalid capture remains unqueryable. |
| Missing markers or runtime completions | Strict capture invalidation; bindings and graph are cleared. [Recent agent failures](../experiments/mcp/evidence/worker-initialization-regression.json) show that successful tool responses alone do not establish trustworthy attribution. |

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
