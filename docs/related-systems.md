# Related provenance and agent observability systems

This comparison narrows the claim made by Causpan. The goal is not to claim that
existing systems cannot observe agent effects. Several systems capture kernel
events or system-level provenance. The unresolved question tested here is how to
bind an individual MCP JSON-RPC `tools/call` invocation to the kernel events
executed on its behalf when runtime work is asynchronous, shared, or multiplexed.

## What adjacent systems provide

| System | Relevant capability | Relationship to this experiment |
| --- | --- | --- |
| [AgentSight](https://arxiv.org/abs/2508.02736) | Uses eBPF boundary tracing to observe LLM traffic and system effects, then correlates the streams with a userspace engine and secondary LLM analysis. | It addresses agent-intent/effect observability. The paper describes stream correlation, not an MCP JSON-RPC request ID propagated through each async execution handoff and attached to each syscall. We have not run AgentSight against our fixtures, so this is a scope distinction, not a comparative failure claim. |
| [Agent-Warden](https://arxiv.org/abs/2609.38245) | Tracks process and regular-file state in the kernel and reconstructs process/file causal edges, including cross-process file-mediated propagation. | It supplies kernel-native process/file provenance for agents. The abstract describes process/file state, not MCP request-level attribution or shared TCP stream request IDs. We have not run it here. |
| [CamFlow](https://camflow.org/) | Captures whole-system provenance through Linux Security Module and NetFilter hooks and exports provenance records for graph reconstruction. | It can provide system/object provenance context that complements request identity. This repository has not installed or benchmarked CamFlow, and does not assume its graph directly contains MCP dispatch identity. |
| [SPADE](https://github.com/ashish-gehani/SPADE) | Provides provenance collection, filtering, storage, and querying; its Linux Audit reporter consumes system audit events. | It is a system-level provenance substrate, not an MCP protocol adapter in this experiment. We have not benchmarked SPADE here. |
| [OpenTelemetry context propagation](https://opentelemetry.io/docs/concepts/context-propagation/) | Carries trace context across instrumented service boundaries using propagators and carriers. | This is a useful model for explicit identity propagation. It does not by itself observe or attribute kernel syscalls; application/runtime instrumentation and a trusted mapping to kernel observations are still required. External context must not be treated as authoritative identity without validation. |

## Causpan's measured boundary

The current prototype assigns an internal context at MCP server dispatch and
propagates it through tested Node/libuv and Rust/Tokio execution paths. The
collector captures syscall records with `strace`; offline analysis links those
records to request contexts and preserves candidate sets when a shared effect
has several possible request owners. The experiment includes dedicated and
shared inbound/outbound TCP streams, subprocesses, background work, async
handoffs, batching, and forged client metadata. See [runtime findings](runtime-findings.md)
for the measured matrices and independent oracle results.

The shared-stream result matters: a single aggregate read can carry data for
many concurrent MCP calls. The graph records all request candidates rather than
inventing a unique owner. Where a protocol or runtime exposes stronger framing
identity, an adapter could refine that candidate set; this prototype does not
infer such identity from syscall timing or payload text.

## Claims this work does not make

- We did not run eBPF, CamFlow, SPADE, AgentSight, or Agent-Warden on these
  workloads. The available host denied syscall tracepoint access to the current
  user, so the measured collector is `strace`/ptrace.
- The prototype is not a tamper-resistant kernel security monitor. It trusts
  server/runtime instrumentation and its marker records.
- Execution-context attribution is not arbitrary data-flow provenance. A
  request context says which logical execution was active at a syscall boundary;
  it does not prove that specific bytes read caused specific bytes written.
- Shared queues, batching, long-lived child servers, TLS/HTTP2 stream framing,
  unsupported runtimes, and less common descriptor producers need explicit
  adapters or remain ambiguous/unknown. Basic socket descriptor copy/share
  semantics for process creation and `CLONE_FILES` are modeled, but the latter
  currently has synthetic trace regression coverage rather than a live MCP
  workload.

These boundaries define the next experiments: compare a kernel provenance
collector with the same request-level fixtures, test application-context handoff
into supported kernel mechanisms, and measure precision, candidate-set size,
coverage, event loss, and overhead independently.
