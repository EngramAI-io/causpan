# Causpan

**Causal attribution of kernel-level side effects to individual logical requests in concurrent asynchronous applications.**

Causpan is a research prototype that investigates whether kernel events (file access, network connections, process creation) can be reliably attributed to individual logical requests when those requests are multiplexed over shared OS processes and threads — the common case in modern async servers such as Tokio-based services and MCP servers.

## The Problem

```text
RPC A ─┐
RPC B ─┼──> Tokio async runtime ──> Linux threads ──> syscalls
RPC C ─┘
```

At the application layer, A, B, and C are distinct logical requests with independent identities, purposes, and trust levels.  At the kernel layer, observability systems see only PIDs, TIDs, timestamps, and syscall types — with no inherent knowledge of which logical task caused each side effect.

Asynchronous interleaving makes this worse:

```text
RPC A executes ──> yield ──> RPC B executes ──> RPC A resumes ──> openat(...)
```

The same Linux thread may execute pieces of several logical requests over a short period.

**Tokio task ≠ Linux task_struct**

## Research Question

> Can kernel effects be reliably attributed to individual logical requests when concurrent requests share processes and execution threads?

Causpan approaches this experimentally — building ground-truth workloads, capturing kernel observations, measuring PID/window baselines, and testing runtime context propagation from MCP dispatch through asynchronous work to observed syscalls. The current Node/libuv and Rust/Tokio bridges are experimental and depend on trusted runtime/application instrumentation; they are not a universal kernel provenance collector.

## Repository Structure

```
causpan/
├── Cargo.toml              # Workspace definition
├── README.md
├── crates/
│   ├── causpan-core/       # Shared types (events, identities, errors)
│   ├── workload/           # Tokio workload generator + ground-truth producer
│   ├── collector/          # strace → KernelEvent JSONL normaliser
│   └── evaluator/          # Attribution strategies + metrics
├── experiments/            # Experiment configurations
├── scripts/                # Run/plot helpers
├── results/                # Experimental output (gitignored)
└── docs/                   # Research notes
```

## Quick Start

### Prerequisites

- Rust ≥ 1.75
- Tokio runtime
- `strace` (for the initial collector)

### Build

```bash
cargo build --release
```

### Capture strace and ground truth in the same execution

```bash
mkdir -p /tmp/causpan-traces /tmp/causpan
strace -ff -ttt \
  -e trace=%file,%process,%desc,%network \
  -o /tmp/causpan-traces/strace \
  ./target/release/workload \
  --data-dir /tmp/causpan --concurrency 8 --operations-per-rpc 4 \
  --output ground-truth.jsonl
```

### Normalise strace

```bash
./target/release/collector --format straces --data-dir /tmp/causpan \
  /tmp/causpan-traces kernel-events.jsonl
```

### Evaluate

```bash
./target/release/evaluator \
  --ground-truth ground-truth.jsonl \
  --kernel-events kernel-events.jsonl \
  --time-windows-ms 1,5,10,50,100,500,1000
```

## Initial Attribution Strategies

| Strategy | Info Used | Expected Weakness |
|---|---|---|
| **PID** | Linux PID only | Fails when multiple RPCs share a PID |
| **PID+TID** | PID + Linux TID | Fails when RPCs interleave on the same thread |
| **Time Window** | PID + TID + temporal proximity | Window size is a guess; fails under high concurrency |

## Experimental Pipeline

```text
Tokio workload (N concurrent logical requests)
        │
        ├──▶ ground-truth.jsonl  (authoritative RPC identity)
        │
strace ──┤
        │
        ▼
collector
        │
        ▼
kernel-events.jsonl  (PID, TID, timestamp, syscall)
        │
        ▼
evaluator
        │
        ▼
attribution.csv  (precision, recall, F1 per strategy)
```

## Key Design Decisions

1. **Isolate scoring from inference.** The MCP pipeline implements this separation. The legacy Rust evaluator still loads ground truth into its strategies and labels its exports `oracle_assisted_*`; those scores are diagnostic only.
2. **Separate inference from its oracle.** Unique file paths, write payloads, and TCP payloads provide independent labels only after attribution in the MCP experiment.
3. **Measure failure modes first.** The runtime mechanism follows from controlled counterexamples and independent evaluation.
4. **Node and Rust/Tokio experiments.** Python asyncio, Go, and arbitrary custom schedulers are not covered by the current bridges.

## Development Philosophy

```text
1. Ground truth
2. Kernel observation
3. Baseline attribution
4. Demonstrate failure
5. Understand failure
6. Build runtime identity bridges  ← experimental Node/libuv and Rust/Tokio paths implemented
7. Evaluate with independent oracles
8. Stress failure boundaries and ambiguous shared effects
9. Compare kernel provenance collectors
10. Test real security workloads
```

## License

MIT

## MCP experiment with a real LLM agent

A separate [MCP experiment guide](docs/mcp-experiment.md) sets up Codex, the official
filesystem MCP server, a JSON-RPC recorder, and per-thread syscall capture. It includes
sequential, concurrent, and shared-file controls with oracle labels kept separate from
attribution. See [runtime findings and reproduction](docs/runtime-findings.md) for
the implemented Node/libuv and Rust/Tokio bridges, the original 212-case runtime
matrices plus a fresh 36-case descriptor regression matrix, multi-parent and network
provenance (including shared inbound streams at concurrency 256), measured overhead,
and remaining limitations. The [initial findings](docs/mcp-initial-findings.md) preserve the baseline experiments;
the [attribution design](docs/attribution-design.md) explains the Node prototype.

The original workload/evaluator above is an early scaffold: its oracle isolation
still needs correction, and separately executed workload/capture runs cannot be
joined by PID and time. Use the MCP pipeline for the validated experiments.
Related kernel provenance and agent observability systems are scoped in
[docs/related-systems.md](docs/related-systems.md); they have not been benchmarked
in this repository.
