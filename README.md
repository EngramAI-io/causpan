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

Causpan approaches this experimentally — building ground-truth workloads, capturing kernel observations, and measuring how well existing attribution baselines (PID, TID, temporal window) perform as concurrency increases.

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

### Run a workload

```bash
./target/release/workload --concurrency 8 --operations-per-rpc 4 --output ground-truth.jsonl
```

### Capture strace

```bash
strace -ff -ttt \
  -e trace=openat,read,write,socket,connect,clone,fork,execve \
  -o strace \
  ./target/release/workload \
  --concurrency 8 --operations-per-rpc 4 --output /dev/null
```

### Normalise strace

```bash
./target/release/collector --format straces --input strace --output kernel-events.jsonl
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

1. **Ground truth is authoritative and isolated.**  Attribution strategies never see RPC IDs during "inference" — the evaluator assigns them after the fact.
2. **Unique resources per RPC.**  Each request uses distinct file paths and network targets so the evaluator can independently verify correctness.
3. **No predetermined solution.**  The project measures failure modes first; the attribution mechanism is designed only after the problem is quantified.
4. **Rust/Tokio first.**  Multi-runtime support (Python asyncio, Go, etc.) is out of scope for v0.1.

## Development Philosophy

```text
1. Ground truth
2. Kernel observation
3. Baseline attribution
4. Demonstrate failure
5. Understand failure
6. Design Causpan mechanism  ← future work
7. Evaluate mechanism
8. Stress / adversarial testing
9. MCP integration
10. Real security workloads
```

## License

MIT
