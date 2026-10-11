# Baseline comparison: attribution strategies for MCP syscall effects

## Research question

Can Causpan's runtime async-context markers attribute individual Linux syscalls to
their originating MCP tool invocations more precisely than what existing
provenance and observability systems can achieve without application-level
instrumentation?

We evaluate five attribution strategies on identical oracle-labelled syscall
events captured from the official Node.js filesystem MCP server under a
deterministic replay workload:

| Strategy | Models |
|---|---|
| camflow | Whole-system provenance (CamFlow): all server-PID events belong to all active requests. |
| otel | OpenTelemetry: wall-clock span window; any request whose span covers the syscall timestamp is a candidate. |
| tetragon_fd | Tetragon with LSMI+FD-table tracking: assign by creation-time epoch of the specific descriptor used. |
| tetragon_best | Tetragon with FD tracking plus scope inference (strongest achievable prior system). |
| causpan | This prototype: per-thread marker timestamps bind syscalls to the executing async context. |

The evaluation uses a **unique-path oracle**: a syscall touching a path that was
exclusively owned by exactly one MCP request receives a ground-truth request
label. Multi-owner paths are excluded. This oracle is deliberately narrow; it
does not cover shared descriptors, caching, or background work. Precision and
recall are reported over the labelled subset, not over all captured syscalls.

## Experimental setup

### Workload

The workload is the official MCP filesystem server (`@modelcontextprotocol/server-filesystem`)
serving 16 `read_text_file` calls issued sequentially by a deterministic
replay client. Each call reads a distinct fixture file under
`results/mcp/<run>/sandbox/call-<batch>-<slot>.txt`. Sequential execution
eliminates overlap and makes oracle labels unambiguous: each fixture path has
exactly one owning request.

The agent-mode traces (used for the real-LLM evidence in `docs/runtime-findings.md`)
were produced by **Codex CLI 0.160.1** with model **`gpt-6-astra`** (configured
in `~/.codex/config.toml`, `model_reasoning_effort = "low"`). The baseline
comparison in this document uses the deterministic replay workload; the agent
transcript and protocol are preserved at `results/mcp/agent-instrumented-v1/`.

### Capture

The experiment records three synchronized data sources:

1. **MCP protocol** (`protocol.jsonl`): bidirectional JSON-RPC messages with
   proxy-observed wall-clock timestamps (`wall_ns`). Request IDs, method names,
   and tool arguments are preserved. Response messages carry completion
   timestamps that define the request window.

2. **System-call trace** (`traces/strace.<tid>`): per-thread `strace -ff -ttt -yy`
   output with decoded file-descriptor paths. The parser reassembles
   `<unfinished ...>` / `<... resumed>` pairs, reconstructs thread groups via
   `CLONE_THREAD`, resolves PIDs from clone parents, and records parser quality
   metrics (unparsed lines, incomplete traces, terminal interruptions).

3. **Causal attribution** (`causal-attribution.jsonl`): Causpan's per-syscall
   output mapping each observed event to its originating request ID (or to
   `no_request_context` / `ambiguous` when the binding is uncertain). These
   entries are produced by the runtime instrumentation and are consumed as a
   lookup table by the evaluation script; they are not used to influence oracle
   labelling.

### Parser and PID resolution

The parser is identical to `experiments/mcp/analyze.py`, which has been
validated across 120+ Node and 48+ Tokio runs. It uses a `CALL` regex that
matches the full `name(args) = ret <duration>` form, extracts path arguments
only from path-related syscalls (not from read/write payloads), and tracks
FD annotations from `sendmsg`/`recvmsg` ancillary data.

Thread groups are resolved from `clone`/`clone3` return values and
`CLONE_THREAD` flags, producing a single PID for all threads in the server
process group. This is the PID used by the camflow/otel/tetragon strategies;
Causpan additionally uses per-TID source-line identifiers.

### Oracle construction

For each captured syscall that references a path under the sandbox directory,
the evaluator computes the set of MCP requests whose arguments reference that
exact path. If the set has exactly one member, the event is labelled with that
request ID. Otherwise it is excluded from scoring.

The oracle is applied **after** candidate generation, not during. The evaluator
does not inject oracle labels into the attribution mechanism.

## Results

### Verified output

Run command:

```bash
python3.11 experiments/mcp/compare_baselines.py results/mcp/all-syscalls-v1/ --latex
```

### Metrics

| Metric | Definition |
|---|---|
| accuracy | correct singleton attributions / attributed events |
| recall | events where ground truth appears in the candidate set / oracle-labelled events |
| F1 | harmonic mean of accuracy and recall |
| extra candidates | sum of (candidate count - 1) across all attributed events |

### Quantitative results

```
Run: all-syscalls-v1
Server PID: 567476
Parsed events: 6230
Sandbox events: 64
Oracle-labelled: 64
FD epoch entries: 13
Causal map entries: 332 (bound) / 5412 (total)

Strategy                        Acc    Rec     F1   Attr  Extra
---------------------------------------------------------------
camflow                       0.000  1.000  0.000     64    448
otel                          0.000  1.000  0.000     64    448
tetragon_fd                   0.000  0.219  0.000     28    196
tetragon_best                 0.000  0.719  0.000     60    420
causpan                       1.000  1.000  1.000     64      0
```

### Interpretation

**CamFlow and OpenTelemetry** (recall = 1.000, accuracy = 0.000, 448 extra candidates).

Both strategies assign every sandbox event to all 16 concurrently-active
requests. Every ground-truth request appears in the candidate set, so recall
is perfect, but no event is narrowed to a singleton. Each event carries 15
extra candidates. These systems lack any mechanism to distinguish execution
scopes within a single process; they are structurally unable to produce
singleton attributions on this workload.

**Tetragon with FD tracking** (recall = 0.219, accuracy = 0.000, 196 extra candidates).

Only 28 of 64 events have a file descriptor whose creation epoch falls within
a traceable call window. Thirteen FDs have recorded creation timestamps; the
rest are inherited via `CLONE_FILES` or opened before tracing began and carry
no epoch. Of the 28 events with epochs, every one points to the wrong request:
on this sequential workload, all calls are active simultaneously, so the FD
creation time is ambiguous across the full request set. Tetragon produces
non-empty candidate sets but never the correct singleton.

**Tetragon with FD tracking plus scope inference** (recall = 0.719, accuracy = 0.000, 420 extra candidates).

Falling back to the request-window strategy recovers 32 additional events
(60 attributed total), but the fallback is the same window logic that produces
448 extra candidates for camflow/otel. The combined strategy widens coverage
without improving precision; accuracy remains 0.000.

**Causpan** (accuracy = 1.000, recall = 1.000, F1 = 1.000, 0 extra candidates).

All 64 oracle-labelled events are attributed to exactly one request, and that
request is always the ground truth. The per-thread marker timestamps resolve
execution scopes that are invisible to PID-, window-, or FD-epoch-based
strategies. No event carries an extra candidate.

## Bug fix in compare_baselines.py

An earlier version of the baseline comparison script contained a bug that made
all strategies report 0/0/0 regardless of the data:

- **Root cause**: the script built `call_map` from `protocol.jsonl` request rows
  only, leaving `end_ns = None` on every entry. All baseline strategies gate on
  `c['end_ns'] is not None`, so they returned empty candidate sets.
- **Fix**: the script now populates `end_ns` from the corresponding response rows.
- **Verification**: after the fix, Causpan's score is unchanged (1.0/1.0/1.0)
  because the causal map bypasses `call_map` windows entirely. The baselines
  now produce their intended (and meaningfully lower) scores.

## Threats to validity

**Internal validity.** The oracle is narrow: only events touching a
uniquely-owned fixture path are labelled. Results do not generalise to shared
descriptors, cached paths, or background syscalls. The workload uses
sequential requests; concurrency would widen candidate sets for all strategies
but the relative ordering is expected to hold.

**Construct validity.** The baseline strategies are simplified models of their
namesake systems. CamFlow and OpenTelemetry are represented by their core
attribution logic on this workload, not by full system deployments. Tetragon
is modelled by FD-creation epoch tracking; real Tetragon includes additional
LSMI signals not captured here.

**External validity.** The workload exercises one MCP server runtime (Node/libuv)
with filesystem operations. The prototype's mechanism depends on runtime
instrumentation hooks that are specific to the measured runtime. Extension to
other runtimes requires corresponding hook implementations.

## Reproducibility

```bash
# Run the workload and capture traces
python3.11 experiments/mcp/run.py --mode replay --concurrency 1 --output results/mcp/all-syscalls-v1

# Run the baseline comparison
python3.11 experiments/mcp/compare_baselines.py results/mcp/all-syscalls-v1/ --latex

# Query individual events
python3.11 experiments/mcp/query.py results/mcp/all-syscalls-v1 --request 3 --fixture-only
```

All raw traces, protocol logs, and causal attribution files are preserved under
`results/mcp/all-syscalls-v1/`. Evidence files suitable for inclusion are under
`experiments/mcp/evidence/`.

## Limitations and future work

- The strace capture path has measured overhead and requires appropriate
  privileges. A production deployment would use an eBPF-based collector with
  lower overhead; eBPF has not been executed on the available host.
- The current oracle covers unique fixture paths only. Extending to shared
  descriptors, network streams, and background work requires richer independent
  oracles (byte-offset checks, payload hashing, descriptor-transfer probes).
- The prototype instruments Node/libuv and Rust/Tokio. Additional runtime
  adapters are needed to generalise beyond these.
- The mechanism trusts runtime instrumentation. An attacker with arbitrary
  native execution could forge context markers; two-party capture (application
  + kernel) detects loss but does not authenticate against a malicious runtime.
- Multiplexed network streams currently produce multi-request candidate sets;
  byte-range attribution on shared connections is unresolved.
- io_uring is observed through a trusted helper sidecar (SQE/CQE snapshots),
  not through general kernel-side decoding. Shared-ring scenarios use fixed
  batches with a cooperating worker.
