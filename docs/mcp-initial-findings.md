# Initial MCP attribution findings

Measured on 2026-10-06 UTC using the environment described in [the experiment guide](mcp-experiment.md). These are single-run observations, not statistical performance estimates. Dependencies are pinned in `experiments/mcp/package-lock.json`. Compact reports are retained in `experiments/mcp/evidence/`; full local captures are in `results/mcp/`.

## Completed runs

| Run directory | Driver | MCP calls | Selected fixture syscalls | Timing singletons | Timing ambiguous | Unique-path oracle labels |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| `serial` | Deterministic, concurrency 1 | 4 | 16 | 16 | 0 | 16 |
| `concurrent` | Deterministic, concurrency 8 | 32 | 128 | 0 | 128 | 128 |
| `shared` | Deterministic, concurrency 8, one shared file | 32 | 128 | 1 | 127 | 0 |
| `agent-complete` | Real Codex LLM, two overlapping reads, write, read-back | 4 | 16 | 8 | 8 | 8 |

All four runs completed with zero MCP errors and zero unfinished requests. Every selected event was ambiguous under PID-only attribution. The sequential run's 16 timing singletons agreed with the oracle. The concurrent unique-file run included the correct request in all 128 candidate sets, but none was uniquely attributable by timing. Shared-file singletons cannot be independently scored with this oracle.

The real agent successfully used `read_text_file`, `read_text_file`, `write_file`, and `read_text_file`. Its transcript was checked for successful MCP operations and absence of shell command execution. The eight overlapping-read events were oracle-labelled but timing-ambiguous; the other eight events had singleton timing candidates but no unique-path label because the summary path was used twice.

The selected counts include syscall **attempts**, including routine failed path probes; they do not imply that every syscall changed filesystem state. The trace also contains thousands of startup/runtime/transport events excluded from this limited scoring subset. Each report provides both total parsed and selected event counts. In these captures, all timestamped lines were either parsed syscalls or explicitly classified lifecycle records; no parser-loss category was reported.

## A concrete identity gap in the real agent run

MCP request 3 read `call-1-0.txt`; request 2 read `call-0-0.txt`. Both requests were in flight during the following events (paths shortened for readability):

| Epoch timestamp, ns | Linux TID | Syscall | Unique-path oracle request | Timing candidates |
| --- | ---: | --- | ---: | --- |
| 1791269943736664000 | 2882152 | readlinkat(call-1-0.txt) | 3 | 3, 2 |
| 1791269943736716000 | 2882154 | readlinkat(call-0-0.txt) | 2 | 3, 2 |
| 1791269943737392000 | 2882145 | openat(call-1-0.txt) | 3 | 3, 2 |
| 1791269943737483000 | 2882149 | openat(call-0-0.txt) | 2 | 3, 2 |
| 1791269943738872000 | 2882145 | read(fd for call-1-0.txt) | 3 | 3, 2 |
| 1791269943739035000 | 2882149 | read(fd for call-0-0.txt) | 2 | 3, 2 |
| 1791269943739194000 | 2882152 | close(fd for call-1-0.txt) | 3 | 3, 2 |
| 1791269943739303000 | 2882152 | close(fd for call-0-0.txt) | 2 | 3, 2 |

All belong to process 2880919. **One request crosses worker threads, and one worker thread performs operations for both requests.** This is direct evidence that neither the server PID nor a permanent TID-to-request association is sufficient for this workload. The raw syscall records contain no MCP request ID; IDs in this table come from a separate, workload-specific oracle.

Inspect `results/mcp/agent-complete/timeline.csv` alongside `tool-calls.jsonl` and `traces/strace.<tid>`. `attribution.jsonl` links each normalized event to its raw trace filename and line. Request 3's read and request 2's read are real model-issued operations, not an assumed concurrency pattern.

## Gaps now demonstrated

1. **Boundary identity is not execution identity.** JSON-RPC supplies request IDs, while worker syscall records supply PID/TID. The protocol recorder supplies intervals but no binding across dispatch and libuv work submission.
2. **Time overlap prevents a unique answer.** The concurrency control makes the failure repeatable without relying on a model to choose parallel calls.
3. **Resource names are an experimental oracle, not a general solution.** Shared-file requests produce events that a path join cannot uniquely label. Reuse occurs even in the basic agent write/read-back task.
4. **Protocol success is not complete kernel provenance.** Background effects, delayed work, subprocesses, and events without decoded paths remain outside the scored subset.

These are measured limitations of the implemented baselines. They are not claims that every existing provenance product fails, or that a new attribution design is already reliable. The [guide](mcp-experiment.md) distinguishes adjacent systems, existing Rust evaluation issues, and the next instrumentation experiments.

## Next experiment

Instrument MCP dispatch and libuv async work submission/execution with separate request IDs and work IDs. First use this only as evaluation ground truth for shared-file requests. Then evaluate a candidate context-propagation mechanism at syscall time with explicit unknown results, thread handoff, context restoration, and leakage checks. Extend to background work, cancellation, and child processes before claiming end-to-end attribution.
