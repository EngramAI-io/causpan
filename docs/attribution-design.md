# Runtime-bound MCP attribution prototype

This implementation binds MCP request contexts to observed Linux syscall execution in a trusted, instrumented Node process. It is an experimental mechanism for the tested runtime, not a production security boundary or a complete whole-system information-flow tracker.

## Mechanism

1. An ESM preload intercepts the MCP SDK's request dispatch. For each `tools/call`, it assigns an internal context ID and records the relation to the session's JSON-RPC ID. Tool-provided `_meta` is not used as authority.
2. `AsyncLocalStorage` propagates that context through JavaScript promises and callbacks. Async hooks install the corresponding native thread-local context before callback execution and restore the previous context afterward. Nested scopes require restoration, not clearing.
3. A native addon intercepts libuv work submission, preserving `(context ID, unique work ID, original callbacks)` until completion. The work object's address is a temporary lookup key, not its identity: addresses can be reused immediately after completion.
4. Worker wrappers install the saved context before executing the original work function and restore it afterward. Completion wrappers preserve context while callbacks execute, then release the record. Cancellation completes a work record without a worker-execution bracket.
5. Context transitions are emitted as bounded writes to a dedicated file. `strace -ff -yy` observes these transitions on the same Linux TID as the measured syscalls. The offline attributor follows each thread's transitions; it does not infer ownership from filenames, contents, or request timing windows.
6. A kernel-observed process-creation event can carry the active request into a one-shot child process. This is explicitly labelled `process_inheritance`: it identifies the initiating request, and is not evidence of per-request separation inside a long-lived child server.
7. The graph records request → async work → syscall → observed resource relations, plus process-creation edges. Request and work nodes are session-scoped. Resource names are paths or decoded FD annotations, not stable inode identities or file versions.

## Reproduce

```bash
npm ci --prefix experiments/mcp
python3.11 experiments/mcp/native/build.py
python3.11 -m unittest discover -s experiments/mcp -v
python3.11 experiments/mcp/run.py --instrumented --shared --concurrency 8
python3.11 experiments/mcp/run.py --instrumented --scenario slots --concurrency 8
python3.11 experiments/mcp/run.py --instrumented --scenario nested --concurrency 8
python3.11 experiments/mcp/run.py --instrumented --scenario detached --concurrency 8
python3.11 experiments/mcp/run.py --instrumented --scenario spawn --concurrency 8
python3.11 experiments/mcp/run.py --instrumented --scenario cancel --concurrency 8 --pool-size 1
python3.11 experiments/mcp/run.py --instrumented --scenario failure --concurrency 8
python3.11 experiments/mcp/run.py --instrumented --scenario fileops --concurrency 8
python3.11 experiments/mcp/run.py --instrumented --mode agent
```

The native prototype currently requires the verified Linux AArch64, non-PIE Node 24.20.0 / libuv 1.52.1 binary. It checks runtime version, executable hash, ELF architecture/type, and the exact instruction prologues before modifying **in-memory** function entry points. It does not modify the installed Node executable. Other builds are rejected rather than guessed. This binary-specific technique enabled unprivileged experiments on the available host; a portable deployment should add explicit runtime hooks or use supported instrumentation, not depend on these prologues.

`uv_queue_work` needs its own hook because this optimized binary inlines the internal submission function there. This was discovered by a failing cancellation test, not assumed from source-level function names. The native addon also contains a small controlled `uv_queue_work` workload for exercising cancellation and failed writes. That test workload is separate from the attribution wrappers used with the official filesystem server.

## Evidence and evaluation

Instrumented runs add `request-map.jsonl`, `native-events.jsonl`, `causal-attribution.jsonl`, `causal-report.json`, and `provenance.jsonl`. Later runs also archive their source files and source/native-library hashes under `code/` and in the manifest. Raw traces are retained. Files under `results/mcp/` are ignored by Git; compact findings can be promoted to `experiments/mcp/evidence/`.

```bash
# Use the actual run directory printed by the runner.
python3.11 experiments/mcp/query.py RUN --request 3 --fixture-only
python3.11 experiments/mcp/query.py RUN --event strace.123:42
```

The offset oracle in the controlled server uses `pread64`/`pwrite64` byte offsets on one shared file and, for normal request I/O, one shared descriptor. Each request owns an independently known slot. Background work uses another slot. These offsets are used only by the evaluator, never by inference. The cancellation oracle additionally checks which jobs actually completed and requires canceled jobs to have no corresponding write. Failed write attempts count as attempted effects, not successful mutations.

`causal-report.json` validates structural capture consistency; `control-score.json` independently checks attribution when that oracle is available. A successful run requires both. A reported binding without an independent oracle is a mechanism output, not a measured accuracy claim.

## Fail-closed checks

The attributor checks that dispatch mappings agree with captured MCP calls, work IDs do not collide, operations have observed completion, successful operations have worker-execution brackets, and canceled operations were not executed. Per-thread marker sequences must exactly match the separate native log. Unparsed or truncated trace records invalidate the capture. Invalid captures produce no provenance graph and publish no request bindings.

Ordinary interrupted syscalls are represented with a restart status and an unknown return value, rather than silently dropped or treated as successful operations. The raw trace remains the authority for syscall details.

[MCP request IDs must be unique within a session](https://modelcontextprotocol.io/specification/2025-11-25/basic). The analyzer rejects reuse and invalid ID types rather than overwriting an earlier invocation. Numeric and string IDs are supported; the internal context is always separately assigned.

## Current boundaries

- The defender must trust the instrumentation and the relevant runtime/application integration. An attacker with arbitrary native execution in the server could forge or tamper with userspace records. Matching two captured copies detects capture loss; it is not cryptographic authenticity against that attacker.
- This collector uses ptrace and synchronous marker writes. Both perturb scheduling; overhead is measured separately with and without strace. It is not an eBPF performance claim.
- Coverage is the explicitly traced syscall classes and propagated runtime paths. Startup, unrelated background work, unknown contexts, and unsupported propagation remain explicit.
- Request identity at execution time is distinct from arbitrary data-dependency provenance. Shared queues, batching, reused network connections, long-lived child servers, and custom schedulers can require multiple parents or additional instrumentation.
- No `io_uring`, arbitrary mmap information flow, cross-host identity, or container identity claim is made. Path/FD resource observations do not resolve hard links, rename history, inode reuse, or content versions.
- The real agent transcript and MCP protocol are both saved. Identical concurrent calls in an uninstrumented client cannot always be uniquely mapped from the agent's own item IDs to JSON-RPC IDs by arguments alone. The reliable root here is the captured MCP session/request identity.

The underlying runtime behavior is documented in [libuv's threadpool implementation](https://raw.githubusercontent.com/libuv/libuv/v1.52.1/src/threadpool.c) and [Node's asynchronous context API](https://nodejs.org/api/async_context.html). Those sources motivate the hook boundaries; correctness claims come from the captured workloads and independent checks.
