#!/usr/bin/env bash
# Quick smoke test — run the full pipeline at concurrency=1.
# This is the first thing to verify before running the full experiment matrix.
#
# Usage:
#   ./scripts/smoke-test.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=== Causpan Smoke Test (concurrency=1) ==="
cd "$PROJECT_ROOT"

# Output paths.
GT="ground-truth.jsonl"
STRACE_DIR="strace-output"
KE="kernel-events.jsonl"
EVAL="results/smoke-test.csv"

# Clean stale outputs from previous runs.
rm -f "$KE" "$GT" "$STRACE_DIR"/strace.*
mkdir -p "$STRACE_DIR" results

# Step 1: Capture strace while the workload generates ground truth.
# Running under strace means PID/TID will match between ground truth and
# kernel observations (same execution, same process).
echo "[1/3] strace: capturing kernel events + ground truth..."
rm -f "$KE" "$GT" "$STRACE_DIR"/strace.*
strace -f -ff -ttt \
    -e trace=openat,read,write,socket,connect,clone,fork,execve \
    -o "$STRACE_DIR/strace" \
    ./target/release/workload \
    --concurrency 1 \
    --operations-per-rpc 4 \
    --seed 42 \
    --output "$GT" \
    --scenario mixed \
    --worker-threads 2 \
    2>/dev/null || true

echo "  Ground truth lines: $(wc -l < "$GT")"
echo "  Strace files: $(ls "$STRACE_DIR"/ 2>/dev/null | wc -l)"

# Step 2: Collect kernel events.
echo "[2/3] collector: normalising strace..."
cargo run --release --bin collector -- \
    --format straces \
    --data-dir /tmp/causpan \
    "$STRACE_DIR" \
    "$KE"

echo "  Kernel events: $(wc -l < "$KE")"

# Step 3: Evaluate.
echo "[3/3] evaluator: running attribution strategies..."
cargo run --release --bin evaluator -- \
    --ground-truth "$GT" \
    --kernel-events "$KE" \
    --output "$EVAL" \
    --time-windows-ms 1,5,10,50,100,500,1000 \
    --verbose

echo ""
echo "=== Smoke test complete ==="
echo "Results: $EVAL"
echo ""
cat "$EVAL"
