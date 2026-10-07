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

# Preserve each run; never clean files from an earlier experiment.
mkdir -p results/mcp
RUN_DIR=$(mktemp -d "results/mcp/smoke-test.XXXXXX")
GT="$RUN_DIR/ground-truth.jsonl"
STRACE_DIR="$RUN_DIR/traces"
KE="$RUN_DIR/kernel-events.jsonl"
EVAL="$RUN_DIR/attribution.csv"
DATA_DIR="$RUN_DIR/sandbox"
mkdir -p "$STRACE_DIR" "$DATA_DIR" results

# Step 1: Capture strace while the workload generates ground truth.
# Ground truth and kernel observations come from the same execution.
echo "[1/3] strace: capturing kernel events + ground truth..."
strace -f -ff -ttt \
    -e trace=openat,read,write,socket,connect,clone,fork,execve \
    -o "$STRACE_DIR/strace" \
    ./target/release/workload \
    --concurrency 1 \
    --operations-per-rpc 4 \
    --seed 42 \
    --output "$GT" \
    --data-dir "$DATA_DIR" \
    --scenario mixed \
    --worker-threads 2

echo "  Ground truth lines: $(wc -l < "$GT")"
echo "  Strace files: $(ls "$STRACE_DIR"/ 2>/dev/null | wc -l)"

# Step 2: Collect kernel events.
echo "[2/3] collector: normalising strace..."
cargo run --release --bin collector -- \
    --format straces \
    --data-dir "$DATA_DIR" \
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
