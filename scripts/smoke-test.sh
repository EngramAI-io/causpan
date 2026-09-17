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

# Build all binaries.
echo "[build] cargo build --release..."
cargo build --release --bin workload --bin collector --bin evaluator
echo ""

# Output paths.
GT="ground-truth.jsonl"
STRACE_DIR="strace-output"
KE="kernel-events.jsonl"
EVAL="results/smoke-test.csv"

mkdir -p "$STRACE_DIR" results

# Step 1: Generate ground truth.
echo "[1/4] workload: generating ground truth..."
cargo run --release --bin workload -- \
    --concurrency 1 \
    --operations-per-rpc 4 \
    --seed 42 \
    --output "$GT" \
    --scenario mixed \
    --worker-threads 2

echo "  Ground truth lines: $(wc -l < "$GT")"

# Step 2: Capture strace.
echo "[2/4] strace: capturing kernel events..."
strace -ff -tt \
    -e trace=openat,read,write,socket,connect,clone,fork,execve \
    -o "$STRACE_DIR/strace" \
    ./target/release/workload \
    --concurrency 1 \
    --operations-per-rpc 4 \
    --seed 42 \
    --output /dev/null \
    --scenario mixed \
    --worker-threads 2 \
    2>/dev/null || true

echo "  Strace files: $(ls "$STRACE_DIR"/ 2>/dev/null | wc -l)"

# Step 3: Collect kernel events.
echo "[3/4] collector: normalising strace..."
cargo run --release --bin collector -- \
    --format straces \
    "$STRACE_DIR" \
    "$KE"

echo "  Kernel events: $(wc -l < "$KE")"

# Step 4: Evaluate.
echo "[4/4] evaluator: running attribution strategies..."
cargo run --release --bin evaluator -- \
    --ground-truth "$GT" \
    --kernel-events "$KE" \
    --output "$EVAL" \
    --time-windows-ms 1,5,10,50,100,500,1000

echo ""
echo "=== Smoke test complete ==="
echo "Results: $EVAL"
echo ""
cat "$EVAL"
