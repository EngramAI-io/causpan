#!/usr/bin/env bash
# run-experiment.sh — run a Causpan experiment end-to-end.
#
# Usage:
#   ./scripts/run-experiment.sh <experiment-config.toml>
#
# For each workload configuration, the script:
#   1. Builds the workload and collector binaries.
#   2. Runs the workload to produce ground-truth JSONL.
#   3. Captures strace output.
#   4. Runs the collector to normalise strace → kernel-events JSONL.
#   5. Runs the evaluator and appends results to a summary CSV.
#
# Requires: strace, cargo, bash ≥ 4.

set -euo pipefail

if [ $# -lt 1 ]; then
    echo "Usage: $0 <experiment-config.toml>"
    exit 1
fi

CONFIG="$1"
EXPERIMENT_NAME=$(basename "$CONFIG" .toml)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=== Causpan experiment: $EXPERIMENT_NAME ==="
echo "Config: $CONFIG"
echo ""

cd "$PROJECT_ROOT"

# Build.
echo "[build] building binaries..."
cargo build --release --bin workload --bin collector --bin evaluator
echo ""

# Parse TOML config (simple grep for key values — replace with a proper
# TOML parser once the experiment framework is built).
# For now, we use a helper script or manual configuration.

CONCURRENCIES=("1" "2" "4" "8" "16" "32" "64")
SEED=42
OPS_PER_RPC=4
SCENARIO="mixed"
RUNS=5

GT_DIR="results/${EXPERIMENT_NAME}/ground-truth"
KE_DIR="results/${EXPERIMENT_NAME}/kernel-events"
CSV_OUT="results/${EXPERIMENT_NAME}/summary.csv"

mkdir -p "$GT_DIR" "$KE_DIR"

# Write CSV header.
echo "concurrency,run,strategy,correct,wrong_rpc,unattributed,precision,recall,f1,wrong_rate,unattributed_rate" \
    > "$CSV_OUT"

TOTAL=$((${#CONCURRENCIES[@]} * RUNS))
CURRENT=0

for CONC in "${CONCURRENCIES[@]}"; do
    for RUN in $(seq 1 "$RUNS"); do
        CURRENT=$((CURRENT + 1))
        TAG="${EXPERIMENT_NAME}-c${CONC}-r${RUN}"
        GT_FILE="${GT_DIR}/${TAG}.jsonl"
        STRACE_FILE="${KE_DIR}/${TAG}.strace"
        KE_FILE="${KE_DIR}/${TAG}.jsonl"

        echo "[${CURRENT}/${TOTAL}] concurrency=${CONC} run=${RUN}"

        # 1. Run workload.
        echo "  [workload] generating ground truth..."
        ./target/release/workload \
            --concurrency "$CONC" \
            --operations-per-rpc "$OPS_PER_RPC" \
            --seed "$SEED" \
            --output "$GT_FILE" \
            --scenario "$SCENARIO" \
            --worker-threads 2

        # 2. Run strace.
        echo "  [strace] capturing kernel events..."
        strace -ff -ttt \
            -e trace=openat,read,write,socket,connect,clone,fork,execve \
            -o "$STRACE_FILE" \
            ./target/release/workload \
            --concurrency "$CONC" \
            --operations-per-rpc "$OPS_PER_RPC" \
            --seed "$SEED" \
            --output /dev/null \
            --scenario "$SCENARIO" \
            --worker-threads 2 \
            2>/dev/null || true

        # 3. Collect kernel events from strace.
        echo "  [collector] normalising strace..."
        ./target/release/collector \
            --format straces \
            --input "$STRACE_FILE" \
            --output "$KE_FILE"

        # 4. Evaluate.
        echo "  [evaluator] running strategies..."
        ./target/release/evaluator \
            --ground-truth "$GT_FILE" \
            --kernel-events "$KE_FILE" \
            --output "${CSV_OUT}.tmp" \
            --time-windows-ms 1,5,10,50,100,500,1000

        # Append to summary (prepend concurrency and run columns).
        if [ -f "${CSV_OUT}.tmp" ]; then
            # Skip header line.
            tail -n +2 "${CSV_OUT}.tmp" \
                | sed "s/^/${CONC},${RUN},/" \
                >> "$CSV_OUT"
            rm "${CSV_OUT}.tmp"
        fi

        echo ""
    done
done

echo "=== Experiment complete: $EXPERIMENT_NAME ==="
echo "Results: $CSV_OUT"
