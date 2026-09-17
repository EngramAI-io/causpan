#!/usr/bin/env python3
"""Plot Causpan experiment results.

Reads aggregated-results.csv and produces:
  1. results/exp-{N}/accuracy_vs_concurrency.png  — precision/recall/F1 lines
  2. results/exp-{N}/wrong_rate_vs_concurrency.png — wrong-attribution rate

Usage:
    python scripts/plot-results.py <aggregated-results.csv> [output-dir]
"""

import sys
import os
import csv
from collections import defaultdict

def main():
    if len(sys.argv) < 2:
        print("Usage: plot-results.py <aggregated-results.csv> [output-dir]")
        sys.exit(1)

    csv_path = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else os.path.dirname(csv_path)

    # Check if matplotlib is available.
    try:
        import matplotlib
        matplotlib.use("Agg")  # non-interactive backend
        import matplotlib.pyplot as plt
    except ImportError:
        print("ERROR: matplotlib not installed. Install with: pip install matplotlib")
        sys.exit(1)

    # Read data.
    rows = []
    with open(csv_path, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)

    if not rows:
        print("No data in CSV.")
        sys.exit(1)

    # Group by strategy.
    strategies: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        strategies[row["strategy"]].append(row)

    concurrency = sorted(set(int(r["concurrency"]) for r in rows))

    # ── Plot 1: Precision, Recall, F1 vs concurrency ──

    fig, axes = plt.subplots(1, 3, figsize=(15, 5), sharex=True)
    metrics = ["precision", "recall", "f1"]
    titles = ["Precision", "Recall", "F1 Score"]

    # Color palette — same across all 3 subplots.
    strategy_names = sorted(strategies.keys())
    # Use a categorical palette that's distinguishable.
    import matplotlib.cm as cm
    colors = cm.get_cmap("tab10", len(strategy_names))
    color_map = {name: colors(i) for i, name in enumerate(strategy_names)}

    for ax, metric, title in zip(axes, metrics, titles):
        for name in strategy_names:
            data = sorted(strategies[name], key=lambda r: int(r["concurrency"]))
            x = [int(d["concurrency"]) for d in data]
            y = [float(d[f"{metric}_mean"]) for d in data]
            yerr = [float(d[f"{metric}_std"]) for d in data]

            ax.errorbar(
                x, y, yerr=yerr,
                label=name,
                color=color_map[name],
                marker="o",
                capsize=3,
                linewidth=1.5,
            )

        ax.set_xscale("log", base=2)
        ax.set_xticks(concurrency)
        ax.set_xticklabels([str(c) for c in concurrency])
        ax.set_xlabel("Concurrent logical requests")
        ax.set_ylabel(title)
        ax.set_ylim(-0.05, 1.05)
        ax.set_title(title)
        ax.legend(fontsize=7, loc="lower left")
        ax.grid(True, alpha=0.3)

    fig.suptitle("Attribution Accuracy vs Concurrency")
    fig.tight_layout()

    out1 = os.path.join(output_dir, "accuracy_vs_concurrency.png")
    fig.savefig(out1, dpi=150)
    plt.close(fig)
    print(f"Saved: {out1}")

    # ── Plot 2: Wrong attribution rate vs concurrency ──

    fig, ax = plt.subplots(figsize=(8, 5))

    for name in strategy_names:
        data = sorted(strategies[name], key=lambda r: int(r["concurrency"]))
        x = [int(d["concurrency"]) for d in data]
        y = [float(d["f1_mean"]) for d in data]

        ax.plot(x, y, label=name, color=color_map[name], marker="o", linewidth=2)

    ax.set_xscale("log", base=2)
    ax.set_xticks(concurrency)
    ax.set_xticklabels([str(c) for c in concurrency])
    ax.set_xlabel("Concurrent logical requests")
    ax.set_ylabel("F1 Score")
    ax.set_title("F1 Score vs Concurrency")
    ax.legend(fontsize=9)
    ax.grid(True, alpha=0.3)
    ax.set_ylim(0, 1.05)

    fig.tight_layout()

    out2 = os.path.join(output_dir, "f1_vs_concurrency.png")
    fig.savefig(out2, dpi=150)
    plt.close(fig)
    print(f"Saved: {out2}")

    # ── Plot 3: Wrong rate vs concurrency (separate, focused) ──

    fig, ax = plt.subplots(figsize=(8, 5))

    for name in strategy_names:
        data = sorted(strategies[name], key=lambda r: int(r["concurrency"]))
        x = [int(d["concurrency"]) for d in data]
        y = [float(d["wrong_rate_mean"]) for d in data]
        yerr = [float(d["wrong_rate_std"]) for d in data]

        ax.errorbar(
            x, y, yerr=yerr,
            label=name,
            color=color_map[name],
            marker="s",
            capsize=3,
            linewidth=1.5,
        )

    ax.set_xscale("log", base=2)
    ax.set_xticks(concurrency)
    ax.set_xticklabels([str(c) for c in concurrency])
    ax.set_xlabel("Concurrent logical requests")
    ax.set_ylabel("Wrong-attribution rate")
    ax.set_title("Wrong Attribution Rate vs Concurrency")
    ax.legend(fontsize=9)
    ax.grid(True, alpha=0.3)
    ax.set_ylim(-0.02, 1.05)

    fig.tight_layout()

    out3 = os.path.join(output_dir, "wrong_rate_vs_concurrency.png")
    fig.savefig(out3, dpi=150)
    plt.close(fig)
    print(f"Saved: {out3}")

    print("\nDone.")


if __name__ == "__main__":
    main()
