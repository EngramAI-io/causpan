//! Causpan evaluator — compares kernel observations to ground truth across
//! multiple attribution strategies and writes results to CSV.
//!
//! ## Usage
//!
//! ```bash
//! # After collecting strace and normalising:
//! evaluator \
//!   --ground-truth ground-truth.jsonl \
//!   --kernel-events  kernel-events.jsonl \
//!   --output         results/attribution.csv
//! ```

use causpan_core::{GroundTruthEvent, KernelEvent, RpcId};
use evaluator::{AttributionStrategy, EventMatcher, EvaluationResults, StrategyResults};
use clap::{Parser, ValueEnum};
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use tracing::{error, info};

// Re-export strategies.
use evaluator::strategies::pid::PidStrategy;
use evaluator::strategies::tid::PidTidStrategy;
use evaluator::strategies::time_window::TimeWindowStrategy;

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Debug, Parser)]
#[command(name = "evaluator", about = "Causpan attribution evaluator")]
struct Cli {
    /// Ground-truth JSONL (produced by the workload).
    #[arg(long)]
    ground_truth: PathBuf,

    /// Kernel-events JSONL (produced by the collector).
    #[arg(long)]
    kernel_events: PathBuf,

    /// Output CSV path.
    #[arg(long, default_value = "results/attribution.csv")]
    output: PathBuf,

    /// Which time windows (ms) to evaluate for the temporal strategy.
    #[arg(long, value_delimiter = ',', default_values_t = [1, 5, 10, 50, 100, 500, 1000])]
    time_windows_ms: Vec<u64>,

    /// Also run a "majority vote" meta-strategy.
    #[arg(long)]
    majority_vote: bool,
}

// ---------------------------------------------------------------------------
// I/O helpers
// ---------------------------------------------------------------------------

fn read_jsonl<T: serde::de::DeserializeOwned>(path: &PathBuf) -> Result<Vec<T>, String> {
    let file = File::open(path).map_err(|e| format!("open {}: {}", path.display(), e))?;
    let reader = BufReader::new(file);
    let mut items = Vec::new();
    for (i, line_res) in reader.lines().enumerate() {
        let line = line_res.map_err(|e| format!("read line {}: {}", i + 1, e))?;
        if line.trim().is_empty() {
            continue;
        }
        items.push(
            serde_json::from_str(&line).map_err(|e| format!("parse line {}: {}", i + 1, e))?,
        );
    }
    Ok(items)
}

// ---------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------

fn evaluate(cli: &Cli) -> Result<EvaluationResults, String> {
    let gt_events: Vec<GroundTruthEvent> = read_jsonl(&cli.ground_truth)?;
    let kernel_events: Vec<KernelEvent> = read_jsonl(&cli.kernel_events)?;

    if gt_events.is_empty() {
        return Err("ground-truth file is empty".into());
    }
    if kernel_events.is_empty() {
        return Err("kernel-events file is empty".into());
    }

    info!(
        gt_events = gt_events.len(),
        kernel_events = kernel_events.len(),
        "loaded events"
    );

    // Build the matcher that pairs kernel events with ground-truth RPC IDs.
    let matcher = EventMatcher::new(&gt_events);

    // Build strategies.
    let mut strategies: Vec<Box<dyn AttributionStrategy>> = Vec::new();

    strategies.push(Box::new(PidStrategy::new()));
    strategies.push(Box::new(PidTidStrategy::new()));
    for s in TimeWindowStrategy::strategies_ms(&cli.time_windows_ms) {
        strategies.push(s);
    }

    info!(strategies = strategies.len(), "strategies loaded");

    // Load ground truth into each strategy.
    for s in &mut strategies {
        s.load_ground_truth(&gt_events);
    }

    // Match kernel events to ground-truth RPC IDs.
    let mut matched = 0usize;
    let mut unmatched = 0usize;

    // Pre-compute the actual RPC ID for each matched kernel event.
    let mut actual_rpc_ids: Vec<Option<RpcId>> = Vec::with_capacity(kernel_events.len());
    for ke in &kernel_events {
        match matcher.match_event(ke) {
            Some(rpc) => {
                matched += 1;
                actual_rpc_ids.push(Some(rpc));
            }
            None => {
                unmatched += 1;
                actual_rpc_ids.push(None);
            }
        }
    }

    info!(matched, unmatched, "matching complete");

    // Run each strategy.
    let mut strategy_results: Vec<StrategyResults> = Vec::new();

    for mut s in strategies {
        // Reset mutable state.
        s.load_ground_truth(&gt_events);

        let mut results = StrategyResults::new(s.name());
        let mut correct_set: HashSet<RpcId> = HashSet::new();
        let mut wrong_set: HashSet<RpcId> = HashSet::new();

        for (idx, ke) in kernel_events.iter().enumerate() {
            let Some(actual) = actual_rpc_ids[idx] else {
                continue; // unmatched — skip
            };

            match s.attribute(ke) {
                Some(assigned) if assigned == actual => {
                    results.correct += 1;
                    correct_set.insert(assigned);
                }
                Some(assigned) => {
                    results.wrong_rpc += 1;
                    wrong_set.insert(assigned);
                }
                None => results.unattributed += 1,
            }
        }

        results.finalise(gt_events.len(), matched);
        strategy_results.push(results);
    }

    // Sort by F1 descending.
    strategy_results.sort_by(|a, b| {
        b.f1.partial_cmp(&a.f1).unwrap_or(std::cmp::Ordering::Equal)
    });

    Ok(EvaluationResults {
        matched_events: matched,
        unmatched_events: unmatched,
        strategies: strategy_results,
        total_kernel_events: kernel_events.len(),
        total_ground_truth_events: gt_events.len(),
    })
}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

fn write_csv(results: &EvaluationResults, path: &PathBuf) -> Result<(), String> {
    let mut file = File::create(path).map_err(|e| format!("create {}: {}", path.display(), e))?;

    writeln!(
        file,
        "strategy,correct,wrong_rpc,unattributed,precision,recall,f1,wrong_rate,unattributed_rate"
    )
    .map_err(|e| e.to_string())?;

    for sr in &results.strategies {
        writeln!(
            file,
            "{},{},{},{},{:.4},{:.4},{:.4},{:.4},{:.4}",
            sr.strategy_name,
            sr.correct,
            sr.wrong_rpc,
            sr.unattributed,
            sr.precision,
            sr.recall,
            sr.f1,
            sr.wrong_rate,
            sr.unattributed_rate,
        )
        .map_err(|e| e.to_string())?;
    }

    info!(path = %path.display(), "results written");
    Ok(())
}

fn print_summary(results: &EvaluationResults) {
    eprintln!("\n=== Causpan Attribution Evaluation ===\n");
    eprintln!(
        "Ground-truth events: {} | Kernel events: {} | Matched: {} | Unmatched: {}",
        results.total_ground_truth_events,
        results.total_kernel_events,
        results.matched_events,
        results.unmatched_events,
    );

    eprintln!("\n{:<30} {:>6} {:>8} {:>11} {:>8} {:>8} {:>8}",
        "Strategy", "Correct", "Wrong", "Unattrib", "Prec", "Rec", "F1");
    eprintln!("{}", "-".repeat(90));

    for sr in &results.strategies {
        eprintln!(
            "{:<30} {:>6} {:>8} {:>11} {:>7.1}% {:>7.1}% {:>7.1}%",
            sr.strategy_name,
            sr.correct,
            sr.wrong_rpc,
            sr.unattributed,
            sr.precision * 100.0,
            sr.recall * 100.0,
            sr.f1 * 100.0,
        );
    }
    eprintln!();
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("evaluator=info")),
        )
        .init();

    match evaluate(&cli) {
        Ok(results) => {
            print_summary(&results);
            if let Err(e) = write_csv(&results, &cli.output) {
                error!("write CSV: {}", e);
                std::process::exit(1);
            }
        }
        Err(e) => {
            error!("evaluation failed: {}", e);
            std::process::exit(1);
        }
    }
}
