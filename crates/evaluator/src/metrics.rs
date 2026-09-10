//! Evaluator library — attribution metrics and strategy orchestration.

use causpan_core::{GroundTruthEvent, KernelEvent, KernelEventType, RpcId};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Aggregate evaluation results across all strategies.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EvaluationResults {
    pub strategies: Vec<StrategyResults>,
    pub total_kernel_events: usize,
    pub total_ground_truth_events: usize,
    pub matched_events: usize,
    pub unmatched_events: usize,
}

/// Per-strategy results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StrategyResults {
    pub strategy_name: String,
    pub correct: usize,
    pub wrong_rpc: usize,
    pub unattributed: usize,
    pub precision: f64,
    pub recall: f64,
    pub f1: f64,
    pub wrong_rate: f64,
    pub unattributed_rate: f64,
}

impl StrategyResults {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            strategy_name: name.into(),
            correct: 0,
            wrong_rpc: 0,
            unattributed: 0,
            precision: 0.0,
            recall: 0.0,
            f1: 0.0,
            wrong_rate: 0.0,
            unattributed_rate: 0.0,
        }
    }

    /// Finalise metrics after all events have been classified.
    pub fn finalise(&mut self, total_gt: usize, matched: usize) {
        let attributed = self.correct + self.wrong_rpc;
        self.precision = if attributed > 0 {
            self.correct as f64 / attributed as f64
        } else {
            0.0
        };
        self.recall = if total_gt > 0 {
            self.correct as f64 / total_gt as f64
        } else {
            0.0
        };
        self.f1 = if self.precision + self.recall > 0.0 {
            2.0 * self.precision * self.recall / (self.precision + self.recall)
        } else {
            0.0
        };
        self.wrong_rate = if matched > 0 {
            self.wrong_rpc as f64 / matched as f64
        } else {
            0.0
        };
        self.unattributed_rate = if matched > 0 {
            self.unattributed as f64 / matched as f64
        } else {
            0.0
        };
    }
}

// ---------------------------------------------------------------------------
// Matching kernel events to ground truth
// ---------------------------------------------------------------------------

/// Match kernel events to ground-truth events.
///
/// Strategy:
/// 1. Index ground-truth by (PID, TID).
/// 2. For each kernel event, look up candidates with the same (PID, TID).
/// 3. Within a generous time window (±max_window_ns), prefer the closest
///    ground-truth event whose operation kind maps to the kernel event type.
/// 4. If no unique match exists, skip the kernel event.
///
/// The matching window is generous (10 seconds) because the only purpose is
/// to align the two event streams for evaluation — the strategy itself must
/// NOT use this large window.
#[derive(Debug)]
pub struct EventMatcher {
    /// (PID, TID) → sorted Vec of (timestamp_ns, operation_kind, rpc_id).
    by_tid: HashMap<(u32, u32), Vec<(u64, causpan_core::OperationKind, RpcId)>>,
    /// Maximum window for matching, in nanoseconds (10 s).
    max_window_ns: u64,
}

impl EventMatcher {
    pub fn new(ground_truth: &[GroundTruthEvent]) -> Self {
        let mut by_tid: HashMap<(u32, u32), Vec<(u64, causpan_core::OperationKind, RpcId)>> =
            HashMap::new();
        for e in ground_truth {
            by_tid
                .entry((e.pid, e.tid))
                .or_default()
                .push((e.timestamp_ns, e.operation, RpcId(e.rpc_id.0)));
        }
        for v in by_tid.values_mut() {
            v.sort_by_key(|&(ts, _, _)| ts);
        }
        Self {
            by_tid,
            max_window_ns: 10_000_000_000, // 10 seconds
        }
    }

    /// Try to find the ground-truth event that corresponds to this kernel
    /// event.  Returns `None` if no unique match exists.
    pub fn match_event(&self, kernel: &KernelEvent) -> Option<RpcId> {
        let Some(candidates) = self.by_tid.get(&(kernel.pid, kernel.tid)) else {
            return None;
        };

        let ts = kernel.timestamp_ns;
        // Binary search insertion point.
        let pos = candidates.partition_point(|&(t, _, _)| t <= ts);

        let mut best: Option<(u64, RpcId)> = None;

        // Check backward.
        if pos > 0 {
            for i in (0..pos).rev() {
                let (t, op, rpc) = candidates[i];
                let dist = ts.saturating_sub(t);
                if dist > self.max_window_ns {
                    break;
                }
                if operation_matches_kernel(op, kernel.event_type) {
                    match best {
                        Some((d, _)) if dist < d => best = Some((dist, rpc)),
                        None => best = Some((dist, rpc)),
                        _ => {}
                    }
                }
            }
        }

        // Check forward.
        for &(t, op, rpc) in candidates[pos..].iter() {
            let dist = t.saturating_sub(ts);
            if dist > self.max_window_ns {
                break;
            }
            if operation_matches_kernel(op, kernel.event_type) {
                match best {
                    Some((d, _)) if dist < d => best = Some((dist, rpc)),
                    None => best = Some((dist, rpc)),
                    _ => {}
                }
            }
        }

        best.map(|(_, rpc)| rpc)
    }
}

/// Does this application-level operation produce the given kernel event type?
fn operation_matches_kernel(op: causpan_core::OperationKind, ev: KernelEventType) -> bool {
    match op {
        causpan_core::OperationKind::FileRead => {
            matches!(ev, KernelEventType::Openat | KernelEventType::Read)
        }
        causpan_core::OperationKind::FileWrite => {
            matches!(ev, KernelEventType::Openat | KernelEventType::Write)
        }
        causpan_core::OperationKind::NetworkConnect => {
            matches!(ev, KernelEventType::Socket | KernelEventType::Connect)
        }
        causpan_core::OperationKind::ProcessSpawn => {
            matches!(ev, KernelEventType::Clone | KernelEventType::Fork | KernelEventType::Execve)
        }
    }
}
