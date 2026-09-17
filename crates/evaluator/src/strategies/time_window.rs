//! PID + TID + temporal-window attribution strategy (B3).
//!
//! Within a configurable time window of the most recent ground-truth event
//! for a given (PID, TID), attribute to that RPC ID.  Outside the window,
//! return `None` (no attribution).
//!
//! Multiple window sizes should be evaluated to understand how quickly
//! ambiguity emerges as concurrency increases.

use causpan_core::{GroundTruthEvent, KernelEvent, RpcId};
use std::collections::BTreeMap;

#[derive(Debug)]
pub struct TimeWindowStrategy {
    /// Attribution window in nanoseconds.
    window_ns: u64,
    /// Per-(PID,TID): sorted Vec of (timestamp_ns, RpcId).
    timeline: BTreeMap<(u32, u32), Vec<(u64, RpcId)>>,
}

impl TimeWindowStrategy {
    pub fn new(window_ns: u64) -> Self {
        Self {
            window_ns,
            timeline: BTreeMap::new(),
        }
    }

    /// Return strategy instances for a set of window sizes (milliseconds).
    pub fn strategies_ms(windows_ms: &[u64]) -> Vec<Box<dyn crate::strategies::AttributionStrategy>> {
        windows_ms
            .iter()
            .map(|&ms| {
                let label = format!("time_window_{}ms", ms);
                Box::new(Self::new(ms * 1_000_000)) as Box<dyn crate::strategies::AttributionStrategy>
            })
            .collect()
    }
}

impl crate::strategies::AttributionStrategy for TimeWindowStrategy {
    fn name(&self) -> &'static str {
        let ms = self.window_ns / 1_000_000;
        if ms == 0 {
            "time_window_0ms"
        } else {
            // Leak the string — fine for a small, long-lived program.
            let s = format!("time_window_{}ms", ms);
            Box::leak(s.into_boxed_str())
        }
    }

    fn load_ground_truth(&mut self, events: &[GroundTruthEvent]) {
        self.timeline.clear();
        for e in events {
            self.timeline
                .entry((e.pid, e.tid))
                .or_default()
                .push((e.timestamp_ns, RpcId(e.rpc_id.0)));
        }
        // Sort each timeline by timestamp.
        for v in self.timeline.values_mut() {
            v.sort_by_key(|&(ts, _)| ts);
        }
    }

    fn attribute(&mut self, event: &KernelEvent) -> Option<RpcId> {
        let key = (event.pid, event.tid);
        let Some(timeline) = self.timeline.get(&key) else {
            return None;
        };

        // Binary search for the insertion point.
        let ts = event.timestamp_ns;
        let pos = timeline.partition_point(|&(t, _)| t <= ts);

        // Search backward from pos for the nearest event within the window.
        let mut best: Option<RpcId> = None;
        let mut best_dist = u64::MAX;

        if pos > 0 {
            for i in (0..pos).rev() {
                let (t, rpc) = timeline[i];
                let dist = ts.saturating_sub(t);
                if dist > self.window_ns {
                    break; // further back events are even farther
                }
                if dist < best_dist {
                    best_dist = dist;
                    best = Some(rpc);
                }
            }
        }

        // Also check forward (in case a kernel event is slightly ahead of
        // the ground-truth log — strace timestamps can differ by a few µs).
        for &(t, rpc) in timeline[pos..].iter() {
            let dist = t.saturating_sub(ts);
            if dist > self.window_ns {
                break;
            }
            if dist < best_dist {
                best_dist = dist;
                best = Some(rpc);
            }
        }

        best
    }
}
