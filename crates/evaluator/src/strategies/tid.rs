//! PID + TID attribution strategy (B2).
//!
//! Maps each (PID, TID) pair to the most-recent RPC ID in ground truth.
//! Improves on B0 when different Tokio worker threads handle different RPCs,
//! but still fails when multiple RPCs execute on the same thread over time.

use causpan_core::{KernelEvent, RpcId};
use std::collections::HashMap;

#[derive(Debug, Default)]
pub struct PidTidStrategy {
    map: HashMap<(u32, u32), RpcId>,
}

impl PidTidStrategy {
    pub fn new() -> Self {
        Self::default()
    }
}

impl crate::strategies::AttributionStrategy for PidTidStrategy {
    fn name(&self) -> &'static str {
        "pid_tid"
    }

    fn load_ground_truth(&mut self, events: &[causpan_core::GroundTruthEvent]) {
        self.map.clear();
        for e in events {
            self.map.insert((e.pid, e.tid), RpcId(e.rpc_id.0));
        }
    }

    fn attribute(&self, event: &KernelEvent) -> Option<RpcId> {
        self.map.get(&(event.pid, event.tid)).copied()
    }
}
