//! PID-only attribution strategy (B0).
//!
//! Maps each PID to the single most-recent RPC ID seen in the ground-truth
//! events.  Fails as soon as two RPCs share a PID concurrently.

use causpan_core::{KernelEvent, RpcId};
use std::collections::HashMap;

#[derive(Debug, Default)]
pub struct PidStrategy {
    pid_to_rpc: HashMap<u32, RpcId>,
}

impl PidStrategy {
    pub fn new() -> Self {
        Self::default()
    }
}

impl crate::strategies::AttributionStrategy for PidStrategy {
    fn name(&self) -> &'static str {
        "pid"
    }

    fn load_ground_truth(&mut self, events: &[causpan_core::GroundTruthEvent]) {
        self.pid_to_rpc.clear();
        for e in events {
            self.pid_to_rpc.insert(e.pid, RpcId(e.rpc_id.0));
        }
    }

    fn attribute(&self, event: &KernelEvent) -> Option<RpcId> {
        self.pid_to_rpc.get(&event.pid).copied()
    }
}
