//! Attribution strategies for the Causpan evaluator.
//!
//! Each strategy receives a [`causpan_core::KernelEvent`] and, based on the
//! information available to it (PID, TID, temporal proximity, …), returns
//! the [`causpan_core::RpcId`] it believes generated that event — or `None`
//! if it cannot decide.
//!
//! Strategies are evaluated against ground-truth records so that precision,
//! recall, and F1 can be computed automatically.

use causpan_core::GroundTruthEvent;

/// A pluggable attribution strategy.
///
/// Strategies are stateful — they may accumulate data from previously seen
/// ground-truth events (e.g. a time-window strategy needs to know which RPCs
/// were recently active).
pub trait AttributionStrategy: Send {
    /// Name of the strategy (used in output headers).
    fn name(&self) -> &'static str;

    /// Provide this strategy with the full ground-truth event set before
    /// attribution begins.
    fn load_ground_truth(&mut self, events: &[GroundTruthEvent]);

    /// Attempt to attribute a kernel event.
    ///
    /// Returns `Some(RpcId)` when a decision can be made, or `None` when the
    /// strategy cannot determine the responsible RPC.
    fn attribute(&mut self, event: &causpan_core::KernelEvent) -> Option<causpan_core::RpcId>;
}

pub mod pid;
pub mod tid;
pub mod time_window;
