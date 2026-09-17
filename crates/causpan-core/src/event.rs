//! Domain event types — re-exports and helpers used across crates.
//!
//! The canonical definitions live in `lib.rs`.  This module exists so that
//! other crates can do `use causpan_core::event::{…}` without importing the
//! entire prelude.

pub use crate::{GroundTruthEvent, KernelEvent, KernelEventArgs, KernelEventType, MatchKey, OperationKind};

/// Group ground-truth events by their semantic match key.
///
/// This is used by the evaluator to align ground-truth and kernel-event
/// streams without relying on PID/TID identity (which is unreliable when
/// the workload runs in separate processes).
pub fn group_gt_by_match_key<'a>(
    events: &'a [GroundTruthEvent],
) -> std::collections::HashMap<MatchKey, Vec<&'a GroundTruthEvent>> {
    let mut map: std::collections::HashMap<MatchKey, Vec<&'a GroundTruthEvent>> =
        std::collections::HashMap::new();
    for e in events {
        map.entry(MatchKey::from_ground_truth(e)).or_default().push(e);
    }
    map
}

/// Group kernel events by their semantic match key.
pub fn group_ke_by_match_key<'a>(
    events: &'a [KernelEvent],
) -> std::collections::HashMap<MatchKey, Vec<&'a KernelEvent>> {
    let mut map: std::collections::HashMap<MatchKey, Vec<&'a KernelEvent>> =
        std::collections::HashMap::new();
    for e in events {
        if let Some(key) = MatchKey::from_kernel_event(e) {
            map.entry(key).or_default().push(e);
        }
    }
    map
}
