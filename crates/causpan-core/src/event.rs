//! Domain event types — re-exports and helpers used across crates.
//!
//! The canonical definitions live in `lib.rs`.  This module exists so that
//! other crates can do `use causpan_core::event::{…}` without importing the
//! entire prelude.

pub use crate::{GroundTruthEvent, KernelEvent, KernelEventArgs, KernelEventType, OperationKind};

/// Iterate ground-truth events and group them by PID.
pub fn group_gt_by_pid<'a>(events: &'a [GroundTruthEvent]) -> std::collections::HashMap<u32, Vec<&'a GroundTruthEvent>> {
    let mut map: std::collections::HashMap<u32, Vec<&'a GroundTruthEvent>> = std::collections::HashMap::new();
    for e in events {
        map.entry(e.pid).or_default().push(e);
    }
    map
}

/// Iterate ground-truth events and group them by (PID, TID).
pub fn group_gt_by_tid<'a>(
    events: &'a [GroundTruthEvent],
) -> std::collections::HashMap<(u32, u32), Vec<&'a GroundTruthEvent>> {
    let mut map: std::collections::HashMap<(u32, u32), Vec<&'a GroundTruthEvent>> =
        std::collections::HashMap::new();
    for e in events {
        map.entry((e.pid, e.tid)).or_default().push(e);
    }
    map
}
