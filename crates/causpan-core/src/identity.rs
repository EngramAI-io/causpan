//! Identity types — RPC ID, operation ID, and related utilities.
//!
//! Keeping these in a separate module makes it easy to import only what a
//! consumer needs without pulling in the full event definitions.

pub use crate::{OperationId, RpcId};

/// A monotonically incrementing counter used to assign unique operation ids
/// within a single workload run.
#[derive(Debug, Default)]
pub struct OperationIdGenerator {
    next: u64,
}

impl OperationIdGenerator {
    pub fn new(start: u64) -> Self {
        Self { next: start }
    }

    /// Produce the next operation id and advance the counter.
    pub fn next(&mut self) -> OperationId {
        let id = OperationId::new(self.next);
        self.next += 1;
        id
    }
}
