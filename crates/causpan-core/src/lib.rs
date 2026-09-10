//! Shared types for the Causpan research prototype.
//!
//! Two core data representations:
//!
//! * [`GroundTruthEvent`] — what the application *knows* about its own operations
//!   (authoritative RPC identity, operation type, target resource, etc.).
//! * [`KernelEvent`] — what can be observed from the kernel (PID, TID, timestamp,
//!   syscall type, arguments).  Critically, `KernelEvent` contains **no** RPC
//!   identity; recovering that mapping is the attribution problem.
//!
//! These two types live in separate modules to enforce the separation at the
//! type level and prevent accidental leakage of ground-truth identity into
//! kernel observations (or vice versa).

use serde::{Deserialize, Serialize};
use std::error::Error;
use thiserror::Error;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors that can occur when parsing or normalising Causpan events.
#[derive(Debug, Error)]
pub enum CauspanError {
    #[error("invalid RPC id: {0}")]
    InvalidRpcId(u64),

    #[error("invalid operation id: {0}")]
    InvalidOperationId(u64),

    #[error("invalid PID: {0}")]
    InvalidPid(u32),

    #[error("invalid TID: {0}")]
    InvalidTid(u32),

    #[error("unsupported operation kind: {0}")]
    UnsupportedOperation(String),

    #[error("strace parsing error at line {line}: {source}")]
    StraceParse {
        line: usize,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    #[error("JSON parse error: {0}")]
    JsonParse(#[from] serde_json::Error),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, CauspanError>;

// ---------------------------------------------------------------------------
// Identifiers
// ---------------------------------------------------------------------------

/// Unique identifier for a logical request (RPC / task / span).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct RpcId(pub u64);

impl std::fmt::Display for RpcId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RPC-{}", self.0)
    }
}

impl RpcId {
    pub fn new(id: u64) -> Self {
        debug_assert!(id > 0, "RPC id 0 is reserved for unknown");
        Self(id)
    }
}

/// Unique identifier for a single operation within an RPC.
///
/// Globally unique across all RPCs so kernel observations and ground-truth
/// records can be matched unambiguously during evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct OperationId(pub u64);

impl OperationId {
    pub fn new(id: u64) -> Self {
        Self(id)
    }
}

// ---------------------------------------------------------------------------
// Operation taxonomy
// ---------------------------------------------------------------------------

/// The kind of operation a logical request performs.
///
/// Each variant maps to one or more Linux syscalls:
///
/// * `FileRead`  → `openat` + `read`
/// * `FileWrite` → `openat` + `write`
/// * `NetworkConnect` → `socket` + `connect`
/// * `ProcessSpawn`  → `clone` / `fork` + `execve`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationKind {
    FileRead,
    FileWrite,
    NetworkConnect,
    ProcessSpawn,
}

impl std::fmt::Display for OperationKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::FileRead => "file_read",
            Self::FileWrite => "file_write",
            Self::NetworkConnect => "network_connect",
            Self::ProcessSpawn => "process_spawn",
        };
        write!(f, "{}", s)
    }
}

// ---------------------------------------------------------------------------
// Ground-truth events  (application layer)
// ---------------------------------------------------------------------------

/// A path used by a file operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileTarget {
    /// Absolute path.
    pub path: String,
}

/// A network target (host:port).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkTarget {
    pub host: String,
    pub port: u16,
}

/// The resource/argument of an operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum OperationTarget {
    File(FileTarget),
    Network(NetworkTarget),
    Process {
        command: String,
        args: Vec<String>,
    },
    Unknown,
}

/// An operation as seen from the *application* — authoritative ground truth.
///
/// This record is produced by the workload itself, so it is assumed correct.
/// It is used **only** for evaluation, never as input to an attribution strategy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroundTruthEvent {
    /// The logical request that caused this operation.
    pub rpc_id: RpcId,
    /// Unique operation identifier (globally unique across all RPCs).
    pub operation_id: OperationId,
    /// What kind of operation this is.
    pub operation: OperationKind,
    /// The target resource (path, host:port, command …).
    pub target: OperationTarget,
    /// Linux PID at the time of the operation.
    pub pid: u32,
    /// Linux TID at the time of the operation.
    pub tid: u32,
    /// Nanosecond-precision monotonic timestamp.
    pub timestamp_ns: u64,
}

// ---------------------------------------------------------------------------
// Kernel events  (kernel layer)
// ---------------------------------------------------------------------------

/// Syscall / tracepoint event type as observable from the kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KernelEventType {
    Openat,
    Read,
    Write,
    Socket,
    Connect,
    Clone,
    Fork,
    Execve,
    Unknown,
}

impl std::fmt::Display for KernelEventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Openat => "openat",
            Self::Read => "read",
            Self::Write => "write",
            Self::Socket => "socket",
            Self::Connect => "connect",
            Self::Clone => "clone",
            Self::Fork => "fork",
            Self::Execve => "execve",
            Self::Unknown => "unknown",
        };
        write!(f, "{}", s)
    }
}

/// Raw arguments captured for a kernel event.
///
/// We store them as strings because different syscalls have different argument
/// types and counts.  The collector normalises the strace/eBPF textual output
/// into this structure.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KernelEventArgs {
    pub arg0: Option<String>,
    pub arg1: Option<String>,
    pub arg2: Option<String>,
    pub arg3: Option<String>,
    pub arg4: Option<String>,
    pub arg5: Option<String>,
}

impl KernelEventArgs {
    pub fn from_vec(args: &[&str]) -> Self {
        let mut out = Self::default();
        for (i, arg) in args.iter().take(6).enumerate() {
            match i {
                0 => out.arg0 = Some((*arg).to_string()),
                1 => out.arg1 = Some((*arg).to_string()),
                2 => out.arg2 = Some((*arg).to_string()),
                3 => out.arg3 = Some((*arg).to_string()),
                4 => out.arg4 = Some((*arg).to_string()),
                5 => out.arg5 = Some((*arg).to_string()),
                _ => {}
            }
        }
        out
    }
}

/// A single kernel-observable event.
///
/// **No `rpc_id` field.**  The entire point of Causpan is to recover that
/// mapping from this (and potentially richer) data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelEvent {
    /// Linux PID.
    pub pid: u32,
    /// Linux TID.
    pub tid: u32,
    /// Nanosecond-precision timestamp (same clock source as ground truth).
    pub timestamp_ns: u64,
    /// The type of kernel event / syscall.
    pub event_type: KernelEventType,
    /// Raw arguments from the kernel observation.
    pub args: KernelEventArgs,
    /// Optional return value (e.g. file descriptor, error code).
    pub return_value: Option<i64>,
}

// ---------------------------------------------------------------------------
// Attribution result
// ---------------------------------------------------------------------------

/// The outcome of attributing a single kernel event.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum AttributionOutcome {
    /// Correctly attributed to the originating RPC.
    Correct {
        kernel_event_index: usize,
        assigned_rpc_id: RpcId,
        actual_rpc_id: RpcId,
    },
    /// Attributed to the wrong RPC.
    WrongRpc {
        kernel_event_index: usize,
        assigned_rpc_id: RpcId,
        actual_rpc_id: RpcId,
    },
    /// The strategy produced no assignment.
    Unattributed { kernel_event_index: usize },
}
