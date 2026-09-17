//! Controlled Tokio workload generator for Causpan.
//!
//! ## Design
//!
//! The workload spawns N concurrent logical requests (RPCs).  Each RPC is a
//! Tokio task that performs a sequence of known operations — file reads,
//! file writes, network connects — interleaved with explicit `yield_now()`
//! calls so that the Tokio scheduler can interleave tasks in interesting ways.
//!
//! ## Ground-truth format
//!
//! A single writer task receives [`GroundTruthEvent`] messages over a Tokio
//! mpsc channel.  Each sender RPC records the event *before* executing the
//! corresponding kernel-visible operation, so the log is authoritative even
//! if the process is interrupted mid-run.
//!
//! ## Resource isolation
//!
//! Each RPC touches unique file paths and network targets so that the
//! evaluator can independently verify attribution correctness without
//! relying on timing heuristics.

use causpan_core::{FileTarget, GroundTruthEvent, NetworkTarget, OperationKind, OperationTarget, OperationId, RpcId};
use causpan_core::identity::OperationIdGenerator;
use clap::{Parser, ValueEnum};
use rand::SeedableRng;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

/// Causpan workload generator — spawns concurrent Tokio tasks that perform
/// file, network, and process operations while producing authoritative
/// ground-truth JSONL.
#[derive(Debug, Parser)]
#[command(name = "workload", about = "Causpan workload generator")]
struct Cli {
    /// Number of concurrent logical requests (RPCs) to spawn.
    #[arg(long, default_value = "1")]
    concurrency: usize,

    /// Number of operations each RPC performs.
    #[arg(long, default_value = "5")]
    operations_per_rpc: usize,

    /// Deterministic seed for the RNG.
    #[arg(long)]
    seed: Option<u64>,

    /// Output path for ground-truth JSONL.
    #[arg(long, default_value = "ground-truth.jsonl")]
    output: PathBuf,

    /// Base directory for file operations.
    #[arg(long, default_value = "/tmp/causpan")]
    data_dir: PathBuf,

    /// Host for network connect operations.
    #[arg(long, default_value = "127.0.0.1")]
    net_host: String,

    /// Port for network connect operations.
    #[arg(long, default_value = "9999")]
    net_port: u16,

    /// Number of Tokio worker threads (runtime threads).
    #[arg(long, default_value = "2")]
    worker_threads: usize,

    /// Which preset workload scenario to run.
    #[arg(long, value_enum, default_value = "mixed")]
    scenario: Scenario,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Scenario {
    /// Alternating file read + write per RPC.
    FileOnly,
    /// Network connect operations only.
    NetworkOnly,
    /// Mixed: file and network operations in random order.
    Mixed,
    /// Includes process spawning (clone + exec).
    WithProcessSpawn,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Monotonic timestamp in nanoseconds.
fn timestamp_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before UNIX_EPOCH")
        .as_nanos() as u64
}

/// Linux PID (process-wide).
fn current_pid() -> u32 {
    std::process::id()
}

/// Linux TID (thread-local — differs across Tokio worker threads).
fn current_tid() -> u32 {
    unsafe { libc::pthread_self() as u32 }
}

/// Unique file path for a given RPC and operation.
fn rpc_file_path(data_dir: &PathBuf, rpc_id: u64, suffix: &str) -> String {
    format!("{}/rpc-{}-{}.bin", data_dir.display(), rpc_id, suffix)
}

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

/// Perform a file read, logging the ground-truth event first.
async fn do_file_read(
    sender: &mpsc::Sender<GroundTruthEvent>,
    data_dir: PathBuf,
    rpc_id: u64,
    op_id: u64,
) {
    let path = rpc_file_path(&data_dir, rpc_id, "read");
    let event = GroundTruthEvent {
        rpc_id: RpcId(rpc_id),
        operation_id: OperationId(op_id),
        operation: OperationKind::FileRead,
        target: OperationTarget::File(FileTarget { path: path.clone() }),
        pid: current_pid(),
        tid: current_tid(),
        timestamp_ns: timestamp_ns(),
    };
    let _ = sender.send(event).await;

    // Kernel side effect (non-blocking via tokio::fs).
    let _ = tokio::fs::read(&path).await;
}

async fn do_file_write(
    sender: &mpsc::Sender<GroundTruthEvent>,
    data_dir: PathBuf,
    rpc_id: u64,
    op_id: u64,
) {
    let path = rpc_file_path(&data_dir, rpc_id, "write");
    let event = GroundTruthEvent {
        rpc_id: RpcId(rpc_id),
        operation_id: OperationId(op_id),
        operation: OperationKind::FileWrite,
        target: OperationTarget::File(FileTarget { path: path.clone() }),
        pid: current_pid(),
        tid: current_tid(),
        timestamp_ns: timestamp_ns(),
    };
    let _ = sender.send(event).await;

    let _ = tokio::fs::write(&path, format!("rpc-{}-op-{}\n", rpc_id, op_id)).await;
}

async fn do_network_connect(
    sender: &mpsc::Sender<GroundTruthEvent>,
    net_host: String,
    net_port: u16,
    rpc_id: u64,
    op_id: u64,
) {
    let target_str = format!("{}:{}", net_host, net_port);
    let event = GroundTruthEvent {
        rpc_id: RpcId(rpc_id),
        operation_id: OperationId(op_id),
        operation: OperationKind::NetworkConnect,
        target: OperationTarget::Network(NetworkTarget {
            host: net_host.clone(),
            port: net_port,
        }),
        pid: current_pid(),
        tid: current_tid(),
        timestamp_ns: timestamp_ns(),
    };
    let _ = sender.send(event).await;

    // Non-blocking connect (will likely fail if nothing is listening; that is
    // fine — we only need the syscall to appear in strace/eBPF).
    let _ = tokio::net::TcpStream::connect(target_str).await;
}

// ---------------------------------------------------------------------------
// Logical request
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
enum OpSpec {
    FileRead,
    FileWrite,
    NetworkConnect,
}

/// Build a per-RPC operation sequence for the chosen scenario.
fn build_ops(scenario: Scenario, count: usize, rng: &mut impl rand::Rng) -> Vec<OpSpec> {
    (0..count)
        .map(|_| match scenario {
            Scenario::FileOnly => {
                if rng.gen_bool(0.5) {
                    OpSpec::FileRead
                } else {
                    OpSpec::FileWrite
                }
            }
            Scenario::NetworkOnly => OpSpec::NetworkConnect,
            Scenario::Mixed => match rng.gen_range(0..3) {
                0 => OpSpec::FileRead,
                1 => OpSpec::FileWrite,
                _ => OpSpec::NetworkConnect,
            },
            Scenario::WithProcessSpawn => match rng.gen_range(0..3) {
                0 => OpSpec::FileRead,
                1 => OpSpec::FileWrite,
                _ => OpSpec::NetworkConnect,
            },
        })
        .collect()
}

/// One logical request (RPC) executing inside the Tokio runtime.
async fn logical_request(
    rpc_id: u64,
    op_gen: &mut OperationIdGenerator,
    ops: &[OpSpec],
    data_dir: PathBuf,
    net_host: String,
    net_port: u16,
    sender: mpsc::Sender<GroundTruthEvent>,
) {
    for spec in ops {
        // Yield control so other RPCs can run on the same worker thread,
        // creating realistic async interleavings.
        tokio::task::yield_now().await;

        match spec {
            OpSpec::FileRead => do_file_read(&sender, data_dir.clone(), rpc_id, op_gen.next().0).await,
            OpSpec::FileWrite => do_file_write(&sender, data_dir.clone(), rpc_id, op_gen.next().0).await,
            OpSpec::NetworkConnect => {
                do_network_connect(&sender, net_host.clone(), net_port, rpc_id, op_gen.next().0).await
            }
        }

        // Another yield to increase interleaving.
        tokio::task::yield_now().await;
    }
}

// ---------------------------------------------------------------------------
// Writer task
// ---------------------------------------------------------------------------

/// Dedicated task that serialises all ground-truth events to a JSONL file.
async fn writer_task(mut rx: mpsc::Receiver<GroundTruthEvent>, output: PathBuf) {
    let mut file = tokio::fs::File::create(&output)
        .await
        .expect("create ground-truth file");
    use tokio::io::AsyncWriteExt;

    while let Some(event) = rx.recv().await {
        let line = serde_json::to_string(&event).expect("serialize GroundTruthEvent");
        file.write_all(line.as_bytes())
            .await
            .expect("write ground-truth line");
        file.write_all(b"\n").await.expect("write newline");
        // Flush periodically so the file stays consistent if interrupted.
        file.flush().await.expect("flush");
    }
    file.flush().await.expect("final flush");
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() {
    let cli = Cli::parse();

    // Build the Tokio runtime with the requested number of worker threads.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(cli.worker_threads)
        .enable_all()
        .build()
        .expect("build tokio runtime");

    rt.block_on(async_main(cli));
}

async fn async_main(cli: Cli) {
    // Set up tracing.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("workload=info")),
        )
        .init();

    tracing::info!(
        concurrency = cli.concurrency,
        ops_per_rpc = cli.operations_per_rpc,
        scenario = ?cli.scenario,
        output = %cli.output.display(),
        "starting workload"
    );

    // Prepare data directory.
    fs::create_dir_all(&cli.data_dir).expect("create data dir");

    // Pre-create per-RPC files so reads don't create new files (which would
    // add extra openat events not attributed to any specific RPC).
    for rpc_id in 1..=cli.concurrency {
        let read_path = rpc_file_path(&cli.data_dir, rpc_id as u64, "read");
        let write_path = rpc_file_path(&cli.data_dir, rpc_id as u64, "write");
        let _ = fs::write(&read_path, format!("rpc-{}-seed\n", rpc_id));
        let _ = fs::write(&write_path, format!("rpc-{}-seed\n", rpc_id));
    }

    // Channel: each RPC sends its GroundTruthEvents to the writer task.
    let (tx, rx) = mpsc::channel(cli.concurrency * cli.operations_per_rpc);

    // Spawn writer task.
    let writer_handle = tokio::spawn(writer_task(rx, cli.output.clone()));

    // Build per-RPC operations.
    let mut rng = match cli.seed {
        Some(s) => rand::rngs::StdRng::seed_from_u64(s),
        None => rand::rngs::StdRng::from_os_rng(),
    };

    let mut handles = Vec::with_capacity(cli.concurrency);

    for rpc_id in 1..=cli.concurrency {
        let ops = build_ops(cli.scenario, cli.operations_per_rpc, &mut rng);
        let sender = tx.clone();
        let data_dir = cli.data_dir.clone();
        let net_host = cli.net_host.clone();

        handles.push(tokio::spawn(async move {
            let mut op_gen = OperationIdGenerator::new(((rpc_id as u64) << 32) | 1);
            logical_request(
                rpc_id as u64,
                &mut op_gen,
                &ops,
                data_dir,
                net_host,
                cli.net_port,
                sender,
            )
            .await;
        }));
    }

    // Drop our clone so the writer task terminates when all senders are gone.
    drop(tx);

    // Wait for all RPCs to finish.
    for handle in handles {
        let _ = handle.await;
    }

    // Wait for the writer to flush everything.
    let _ = writer_handle.await;

    tracing::info!("workload complete");
}
