//! Normalises `strace` output into [`causpan_core::KernelEvent`] JSONL.
//!
//! ## Usage
//!
//! ```bash
//! strace -f -ff -ttt -e trace=openat,read,write,socket,connect,clone,fork,execve \
//!   ./target/release/workload 2> strace.raw
//!
//! collector strace.raw kernel-events.jsonl
//! ```
//!
//! The collector produces one JSON object per line, sorted by timestamp.

use causpan_core::{CauspanError, KernelEvent, KernelEventArgs, KernelEventType};
use clap::{Parser, ValueEnum};
use regex::Regex;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use tracing::{error, info, warn};

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Debug, Parser)]
#[command(name = "collector", about = "Causpan kernel-event collector")]
struct Cli {
    /// Input directory containing strace output files (for `straces` format).
    input: PathBuf,

    /// Output file (JSONL of KernelEvents).
    output: PathBuf,

    /// Data directory where the workload wrote `workload.pid`.
    #[arg(long)]
    data_dir: Option<PathBuf>,

    /// Input format.
    #[arg(long, value_enum, default_value = "strace")]
    format: InputFormat,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum InputFormat {
    Straces,
    /// Pre-processed JSONL (just sort and dedup).
    Jsonl,
}

// ---------------------------------------------------------------------------
// strace parser
// ---------------------------------------------------------------------------

/// Line-level parsed representation.
#[derive(Debug, Clone)]
struct ParsedLine {
    timestamp_ns: u64,
    event_type: KernelEventType,
    args: KernelEventArgs,
    return_value: Option<i64>,
}

/// Parse a single `strace -f -ff -ttt` line.
///
/// With `-ttt`, each file has one thread — no PID/TID on each line:
///
/// ```text
/// 12345.678901234  openat(AT_FDCWD, "/tmp/causpan/rpc-1-read.bin", O_RDONLY) = 3
/// 12345.679012345  read(3, "rpc-1-seed\n", 4096)     = 12
/// ```
///
/// The timestamp is in seconds with microsecond (or better) precision; we
/// convert to nanoseconds.
///
/// The TID comes from the filename suffix (strace.<tid>) with `-ff`.
/// The PID (thread-group ID) is obtained from `/proc/<tid>/status` → Tgid.
fn parse_strace_line(line: &str) -> Result<Option<ParsedLine>, CauspanError> {
    // Line format (no PID/TID prefix with -ttt):
    //   `<timestamp> <syscall>(<args>) = <ret>`
    let re = Regex::new(
        r#"^(?P<ts>\d+\.\d+)(?:\s+(?P<pid_tid>\d+))?\s+(?P<name>\w+)\((?P<args>[^)]*)\)(?:\s+=\s+(?P<ret>-?\d+|[a-fx0-9]+))?"#,
    )
    .expect("valid regex");

    let caps = match re.captures(line) {
        Some(c) => c,
        None => return Ok(None), // not a syscall line (e.g. "+++ exited")
    };

    let ts_str = caps.name("ts").expect("timestamp group").as_str();
    let timestamp_ns = parse_timestamp_ns(ts_str)?;

    let name = caps.name("name").expect("name group").as_str();
    let event_type = syscall_name_to_event(name);

    let args_str = caps.name("args").map(|m| m.as_str()).unwrap_or("");
    let args = parse_args(args_str);

    let ret = caps.name("ret").and_then(|m| {
        let s = m.as_str();
        if s.starts_with("0x") || s.starts_with("0X") {
            i64::from_str_radix(&s[2..], 16).ok()
        } else {
            s.parse().ok()
        }
    });

    Ok(Some(ParsedLine {
        timestamp_ns,
        event_type,
        args,
        return_value: ret,
    }))
}

/// Parse `<seconds>.<microseconds>` to nanoseconds.
fn parse_timestamp_ns(s: &str) -> Result<u64, CauspanError> {
    let dot = s.find('.').ok_or_else(|| CauspanError::StraceParse {
        line: 0,
        source: "missing decimal point in timestamp".into(),
    })?;
    let secs: u64 = s[..dot].parse().map_err(|e| CauspanError::StraceParse {
        line: 0,
        source: Box::new(e),
    })?;
    let frac_str = &s[dot + 1..];
    // Pad to 9 digits (nanoseconds).
    let frac_ns: u64 = frac_str
        .parse()
        .map_err(|e| CauspanError::StraceParse {
            line: 0,
            source: Box::new(e),
        })?;
    let scale = 10u64.pow(9 - frac_str.len() as u32);
    Ok(secs * 1_000_000_000 + frac_ns * scale)
}

/// Read the thread-group leader PID (Tgid) for a given TID from `/proc`.
/// All threads in a process share the same Tgid; this is the PID that
/// processes and baselines expect.
fn tgid_for_tid(tid: u32) -> u32 {
    let status_path = format!("/proc/{}/status", tid);
    let content = match std::fs::read_to_string(&status_path) {
        Ok(c) => c,
        Err(_) => return tid, // fallback: assume single-threaded
    };
    for line in content.lines() {
        if line.starts_with("Tgid:") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if let Some(tgid_str) = parts.get(1) {
                if let Ok(tgid) = tgid_str.parse::<u32>() {
                    return tgid;
                }
            }
        }
    }
    tid // fallback
}
fn syscall_name_to_event(name: &str) -> KernelEventType {
    match name {
        "openat" => KernelEventType::Openat,
        "read" => KernelEventType::Read,
        "write" => KernelEventType::Write,
        "socket" => KernelEventType::Socket,
        "connect" => KernelEventType::Connect,
        "clone" => KernelEventType::Clone,
        "fork" => KernelEventType::Fork,
        "execve" => KernelEventType::Execve,
        _ => KernelEventType::Unknown,
    }
}

/// Split the comma-separated argument string into individual values.
fn parse_args(s: &str) -> KernelEventArgs {
    let parts: Vec<&str> = s
        .split(',')
        .map(|p| p.trim().trim_matches('"'))
        .collect();
    KernelEventArgs::from_vec(&parts)
}

// ---------------------------------------------------------------------------
// PID extraction from filename
// ---------------------------------------------------------------------------

/// strace -ff names files `strace.<tid>`.  Extract the TID.
fn tid_from_filename(path: &std::path::Path) -> Option<u32> {
    path.file_name()?
        .to_str()?
        .rsplit('.')
        .next()?
        .parse()
        .ok()
}

// ---------------------------------------------------------------------------
// Collection
// ---------------------------------------------------------------------------

fn collect_strace(input: PathBuf, output: PathBuf, data_dir: Option<PathBuf>) -> Result<(), CauspanError> {
    // Read the workload's PID from the pid file if available.  This is the
    // authoritative PID — /proc/<tid>/status is not available after the
    // traced process has exited.
    let workload_pid: Option<u32> = data_dir
        .as_ref()
        .and_then(|d| std::fs::read_to_string(d.join("workload.pid")).ok())
        .and_then(|s| s.trim().parse().ok());

    info!(?workload_pid, "collecting kernel events");
    let entries = std::fs::read_dir(&input).map_err(|e| CauspanError::Io(e))?;

    let mut events: Vec<KernelEvent> = Vec::new();

    for entry in entries {
        let entry = entry.map_err(CauspanError::Io)?;
        let path = entry.path();

        // strace -ff writes files named <prefix>.<tid>.  Extract the TID from
        // the filename extension.  PID (thread-group ID / Tgid) is obtained
        // from /proc/<tid>/status so the two can differ for multi-threaded
        // processes.
        let tid_from_name = tid_from_filename(&path);
        let file = File::open(&path)?;
        let reader = BufReader::new(file);

        for (line_no, line_res) in reader.lines().enumerate() {
            let line = line_res?;
            let Some(parsed) = parse_strace_line(&line)? else {
                continue;
            };
            // TID from the filename (strace.<tid> with -ff).
            // PID from the workload's pid file (written before any threads
            // exit), or /proc/<tid>/status Tgid as fallback.
            let tid = match tid_from_name {
                Some(t) => t,
                None => continue,
            };
            let pid = workload_pid.unwrap_or_else(|| tgid_for_tid(tid));
            events.push(KernelEvent {
                pid,
                tid,
                timestamp_ns: parsed.timestamp_ns,
                event_type: parsed.event_type,
                args: parsed.args,
                return_value: parsed.return_value,
            });
        }
    }

    // Sort by timestamp so the evaluator can merge with ground truth.
    events.sort_by_key(|e| e.timestamp_ns);

    // Write output JSONL.
    let mut out = File::create(&output)?;
    for event in &events {
        writeln!(out, "{}", serde_json::to_string(event)?)?;
    }

    info!(
        events = events.len(),
        output = %output.display(),
        "collection complete"
    );
    Ok(())
}

fn collect_jsonl(input: PathBuf, output: PathBuf) -> Result<(), CauspanError> {
    let file = File::open(&input)?;
    let reader = BufReader::new(file);
    let mut events: Vec<KernelEvent> = Vec::new();

    for line_res in reader.lines() {
        let line = line_res?;
        if line.trim().is_empty() {
            continue;
        }
        events.push(serde_json::from_str(&line)?);
    }

    events.sort_by_key(|e| e.timestamp_ns);

    let mut out = File::create(&output)?;
    for event in &events {
        writeln!(out, "{}", serde_json::to_string(event)?)?;
    }

    info!(
        events = events.len(),
        output = %output.display(),
        "JSONL sort complete"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() -> Result<(), CauspanError> {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("collector=info")),
        )
        .init();

    match cli.format {
        InputFormat::Straces => collect_strace(cli.input, cli.output, cli.data_dir),
        InputFormat::Jsonl => collect_jsonl(cli.input, cli.output),
    }
}
