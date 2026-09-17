//! Normalises `strace` output into [`causpan_core::KernelEvent`] JSONL.
//!
//! ## Usage
//!
//! ```bash
//! strace -ff -ttt -e trace=openat,read,write,socket,connect,clone,fork,execve \
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
    /// Input file (raw strace output, or JSONL of KernelEvents to sort).
    input: PathBuf,

    /// Output file (JSONL of KernelEvents).
    output: PathBuf,

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
    pid: u32,
    tid: u32,
    timestamp_ns: u64,
    event_type: KernelEventType,
    args: KernelEventArgs,
    return_value: Option<i64>,
}

/// Parse a single `strace -ff -ttt` line.
///
/// Expected format (one PID/TID per file when `-ff` is used):
///
/// ```text
/// 12345.678901234  4123  openat(AT_FDCWD, "/tmp/causpan/rpc-1-read.bin", O_RDONLY) = 3
/// 12345.679012345  4123  read(3, "rpc-1-seed\n", 4096)     = 12
/// ```
///
/// The timestamp is in seconds with microsecond (or better) precision; we
/// convert to nanoseconds.
fn parse_strace_line(line: &str) -> Result<Option<ParsedLine>, CauspanError> {
    // ── pattern ────────────────────────────────────────────────────────────
    //   <seconds>.<micro>  <tid>  <syscall>(<args>) = <ret>
    // or
    //   <seconds>.<micro>  <tid>  <syscall>(<args>) <unfinished ...>
    // or
    //   <seconds>.<micro>  <tid>  <syscall>(<args>) <no return>
    // ────────────────────────────────────────────────────────────────────────

    let re = Regex::new(
        r#"^(?P<ts>\d+\.\d+)\s+(?P<tid>\d+)\s+(?P<name>\w+)\((?P<args>[^)]*)\)(?:\s+=\s+(?P<ret>-?\d+|[a-fx0-9]+))?"#,
    )
    .expect("valid regex");

    let caps = match re.captures(line) {
        Some(c) => c,
        None => return Ok(None), // not a syscall line (e.g. "+++ exited")
    };

    let ts_str = caps.name("ts").expect("timestamp group").as_str();
    let timestamp_ns = parse_timestamp_ns(ts_str)?;

    let tid: u32 = caps
        .name("tid")
        .expect("tid group")
        .as_str()
        .parse()
        .map_err(|e| CauspanError::StraceParse {
            line: 0,
            source: Box::new(e),
        })?;

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

    // PID — strace -ff writes one file per PID when both PID and TID differ,
    // but when PID=TID (single-threaded) it writes a single file.  We
    // extract PID from the filename when available: `strace.<pid>`.
    // Otherwise fall back to TID (single-threaded case).
    let pid = tid; // will be overwritten by caller from filename

    Ok(Some(ParsedLine {
        pid,
        tid,
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

/// Map a syscall name to a [`KernelEventType`].
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
    let mut parts = s.split(',').map(|p| p.trim().to_string());
    KernelEventArgs::from_vec(parts.collect())
}

// ---------------------------------------------------------------------------
// PID extraction from filename
// ---------------------------------------------------------------------------

/// strace -ff names files `strace.<pid>`.  Extract the PID.
fn pid_from_filename(path: &std::path::Path) -> Option<u32> {
    path.file_stem()
        .and_then(|s| s.to_str())
        .and_then(|s| s.rsplit('.').next())
        .and_then(|s| s.parse().ok())
}

// ---------------------------------------------------------------------------
// Collection
// ---------------------------------------------------------------------------

fn collect_strace(input: PathBuf, output: PathBuf) -> Result<(), CauspanError> {
    let entries = std::fs::read_dir(&input).map_err(|e| CauspanError::Io(e))?;

    let mut events: Vec<KernelEvent> = Vec::new();

    for entry in entries {
        let entry = entry.map_err(CauspanError::Io)?;
        let path = entry.path();

        // strace -ff writes files named <prefix>.<tid> (or <prefix>.<pid>.<tid>).
        // Extract the last numeric component as the TID/PID.
        let Some(file_stem) = path.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };

        // Find the last dot-separated numeric component.
        let numeric_part = file_stem.rsplit('.').next();
        let tid_from_name: u32 = match numeric_part.and_then(|s| s.parse().ok()) {
            Some(n) => n,
            None => continue,
        };

        let base_pid = pid_from_filename(&path).unwrap_or(tid_from_name);
        let file = File::open(&path)?;
        let reader = BufReader::new(file);

        for (line_no, line_res) in reader.lines().enumerate() {
            let line = line_res?;
            let Some(parsed) = parse_strace_line(&line)? else {
                continue;
            };
            // PID from filename is the base PID; TID from the line itself.
            events.push(KernelEvent {
                pid: base_pid,
                tid: parsed.tid,
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
        InputFormat::Straces => collect_strace(cli.input, cli.output),
        InputFormat::Jsonl => collect_jsonl(cli.input, cli.output),
    }
}
