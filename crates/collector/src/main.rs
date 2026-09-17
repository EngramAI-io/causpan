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
    timestamp_ns: u64,
    event_type: KernelEventType,
    args: KernelEventArgs,
    return_value: Option<i64>,
}

/// Parse a single `strace -ff -ttt` line.
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
/// With `-ttt`, the line format is:
///
///   `<timestamp> <syscall>(<args>) = <ret>`
///
/// No PID/TID column appears — each file is one thread.  We extract the
/// TID from the filename at the call site.
fn parse_strace_line(line: &str) -> Result<Option<ParsedLine>, CauspanError> {
    // Optional PID/TID group (for `-f` + `-tt` format); not present with `-ttt`.
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

    let _pid_tid = caps.name("pid_tid").and_then(|m| m.as_str().parse::<u32>().ok());

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

fn collect_strace(input: PathBuf, output: PathBuf) -> Result<(), CauspanError> {
    let entries = std::fs::read_dir(&input).map_err(|e| CauspanError::Io(e))?;

    let mut events: Vec<KernelEvent> = Vec::new();

    for entry in entries {
        let entry = entry.map_err(CauspanError::Io)?;
        let path = entry.path();

        // strace -ff writes files named <prefix>.<tid>.  Extract the TID from
        // the filename extension.  PID defaults to the same value (single-
        // threaded case); the per-line TID from strace is authoritative.
        let tid_from_name = tid_from_filename(&path).unwrap_or(0);
        let file = File::open(&path)?;
        let reader = BufReader::new(file);

        for (line_no, line_res) in reader.lines().enumerate() {
            let line = line_res?;
            let Some(parsed) = parse_strace_line(&line)? else {
                continue;
            };
            // PID = TID from filename (same for single-threaded processes).
            // TID = TID from the strace line itself.
            events.push(KernelEvent {
                pid: tid_from_name,
                tid: tid_from_name,
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
