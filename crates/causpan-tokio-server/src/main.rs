#![allow(unexpected_cfgs)]
//! Real newline-delimited MCP/JSON-RPC transport with controlled shared-FD workloads.
use causpan_runtime::{CausalContext, ContextRegistry};
use clap::Parser;
use serde_json::{json, Value};
use std::{
    collections::{HashSet, VecDeque},
    fs::{File, OpenOptions},
    io::{BufRead, Write},
    os::unix::fs::FileExt,
    path::PathBuf,
    sync::Arc,
    time::Duration,
};
use tokio::{
    sync::{mpsc, oneshot, Mutex},
    task::JoinHandle,
};
use tracing::Instrument;
use tracing_subscriber::prelude::*;

// Slot layout constants — shared across the Python control server and this Rust server
// so both write to byte-exact offsets on the same slots.bin file.
const SLOT_BYTE_WIDTH: u64 = 128;                  // Bytes reserved per slot.
const MAX_SLOT: u64 = 99999;                        // Highest valid slot index (0..99999).
const BACKGROUND_SLOT_OFFSET: u64 = 100000 * 128;   // Byte offset for background-write slot.

#[derive(Parser)]
#[command(version)]
struct Args {
    root: PathBuf,
    #[arg(long, default_value = "2")]
    worker_threads: usize,
    #[arg(long, default_value = "4")]
    blocking_threads: usize,
}
struct State {
    root: PathBuf,
    file: Arc<File>,
    detached: Mutex<Vec<JoinHandle<Result<(), String>>>>,
    registry: Option<ContextRegistry>,
    batch: Mutex<Vec<BatchItem>>,
}
struct BatchItem {
    slot: u64,
    context: Option<CausalContext>,
    joined: bool,
    reply: oneshot::Sender<Result<(), String>>,
}

async fn flush_batch(state: Arc<State>, mut entries: Vec<BatchItem>) {
    entries.sort_by_key(|entry| entry.slot);
    let mut pending: VecDeque<_> = entries.into();
    while let Some(first) = pending.pop_front() {
        let mut group = vec![first];
        while pending
            .front()
            .is_some_and(|entry| entry.slot == group.last().unwrap().slot + 1)
        {
            group.push(pending.pop_front().unwrap());
        }
        let result = async {
            let joined = group[0].joined;
            if group.iter().any(|entry| entry.joined != joined) {
                return Err("mixed join policies in batch".to_string());
            }
            let context = if joined {
                let registry = state
                    .registry
                    .as_ref()
                    .ok_or("join instrumentation unavailable")?;
                let parents: Vec<_> = group
                    .iter()
                    .map(|entry| entry.context.clone().ok_or("missing batch parent"))
                    .collect::<Result<_, _>>()?;
                Some(registry.join(&parents).map_err(|e| e.to_string())?)
            } else {
                None
            };
            let mut bytes = vec![0_u8; group.len() * SLOT_BYTE_WIDTH as usize];
            for (i, entry) in group.iter().enumerate() {
                let label = format!("slot:{}", entry.slot);
                bytes[i * SLOT_BYTE_WIDTH as usize..i * SLOT_BYTE_WIDTH as usize + label.len()].copy_from_slice(label.as_bytes());
            }
            let file = state.file.clone();
            let offset = group[0].slot * SLOT_BYTE_WIDTH;
            let perform = async move {
                tokio::task::spawn_blocking(move || file.write_all_at(&bytes, offset))
                    .await
                    .map_err(|e| e.to_string())?
                    .map_err(|e| e.to_string())
            };
            if let Some(context) = context {
                perform.instrument(context.span()).await
            } else {
                perform.await
            }
        }
        .await;
        for entry in group {
            let _ = entry.reply.send(result.clone());
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let instrumented = std::env::var("CAUSPAN_INSTRUMENTED").as_deref() == Ok("1");
    if instrumented {
        if !cfg!(tokio_unstable) {
            return Err("Build instrumentation with RUSTFLAGS='--cfg tokio_unstable'".into());
        }
        let run = PathBuf::from(std::env::var("CAUSPAN_RUN")?);
        tracing_subscriber::registry()
            .with(causpan_runtime::RuntimeLayer::new(
                run.join("native-events.jsonl"),
            )?)
            .init();
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(args.worker_threads)
        .max_blocking_threads(args.blocking_threads)
        .enable_all()
        .build()?;
    runtime.block_on(serve(args, instrumented))
}
async fn slot_io(state: Arc<State>, args: Value) -> Result<(), String> {
    let slot = args["slot"].as_u64().ok_or("slot must be an integer")?;
    let rounds = args["rounds"].as_u64().unwrap_or(3);
    let delay = args["delay_ms"].as_u64().unwrap_or(1);
    if slot > MAX_SLOT || rounds == 0 || rounds > 20 || delay > 100 {
        return Err("argument out of range".into());
    }
    for _ in 0..rounds {
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(delay + slot % 3)).await;
        let file = state.file.clone();
        let nested = args["nested"].as_bool().unwrap_or(false);
        tokio::task::spawn_blocking(move || -> Result<(), String> {
            if nested {
                tracing::trace_span!("nested.sync")
                    .in_scope(|| file.metadata())
                    .map_err(|e| e.to_string())?;
            }
            let payload = format!("{:.<32}", format!("slot:{slot}"));
            file.write_all_at(payload.as_bytes(), slot * SLOT_BYTE_WIDTH)
                .map_err(|e| e.to_string())?;
            let mut read = vec![0; payload.len()];
            file.read_exact_at(&mut read, slot * SLOT_BYTE_WIDTH)
                .map_err(|e| e.to_string())?;
            if read != payload.as_bytes() {
                return Err(format!("slot {slot} read-back mismatch"));
            }
            Ok(())
        })
        .await
        .map_err(|e| e.to_string())??;
    }
    Ok(())
}
async fn tool(
    state: Arc<State>,
    name: &str,
    args: Value,
    context: Option<CausalContext>,
) -> Result<Value, String> {
    match name {
        "batch_io" => {
            let slot = args["slot"]
                .as_u64()
                .filter(|slot| *slot < MAX_SLOT)
                .ok_or("invalid slot")?;
            let (reply, receive) = oneshot::channel();
            let mut batch = state.batch.lock().await;
            let width = args["batch_width"].as_u64().unwrap_or(1);
            if width == 0 || width > 1024 {
                return Err("invalid batch width".into());
            }
            batch.push(BatchItem {
                slot,
                context,
                joined: args["joined"].as_bool().unwrap_or(false),
                reply,
            });
            if batch.len() >= width as usize {
                let entries = std::mem::take(&mut *batch);
                tokio::spawn(flush_batch(state.clone(), entries));
            }
            drop(batch);
            receive.await.map_err(|e| e.to_string())??;
            Ok(json!({"content":[{"type":"text","text":format!("batched slot {slot}")}]}))
        }
        "read_text_file" => {
            let path = PathBuf::from(args["path"].as_str().ok_or("path required")?);
            if path.parent() != Some(state.root.as_path()) {
                return Err("read path must be a direct fixture child".into());
            }
            let resolved = tokio::fs::canonicalize(&path)
                .await
                .map_err(|e| e.to_string())?;
            if !resolved.starts_with(&state.root) {
                return Err("read path escapes fixture root".into());
            }
            let text = tokio::fs::read_to_string(resolved)
                .await
                .map_err(|e| e.to_string())?;
            Ok(
                json!({"content":[{"type":"text","text":text}],"structuredContent":{"content":text}}),
            )
        }
        "write_file" => {
            let path = PathBuf::from(args["path"].as_str().ok_or("path required")?);
            if path != state.root.join("agent-summary.txt") {
                return Err("controlled write tool only permits agent-summary.txt".into());
            }
            if tokio::fs::symlink_metadata(&path)
                .await
                .is_ok_and(|m| m.file_type().is_symlink())
            {
                return Err("refusing symlink output".into());
            }
            let content = args["content"].as_str().ok_or("content required")?;
            tokio::fs::write(path, content)
                .await
                .map_err(|e| e.to_string())?;
            Ok(json!({"content":[{"type":"text","text":"summary written"}]}))
        }
        "spawn_slot" => {
            let slot = args["slot"].as_u64().ok_or("slot required")?;
            if slot > MAX_SLOT {
                return Err("slot out of range".into());
            }
            let program="import os,sys; f=os.open(sys.argv[1],os.O_RDWR); os.pwrite(f,(\"child:\"+sys.argv[2]).encode(),int(sys.argv[2])*128); os.close(f)";
            let status = tokio::process::Command::new("python3.11")
                .args(["-c", program])
                .arg(state.root.join("slots.bin"))
                .arg(slot.to_string())
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .await
                .map_err(|e| e.to_string())?;
            if !status.success() {
                return Err(format!("child failed: {status}"));
            }
            Ok(json!({"content":[{"type":"text","text":"child complete"}]}))
        }
        "cancel_probe" => {
            let slot = args["slot"].as_u64().ok_or("slot required")?;
            if slot > MAX_SLOT {
                return Err("slot out of range".into());
            }
            let file = state.file.clone();
            let handle = tokio::task::spawn_blocking(move || {
                std::thread::sleep(Duration::from_millis(25));
                file.write_all_at(b"tokio probe", slot * SLOT_BYTE_WIDTH)
            });
            if args["cancel"].as_bool().unwrap_or(false) {
                handle.abort();
            }
            let result = match handle.await {
                Ok(Ok(())) => json!({"status":0,"bytes":11}),
                Ok(Err(e)) => return Err(e.to_string()),
                Err(e) if e.is_cancelled() => json!({"status":-125,"bytes":0}),
                Err(e) => return Err(e.to_string()),
            };
            Ok(
                json!({"content":[{"type":"text","text":result.to_string()}],"structuredContent":result}),
            )
        }
        "fail_probe" => {
            let slot = args["slot"].as_u64().ok_or("slot required")?;
            if slot > MAX_SLOT {
                return Err("slot out of range".into());
            }
            let root = state.root.clone();
            tokio::task::spawn_blocking(move || -> Result<(), String> {
                let readonly = File::open(root.join("slots.bin")).map_err(|e| e.to_string())?;
                if readonly.write_at(b"rejected", slot * SLOT_BYTE_WIDTH).is_ok() {
                    return Err("readonly write unexpectedly succeeded".into());
                }
                Ok(())
            })
            .await
            .map_err(|e| e.to_string())??;
            Ok(json!({"content":[{"type":"text","text":"failed write observed"}]}))
        }
        "slot_io" => {
            if args["detached"].as_bool().unwrap_or(false) {
                let state2 = state.clone();
                let handle = tokio::spawn(async move { slot_io(state2, args).await });
                state.detached.lock().await.push(handle);
                Ok(json!({"content":[{"type":"text","text":"scheduled"}]}))
            } else {
                slot_io(state, args).await?;
                Ok(json!({"content":[{"type":"text","text":"verified"}]}))
            }
        }
        "barrier" => {
            let jobs = std::mem::take(&mut *state.detached.lock().await);
            for job in jobs {
                job.await.map_err(|e| e.to_string())??;
            }
            Ok(json!({"content":[{"type":"text","text":"all work drained"}]}))
        }
        _ => Err(format!("unknown tool {name}")),
    }
}
fn tools() -> Value {
    json!({"tools":[
        {"name":"read_text_file","description":"Read text inside the controlled fixture root","annotations":{"readOnlyHint":true},
         "inputSchema":{"type":"object","properties":{"path":{"type":"string"}},"required":["path"],"additionalProperties":false}},
        {"name":"write_file","description":"Write agent-summary.txt in the controlled fixture root","annotations":{"readOnlyHint":false,"destructiveHint":true},
         "inputSchema":{"type":"object","properties":{"path":{"type":"string"},"content":{"type":"string"}},"required":["path","content"],"additionalProperties":false}},
        {"name":"slot_io","description":"Write/read a request-specific offset on a shared descriptor",
         "inputSchema":{"type":"object","properties":{
             "slot":{"type":"integer","minimum":0,"maximum":99999},
             "rounds":{"type":"integer","minimum":1,"maximum":20},
             "delay_ms":{"type":"integer","minimum":0,"maximum":100},
             "nested":{"type":"boolean"},"detached":{"type":"boolean"}},"required":["slot"],"additionalProperties":false}},
        {"name":"spawn_slot","description":"Spawn a one-shot child writer","inputSchema":{"type":"object","properties":{"slot":{"type":"integer","minimum":0,"maximum":99999}},"required":["slot"]}},
        {"name":"cancel_probe","description":"Optionally cancel queued blocking work","inputSchema":{"type":"object","properties":{"slot":{"type":"integer","minimum":0,"maximum":99999},"cancel":{"type":"boolean"}},"required":["slot","cancel"]}},
        {"name":"fail_probe","description":"Attempt a write on a readonly descriptor","inputSchema":{"type":"object","properties":{"slot":{"type":"integer","minimum":0,"maximum":99999}},"required":["slot"]}},
        {"name":"batch_io","description":"Batch request contributions into shared writes","inputSchema":{"type":"object","properties":{"slot":{"type":"integer","minimum":0,"maximum":99999},"joined":{"type":"boolean"},"batch_width":{"type":"integer","minimum":1,"maximum":1024}},"required":["slot"]}},
        {"name":"barrier","description":"Wait for detached request work",
         "inputSchema":{"type":"object","properties":{},"additionalProperties":false}}
    ]})
}
async fn serve(args: Args, instrumented: bool) -> Result<(), Box<dyn std::error::Error>> {
    let file = Arc::new(
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(args.root.join("slots.bin"))?,
    );
    let registry = if instrumented {
        Some(ContextRegistry::new(
            PathBuf::from(std::env::var("CAUSPAN_RUN")?).join("request-map.jsonl"),
        )?)
    } else {
        None
    };
    let state = Arc::new(State {
        root: args.root.clone(),
        file,
        registry,
        detached: Mutex::new(Vec::new()),
        batch: Mutex::new(Vec::new()),
    });
    let background_file = state.file.clone();
    let background = tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_millis(10)).await;
            let file = background_file.clone();
            tokio::task::spawn_blocking(move || file.write_all_at(b"background", BACKGROUND_SLOT_OFFSET))
                .await
                .unwrap()
                .unwrap();
        }
    });
    // Dedicated stdio threads avoid consuming Tokio's configurable blocking pool.
    // Otherwise a pending stdin read deadlocks filesystem work with a pool of size 1.
    let (sender, receiver) = std::sync::mpsc::channel::<Value>();
    let writer = std::thread::spawn(move || {
        let mut stdout = std::io::stdout().lock();
        while let Ok(message) = receiver.recv() {
            let mut line = serde_json::to_vec(&message).unwrap();
            line.push(b'\n');
            stdout.write_all(&line).unwrap();
            stdout.flush().unwrap();
        }
    });
    let (input, mut lines) = mpsc::unbounded_channel();
    let reader = std::thread::spawn(move || {
        for line in std::io::stdin().lock().lines() {
            if input.send(line).is_err() {
                break;
            }
        }
    });
    let mut tasks = Vec::new();
    let mut seen = HashSet::new();
    while let Some(line) = lines.recv().await {
        let request: Value = serde_json::from_str(&line?)?;
        let Some(id) = request.get("id").cloned() else {
            continue;
        };
        if !(id.is_string() || id.is_i64() || id.is_u64()) || !seen.insert(id.to_string()) {
            sender.send(json!({"jsonrpc":"2.0","id":id,"error":{"code":-32600,"message":"invalid or reused request ID"}}))?;
            continue;
        }
        let method = request["method"].as_str().unwrap_or("");
        match method {
            "initialize" => {
                let requested = request["params"]["protocolVersion"]
                    .as_str()
                    .unwrap_or("2024-11-05");
                let version = if ["2024-11-05", "2025-03-26", "2025-11-25"].contains(&requested) {
                    requested
                } else {
                    "2024-11-05"
                };
                sender.send(json!({"jsonrpc":"2.0","id":id,"result":{"protocolVersion":version,"capabilities":{"tools":{}},"serverInfo":{"name":"causpan-tokio","version":env!("CARGO_PKG_VERSION")}}}))?;
            }
            "tools/list" => {
                sender.send(json!({"jsonrpc":"2.0","id":id,"result":tools()}))?;
            }
            "ping" => {
                sender.send(json!({"jsonrpc":"2.0","id":id,"result":{}}))?;
            }
            "tools/call" => {
                let name = request["params"]["name"].as_str().unwrap_or("").to_owned();
                let context = state
                    .registry
                    .as_ref()
                    .map(|registry| registry.request(id.clone(), &name))
                    .transpose()?;
                let args = request["params"]
                    .get("arguments")
                    .cloned()
                    .unwrap_or(json!({}));
                let state = state.clone();
                let sender = sender.clone();
                let span = context
                    .as_ref()
                    .map(CausalContext::span)
                    .unwrap_or_else(tracing::Span::none);
                tasks.push(tokio::spawn(
                    async move {
                        let result = match tool(state, &name, args, context).await {
                            Ok(result) => result,
                            Err(message) => {
                                json!({"content":[{"type":"text","text":message}],"isError":true})
                            }
                        };
                        sender
                            .send(json!({"jsonrpc":"2.0","id":id,"result":result}))
                            .unwrap();
                    }
                    .instrument(span),
                ));
            }
            _ => {
                sender.send(json!({"jsonrpc":"2.0","id":id,"error":{"code":-32601,"message":"method not found"}}))?;
            }
        }
    }
    for task in tasks {
        task.await?;
    }
    tool(state, "barrier", json!({}), None)
        .await
        .map_err(io_error)?;
    background.abort();
    let _ = background.await;
    drop(sender);
    writer.join().expect("stdout writer panicked");
    reader.join().expect("stdin reader panicked");
    Ok(())
}
fn io_error(message: String) -> std::io::Error {
    std::io::Error::other(message)
}
