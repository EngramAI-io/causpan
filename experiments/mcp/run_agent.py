#!/usr/bin/env python3
"""Minimal CLI to run an LLM agent against the causpan_fs MCP server.

Usage:
    python3.11 run_agent.py --model <model-id> [OPTIONS]

Examples:
    # GPT-6 Astra via Codex CLI (existing workflow)
    python3.11 run_agent.py --model gpt-6-astra --output results/run-1

    # Open-source model on GH200 / DeltaAI cluster
    python3.11 run_agent.py --model meta-llama/Llama-4-Maverick-17B --output results/run-2

The script starts the instrumented MCP proxy, runs the agent, captures
the protocol + strace, and produces causal attribution.  All raw evidence
is preserved under --output/ for independent scoring.
"""

import argparse, json, platform, subprocess, sys, time
from pathlib import Path

HERE = Path(__file__).resolve().parent


def main():
    ap = argparse.ArgumentParser(description="Run LLM agent MCP attribution experiment")
    ap.add_argument("--model", required=True,
                    help="Model identifier (HuggingFace repo ID or agent CLI model name). "
                         "Current production use: / (Apache 2.0, GH200-native).")
    ap.add_argument("--output", type=Path, required=True,
                    help="Output directory for this run (created fresh)")
    ap.add_argument("--scenario", default="read",
                    choices=["read", "worker-relay", "uring", "uring-memory", "uring-shared"])
    ap.add_argument("--concurrency", type=int, default=8)
    ap.add_argument("--batches", type=int, default=2)
    ap.add_argument("--pool-size", type=int, default=4)
    ap.add_argument("--instrumented", action="store_true", default=True)
    ap.add_argument("--capture", default="on", choices=["on", "off"])
    args = ap.parse_args()

    run = args.output.resolve()
    if run.exists():
        sys.exit(f"refusing to overwrite existing directory: {run}")
    run.mkdir(parents=True)
    (run / "sandbox").mkdir()

    # ── Build the agent prompt ─────────────────────────────────────────
    if args.scenario == "read":
        slots = [(b, s) for b in range(args.batches) for s in range(args.concurrency)]
        paths = [f"{run}/sandbox/call-{b}-{s}.txt" for b, s in slots]
        prompt_lines = [
            "This is a filesystem MCP attribution experiment.",
            "Use ONLY tools from causpan_fs. Do not use shell or code execution.",
            f"Read these {len(paths)} files using separate read_text_file calls:",
        ]
        for p in paths:
            prompt_lines.append(f"  {p}")
        prompt_lines += [
            "Then write a summary to agent-summary.txt and read it back.",
            "Stop after verifying.",
        ]
    elif args.scenario == "worker-relay":
        prompt_lines = [
            "Use the worker_slot tool to request 4 distinct jobs,",
            "then call barrier to complete the experiment.",
            "Do not use shell or other tools.",
        ]
    elif args.scenario in ("uring", "uring-memory", "uring-shared"):
        prompt_lines = [
            f"Use uring_slot to request {args.concurrency} ring operations.",
            "Then call barrier. Do not use shell or other tools.",
        ]
    else:
        sys.exit(f"unsupported scenario: {args.scenario}")

    prompt = "\n".join(prompt_lines) + "\n"
    (run / "prompt.txt").write_text(prompt)

    # ── Agent configuration ───────────────────────────────────────────
    # The MCP server is the causpan_fs proxy; tool approval is pre-approved.
    config = {
        "mcp_servers.causpan_fs.command": sys.executable,
        "mcp_servers.causpan_fs.args": [str(HERE / "proxy.py"), "--run", str(run)],
        "mcp_servers.causpan_fs.required": True,
        "mcp_servers.causpan_fs.tools.write_file.approval_mode": "approve",
        "mcp_servers.causpan_fs.tools.worker_slot.approval_mode": "approve",
        "mcp_servers.causpan_fs.tools.uring_slot.approval_mode": "approve",
        "mcp_servers.causpan_fs.tools.barrier.approval_mode": "approve",
        "mcp_servers.causpan_fs.startup_timeout_sec": 30,
        "mcp_servers.causpan_fs.tool_timeout_sec": 60,
        "approval_policy": "never",
    }

    # ── Build agent command ───────────────────────────────────────────
    # Pass --model through to the underlying CLI.  Swap the base command
    # if using a non-Codex agent (e.g. a local GH200 model runner).
    agent_cmd = build_agent_command(args.model, config, run)

    # ── Execute ───────────────────────────────────────────────────────
    started = time.monotonic()
    versions = detect_versions()
    manifest = {
        "mode": "agent",
        "model": args.model,
        "scenario": args.scenario,
        "concurrency": args.concurrency,
        "batches": args.batches,
        "pool_size": args.pool_size,
        "instrumented": args.instrumented,
        "platform": platform.platform(),
        "versions": versions,
        "status": "running",
    }
    (run / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")

    try:
        with (run / "agent.jsonl").open("w") as out, \
             (run / "agent.stderr").open("w") as err:
            subprocess.run(
                agent_cmd, stdin=subprocess.DEVNULL,
                stdout=out, stderr=err, check=True, timeout=600,
            )
        manifest["execution_seconds"] = time.monotonic() - started
        manifest["status"] = "complete"
    except Exception as e:
        manifest["status"] = "failed"
        manifest["error"] = str(e)
        raise
    finally:
        (run / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")


def build_agent_command(model: str, config: dict, run: Path) -> list[str]:
    """Construct the agent CLI invocation.

    Currently wraps Codex CLI.  Swap this function for a different runner
    when using a local model on the GH200 cluster.
    """
    cmd = [
        "codex", "exec",
        "--ignore-user-config",
        "--ephemeral",
        "--skip-git-repo-check",
        "--json",
        "--sandbox", "read-only",
        "-C", str(run / "sandbox"),
    ]
    for key, value in config.items():
        cmd += ["-c", f"{key}={json.dumps(value)}"]
    cmd += ["--model", model]
    cmd += [str(run / "prompt.txt")]
    return cmd


def detect_versions() -> dict:
    versions = {}
    for name, flag in [("node", "--version"), ("codex", "--version")]:
        try:
            out = subprocess.run([name, flag], capture_output=True, text=True, timeout=5)
            versions[name] = out.stdout.strip() or out.stderr.strip().splitlines()[0]
        except Exception:
            versions[name] = "not found"
    try:
        out = subprocess.run(["strace", "--version"], capture_output=True, text=True, timeout=5)
        versions["strace"] = out.stdout.strip().splitlines()[0]
    except Exception:
        versions["strace"] = "not found"
    return versions


if __name__ == "__main__":
    main()
