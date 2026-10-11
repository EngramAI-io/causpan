#!/usr/bin/env python3
"""OpenAI-compatible agent runner for vLLM / Ollama / TGI.

Starts the MCP proxy as a subprocess, drives tool-using conversations with
any OpenAI-compatible API, and logs the full transcript for later validation.

Usage:
    python3.11 experiments/mcp/run_openai_agent.py \
        --url http://127.0.0.1:8000/v1 \
        --model / \
        --run results/mcp/ \
        --max-turns 20
"""

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

from openai import OpenAI


def main():
    ap = argparse.ArgumentParser(description="OpenAI-compatible agent runner")
    ap.add_argument("--url", required=True, help="OpenAI-compatible base URL (e.g. http://127.0.0.1:8000/v1)")
    ap.add_argument("--model", required=True, help="Model identifier (e.g. /)")
    ap.add_argument("--run", type=Path, required=True, help="Run directory with prompt.txt and run-config.json")
    ap.add_argument("--max-turns", type=int, default=20)
    ap.add_argument("--api-key", default="EMPTY", help="API key (default: EMPTY for local vLLM)")
    ap.add_argument("--concurrency", type=int, default=4,
                    help="Files per batch for the read scenario (default: 4)")
    ap.add_argument("--batches", type=int, default=1,
                    help="Number of batches for fixture generation (default: 1)")
    args = ap.parse_args()

    run = args.run.resolve()
    run.mkdir(parents=True, exist_ok=True)
    (run / "traces").mkdir(exist_ok=True)
    (run / "sandbox").mkdir(exist_ok=True)

    # Create prompt.txt and run-config.json if missing (standalone mode).
    prompt_path = run / "prompt.txt"
    if not prompt_path.exists():
        slots = [(b, s) for b in range(args.batches) for s in range(args.concurrency)]
        paths = [str(run / "sandbox" / f"call-{b}-{s}.txt") for b, s in slots]
        for p in paths:
            Path(p).write_text(f"fixture {p.split('/')[-1]}\n" + "sample data\n" * 512)
        lines = [
            "This is a filesystem MCP attribution experiment.",
            "Use ONLY tools from causpan_fs. Do not use shell or code execution.",
            f"Read these {len(paths)} files using separate read_text_file calls:",
        ] + [f"  {p}" for p in paths] + [
            "Then write a summary to agent-summary.txt and read it back.",
            "Stop after verifying.",
        ]
        prompt_path.write_text("\n".join(lines) + "\n")

    config_path = run / "run-config.json"
    if not config_path.exists():
        config_path.write_text(json.dumps({
            "scenario": "read",
            "capture": "strace",
            "instrumented": True,
            "pool_size": 4,
        }, indent=2) + "\n")

    prompt = prompt_path.read_text()

    # ── Start MCP proxy ────────────────────────────────────────────────
    proxy_cmd = [sys.executable, str(Path(__file__).resolve().parent / "proxy.py"), "--run", str(run)]
    proxy = subprocess.Popen(
        proxy_cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=0,
    )

    log_path = run / "agent.jsonl"
    err_path = run / "agent.stderr"
    log = log_path.open("w")
    err = err_path.open("w")

    try:
        # ── MCP initialization ────────────────────────────────────────
        send(proxy.stdin, {
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "openai-agent", "version": "1.0"},
            }
        }, log)
        recv(proxy.stdout, expected_id=1, log=log)  # initialize response

        send(proxy.stdin, {"jsonrpc": "2.0", "method": "notifications/initialized"}, log)

        # ── Discover tools ────────────────────────────────────────────
        send(proxy.stdin, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}, log)
        tools_resp = recv(proxy.stdout, expected_id=2, log=log)
        mcp_tools = tools_resp.get("result", {}).get("tools", [])

        openai_tools = [
            {
                "type": "function",
                "function": {
                    "name": t["name"],
                    "description": t.get("description", ""),
                    "parameters": t.get("inputSchema", {"type": "object"}),
                }
            }
            for t in mcp_tools
        ]

        # ── Conversation loop ─────────────────────────────────────────
        client = OpenAI(base_url=args.url, api_key=args.api_key)
        messages = [
            {"role": "system", "content": prompt},
            {"role": "user", "content": "Begin the task now. Use only the provided tools."},
        ]
        next_rpc_id = 100

        for turn in range(1, args.max_turns + 1):
            resp = client.chat.completions.create(
                model=args.model,
                messages=messages,
                tools=openai_tools,
                tool_choice="auto",
                temperature=0.0,
                max_tokens=2048,
            )
            msg = resp.choices[0].message
            log_entry = {
                "turn": turn,
                "role": msg.role,
                "content": msg.content,
                "tool_calls": [tc.model_dump() for tc in (msg.tool_calls or [])],
            }
            log.write(json.dumps(log_entry) + "\n")
            log.flush()
            messages.append({
                "role": msg.role,
                "content": msg.content,
                "tool_calls": [tc.model_dump() for tc in (msg.tool_calls or [])],
            })

            if not msg.tool_calls:
                break

            for tc in msg.tool_calls:
                next_rpc_id += 1
                fn_name = tc.function.name
                fn_args = json.loads(tc.function.arguments)

                send(proxy.stdin, {
                    "jsonrpc": "2.0",
                    "id": next_rpc_id,
                    "method": "tools/call",
                    "params": {"name": fn_name, "arguments": fn_args},
                }, log)

                tool_resp = recv(proxy.stdout, log=log)
                result_content = tool_resp.get("result", {}).get("content", [{}])
                result_text = result_content[0].get("text", json.dumps(result_content)) if result_content else ""

                log.write(json.dumps({"turn": turn, "tool": fn_name, "args": fn_args, "result": result_text[:500]}) + "\n")
                log.flush()

                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": result_text,
                })

        log.write(json.dumps({"status": "complete", "turns": turn}) + "\n")

    except Exception as e:
        err.write(f"{type(e).__name__}: {e}\n")
        log.write(json.dumps({"status": "failed", "error": str(e)}) + "\n")
        raise
    finally:
        proxy.stdin.close()
        proxy.terminate()
        proxy.wait()
        log.close()
        err.close()


def send(stdin, obj, log):
    line = json.dumps(obj) + "\n"
    stdin.write(line.encode())
    stdin.flush()


def recv(stdout, expected_id=None, log=None):
    """Read one JSON-RPC response, skipping notifications."""
    while True:
        line = stdout.readline()
        if not line:
            raise ConnectionError("proxy stdout closed")
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        if "id" not in msg:
            continue  # skip notifications
        if expected_id is not None and msg.get("id") != expected_id:
            continue
        if log:
            log.write(json.dumps({"recv": msg}) + "\n")
            log.flush()
        return msg


if __name__ == "__main__":
    main()
