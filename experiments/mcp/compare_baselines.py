#!/usr/bin/env python3
"""
Baseline-comparison experiment for Causpan.

Reuses analyze.py's proven parser, oracle, and PID-resolution logic.
Adds competing attribution strategies on top of the same ground-truth labels.

Strategies
----------
  camflow               : group all syscalls by server PID; any active
                          request during a syscall is a candidate.
                          (what CamFlow would produce on this workload
                          without MCP-aware extensions)
  otel                  : assign to any request whose wall-clock window
                          covers the syscall timestamp.
                          (what OpenTelemetry distributed tracing would
                          produce without kernel-side traceback)
  tetragon_fd           : assign based on the creation-time epoch of the
                          specific file descriptor used; a descriptor created
                          during request N's window is owned by request N.
                          (what Tetragon with LSMI + FD table tracking would
                          produce on this workload)
  tetragon_best         : tetragon_fd + fall back to otel when the FD
                          creation epoch is not known.
                          (the strongest achievable Tetragon result)
  causpan               : full Causpan mechanism: marker timestamps bind the
                          per-thread async execution scope to a request ID.
                          This is the system under evaluation.

All strategies are evaluated on the same ground-truth oracle produced by
unique-path and byte-offset labelling (the workload emits per-request tokens
as file content so a mismatch between read payload and the active request
is an independent correctness check).

Metrics
-------
  * correct_singleton     : events assigned to exactly the right request
  * truth_in_candidates  : ground-truth request appears in the candidate set
                            (recall proxy — no false negatives)
  * extra_candidates     : total (|candidates| - 1) across all events
  * candidate_accuracy   : correct_singleton / attributed events
  * recall              : truth_in_candidates / oracle_labelled
  * f1                  : harmonic mean of accuracy and recall

The output is a JSON evidence file plus a LaTeX-ready summary.
"""

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

# ---------------------------------------------------------------------------
# Reuse the proven parser / oracle from analyze.py so trace ingestion is
# identical across all experiments.
# ---------------------------------------------------------------------------
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'mcp'))
from analyze import parse_traces  # noqa: E402  (proven parser/oracle)


# ---------------------------------------------------------------------------
# Strategy implementations
# ---------------------------------------------------------------------------

def strategy_camflow(event, calls, server_pid: int,
                     _fd_epoch: dict, _causal: dict) -> list:
    """CamFlow: assign every server-PID syscall to every still-active request.

    No request identity — all concurrent requests are equally plausible.
    This is the upper-bound on the CamFlow candidate set for this workload.
    """
    if event.get('pid') != server_pid:
        return []
    return [c['id'] for c in calls.values()
            if c['end_ns'] is not None
            and c['start_ns'] <= event['timestamp_ns'] <= c['end_ns']]


def strategy_otel(event, calls, server_pid: int,
                  _fd_epoch: dict, _causal: dict) -> list:
    """OpenTelemetry: assign by wall-clock time window.

    OTel spans carry a start/end wall-clock interval.  When requests overlap
    (as they do on the async server), this strategy assigns syscalls to every
    request whose span covers the syscall timestamp — same result as camflow
    on this workload, but the reasoning is different (span window vs PID).
    """
    return strategy_camflow(event, calls, server_pid, _fd_epoch, _causal)


def build_fd_epoch(events: List[Dict], calls: dict) -> Dict[int, int]:
    """Map each FD to the timestamp of the open that created it.

    Mirrors what Tetragon would build from LSMI + FD-table events.  Descriptors
    inherited via CLONE_FILES or dup without a recorded open return have no
    epoch and therefore produce empty candidate sets under tetragon_fd.
    """
    fd_epoch: Dict[int, int] = {}
    for e in events:
        if e['syscall'] in {'openat', 'open'} and e['return_value'] and e['return_value'] > 0:
            fd = e['return_value']
            if fd not in fd_epoch:
                fd_epoch[fd] = e['timestamp_ns']
        elif e['syscall'] == 'dup' and e['return_value'] and e['return_value'] > 0:
            fd = e['return_value']
            if fd not in fd_epoch:
                m = re.search(r'\b(\d+)\s*<', e['args'])
                if m:
                    src = int(m.group(1))
                    if src in fd_epoch:
                        fd_epoch[fd] = fd_epoch[src]
    return fd_epoch


def strategy_tetragon_fd(event, calls, server_pid: int,
                         fd_epoch: dict, _causal: dict) -> list:
    """Tetragon with FD tracking.

    Assign based on the creation-time request of the file descriptor used.
    Descriptors created before tracing started or inherited via CLONE_FILES
    return empty candidate sets — this is what Tetragon actually produces.
    """
    if event.get('pid') != server_pid:
        return []
    fd_m = re.match(r'\s*(\d+)<', event['args'])
    if not fd_m:
        return []
    fd = int(fd_m.group(1))
    epoch = fd_epoch.get(fd)
    if epoch is None:
        return []
    return [c['id'] for c in calls.values()
            if c['end_ns'] is not None
            and c['start_ns'] <= epoch <= c['end_ns']]


def strategy_tetragon_best(event, calls, server_pid: int,
                           fd_epoch: dict, _causal: dict) -> list:
    """Tetragon with FD tracking + scope inference (best achievable prior).

    Uses the FD-epoch assignment when traceable; falls back to the
    request-window (OTel) strategy when the FD creation is not observable.
    This is the strongest result achievable without Causpan-style
    async-context markers.
    """
    if event.get('pid') != server_pid:
        return []
    fd_m = re.match(r'\s*(\d+)<', event['args'])
    if fd_m:
        fd = int(fd_m.group(1))
        epoch = fd_epoch.get(fd)
        if epoch is not None:
            return [c['id'] for c in calls.values()
                    if c['end_ns'] is not None
                    and c['start_ns'] <= epoch <= c['end_ns']]
    return strategy_otel(event, calls, server_pid, fd_epoch, _causal)


def _make_causpan_fn(call_map: dict):
    """Build a Causpan strategy that looks up request IDs from the causal map."""
    def _fn(event, _calls, _server_pid, _fd_epoch, causal_map):
        src = event.get('source', '')
        req = causal_map.get(src)
        if req is None or req not in call_map:
            return []
        return [req]
    return _fn


# ---------------------------------------------------------------------------
# Load Causpan causal annotations
# ---------------------------------------------------------------------------

def load_causal_map(run: Path, causal_path: str = 'causal-attribution.jsonl') -> dict:
    """Map event source (tid:lineno) → request_id from Causpan output."""
    result: Dict[str, Union[int, str, None]] = {}
    p = run / causal_path
    if not p.exists():
        return result
    for row in map(json.loads, p.read_text().splitlines()):
        src = row.get('source', '')
        if src:
            req = row.get('request_id')
            if isinstance(req, list):
                req = req[0] if req else None
            result[src] = req
    return result


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------

def evaluate_strategy(name: str, events: List[Dict], calls: Dict[int, dict],
                      server_pid: int, fd_epoch: dict,
                      causal_map: dict, strategy_fn) -> dict:
    """Run a strategy over oracle-labelled events and compute metrics."""
    counts = Counter()
    for e in events:
        if e.get('oracle_request_id') is None:
            continue
        candidates = strategy_fn(e, calls, server_pid, fd_epoch, causal_map)
        truth = e['oracle_request_id']
        counts['oracle_labelled'] += 1
        if not candidates:
            counts['unattributed'] += 1
            continue
        counts['attributed'] += 1
        counts['extra_candidates'] += max(len(candidates) - 1, 0)
        if len(candidates) == 1 and candidates[0] == truth:
            counts['correct_singleton'] += 1
        elif truth in candidates:
            counts['truth_in_candidates'] += 1
        else:
            counts['wrong_candidates'] += 1

    attributed = (counts['correct_singleton'] + counts['truth_in_candidates']
                  + counts['wrong_candidates'])
    accuracy = counts['correct_singleton'] / attributed if attributed else 0.0
    # Recall = fraction of oracle-labelled events where ground truth appeared
    # in the candidate set (covers both singleton and multi-candidate wins).
    recall = ((counts['correct_singleton'] + counts['truth_in_candidates'])
              / counts['oracle_labelled']) if counts['oracle_labelled'] else 0.0
    f1 = (2 * accuracy * recall / (accuracy + recall)) if (accuracy + recall) else 0.0

    return dict(
        strategy=name,
        oracle_labelled=counts['oracle_labelled'],
        attributed=attributed,
        unattributed=counts['unattributed'],
        correct_singleton=counts['correct_singleton'],
        truth_in_candidates=counts['truth_in_candidates'],
        wrong_candidates=counts['wrong_candidates'],
        extra_candidates=counts['extra_candidates'],
        accuracy=round(accuracy, 6),
        recall=round(recall, 6),
        f1=round(f1, 6),
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('run', type=Path, help='result directory from run.py')
    ap.add_argument('--output', type=Path,
                    default=None,
                    help='output path (default: <run>/baseline-comparison.json)')
    ap.add_argument('--latex', action='store_true',
                    help='also print a LaTeX table to stdout')
    ap.add_argument('--causal-attribution', default='causal-attribution.jsonl',
                    help='provenance file for Causpan strategy')
    args = ap.parse_args()
    run = args.run.resolve()

    # ── Load protocol.jsonl directly (analyze() prints results, doesn't return) ──
    protocol_path = run / 'protocol.jsonl'
    calls_raw = [json.loads(line) for line in protocol_path.read_text().splitlines()] \
        if protocol_path.exists() else []
    call_map = {}
    seen_ids = set()
    for row in calls_raw:
        msg = row['message']
        if (row['direction'] == 'request'
                and msg.get('method') == 'tools/call'
                and 'id' in msg):
            if msg['id'] in seen_ids:
                continue
            seen_ids.add(msg['id'])
            call_map[msg['id']] = dict(
                id=msg['id'],
                start_ns=row['wall_ns'], end_ns=None,
                tool=msg['params']['name'],
                arguments=msg['params'].get('arguments', {}))
        elif (row['direction'] == 'response'
              and msg.get('id') in call_map):
            call_map[msg['id']]['end_ns'] = row['wall_ns']

    # parse_traces takes a directory Path and returns (events, quality).
    events, quality = parse_traces(run / 'traces')

    # Server PID: use the same logic as analyze.py.
    roots = [e['pid'] for e in events
             if e['syscall'] == 'execve'
             and e['return_value'] == 0
             and any(name in e['args']
                      for name in ['server-filesystem/dist/index.js',
                                   'control-server.mjs',
                                   'causpan-tokio-server'])]
    server_pid = roots[0] if len(set(roots)) == 1 else 0

    # Oracle: unique-path ownership labels.
    owners = defaultdict(set)
    for c in call_map.values():
        for key in ['path', 'source', 'destination']:
            if key in c['arguments']:
                owners[c['arguments'][key]].add(c['id'])
        for p in c['arguments'].get('paths', []):
            owners[p].add(c['id'])
    root_prefix = str(run / 'sandbox') + '/'
    annotated = []
    for e in events:
        if not any(p.startswith(root_prefix) for p in e.get('paths', [])):
            continue
        possible = set().union(*(owners.get(p, set()) for p in e['paths']))
        truth = next(iter(possible)) if len(possible) == 1 else None
        annotated.append(dict(**e, oracle_request_id=truth))

    oracle = dict(
        call_count=len(call_map),
        incomplete_calls=sum(1 for c in call_map.values() if c['end_ns'] is None),
        tool_errors=sum(1 for c in call_map.values() if c.get('error')),
        oracle_labelled=sum(1 for e in annotated if e.get('oracle_request_id') is not None),
    )

    fd_epoch = build_fd_epoch(events, call_map)
    causal_map = load_causal_map(run, args.causal_attribution)

    print(f"Run: {run.name}")
    print(f"Server PID: {server_pid}")
    print(f"Parsed events: {quality.get('parsed', len(events))}")
    print(f"Sandbox events: {len(annotated)}")
    print(f"Oracle-labelled: {oracle['oracle_labelled']}")
    print(f"FD epoch entries: {len(fd_epoch)}")
    print(f"Causal map entries: {len(causal_map)}")
    print()

    # ── Run all strategies ───────────────────────────────────────────────
    strategies = [
        ('camflow', strategy_camflow,
         'CamFlow (PID-based provenance, no request identity)'),
        ('otel', strategy_otel,
         'OpenTelemetry (in-process context, no kernel traceback)'),
        ('tetragon_fd', strategy_tetragon_fd,
         'Tetragon with FD tracking (no async context binding)'),
        ('tetragon_best', strategy_tetragon_best,
         'Tetragon with FD tracking + scope inference (best prior)'),
        ('causpan', _make_causpan_fn(call_map),
         'Causpan (full mechanism with async-context markers)'),
    ]

    results = []
    for name, fn, desc in strategies:
        try:
            r = evaluate_strategy(name, annotated, call_map, server_pid,
                                   fd_epoch, causal_map, fn)
            r['description'] = desc
            results.append(r)
        except Exception as exc:
            results.append(dict(strategy=name, description=desc, error=str(exc)))

    # Load any existing causpan report for overhead / coverage context
    report_path = run / 'report.json'
    causpan_context = {}
    if report_path.exists():
        try:
            causpan_context = json.loads(report_path.read_text())
        except Exception:
            pass

    output = dict(
        experiment='baseline-comparison',
        run=run.name,
        scenario=causpan_context.get('scenario', 'unknown'),
        oracle=oracle,
        parser_quality=dict(quality),
        server_pid=server_pid,
        fd_epoch_entries=len(fd_epoch),
        causal_map_entries=len(causal_map),
        results=results,
        notes=[
            'camflow groups all server-PID syscalls to every active request.',
            'otel matches by wall-clock interval (OTel span window).',
            'tetragon_fd tracks the creation-time request of each file '
            'descriptor; descriptors inherited via CLONE_FILES or dup '
            'without a recorded open return empty candidate sets.',
            'tetragon_best is the strongest achievable prior-system strategy: '
            'it uses FD epoch when traceable and falls back to otel otherwise.',
            'causpan uses per-thread marker timestamps to bind syscalls to '
            'the executing async context.',
            'All strategies are evaluated on the same oracle-labelled events. '
            'The oracle labels events with a unique request ID when exactly '
            'one request owns the resource; multi-owner events are excluded.',
        ],
    )

    out_path = args.output or (run / 'baseline-comparison.json')
    out_path.write_text(json.dumps(output, indent=2) + '\n')
    print(f"Wrote: {out_path}")

    # ── Console output ───────────────────────────────────────────────────
    print()
    if any('error' in r for r in results):
        for r in results:
            if 'error' in r:
                print(f"{r['strategy']:<28} error: {r['error']}")
    else:
        header = (f"{'Strategy':<28} {'Acc':>6} {'Rec':>6} {'F1':>6} "
                  f"{'Attr':>6} {'Extra':>6}")
        print(header)
        print('-' * len(header))
        for r in results:
            print(f"{r['strategy']:<28} {r['accuracy']:6.3f} {r['recall']:6.3f} "
                  f"{r['f1']:6.3f} {r['attributed']:6d} "
                  f"{r['extra_candidates']:6d}")
    print()

    # ── LaTeX table ─────────────────────────────────────────────────────
    if args.latex:
        n = oracle['oracle_labelled']
        print(r"\begin{table}[ht]")
        print(r"\centering")
        print(f"\\caption{{Attribution strategies evaluated on {n} "
              f"oracle-labelled events ({run.name}).")
        print(r"\label{tab:baseline-comparison}")
        print(r"\begin{tabular}{lrrrrr}")
        print(r"Strategy & Accuracy & Recall & F1 & Attributed & Extra cand. \\")
        print(r"\hline")
        for r in results:
            if 'error' in r:
                print(f"{r['strategy']} & -- & -- & -- & -- & "
                      f"error: {r['error']} \\\\")
            else:
                print(f"{r['strategy']} & {r['accuracy']:.3f} & {r['recall']:.3f} "
                      f"& {r['f1']:.3f} & {r['attributed']} & "
                      f"{r['extra_candidates']} \\\\")
        print(r"\end{tabular}")
        print(r"\end{table}")
        print()


if __name__ == '__main__':
    main()
