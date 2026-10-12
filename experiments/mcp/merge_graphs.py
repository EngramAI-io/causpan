#!/usr/bin/env python3
"""Merge the strace-based provenance graph with the native-ring evidence graph.

The strace graph is written by attribute.py as provenance.jsonl.
The native graph is written by native_graph.py as native-graph.json.

After the merge, provenance.jsonl contains a unified graph where:
  * native nodes are prefixed 'native_' to avoid ID collisions
  * request nodes are merged by matching rpc_id across both graphs
  * all native edge kinds are preserved
  * ring_operation nodes from both sources coexist (they have different IDs)

The merged provenance.jsonl can be queried by query.py; its evidence-chain
traversal also needs the native-specific edge kinds added.
"""
import argparse
import json
import hashlib
import sys
from pathlib import Path


NATIVE_EDGE_KINDS = {
    'prepared_as',
    'observed_queue_episode',
    'poll_prepared',
    'observed_update_while_queued',
    'canceled_before_poll',
    'triggered_retry',
}


def load_jsonl(path: Path) -> list:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def prefix_id(record: dict, prefix: str = 'native_') -> dict:
    """Prefix node/edge IDs so native records don't collide with strace IDs."""
    out = dict(record)
    for field in ('id', 'source', 'target'):
        if field in out:
            val = out[field]
            if isinstance(val, str) and not val.startswith(prefix):
                out[field] = prefix + val
    return out


def build_id_map(native_nodes: list, strace_nodes: list) -> dict:
    """Map native request context IDs to the matching strace request node IDs.

    Both graphs carry 'rpc_id' on request/root nodes.  When they match we
    point the native request ID at the strace request ID so the merged graph
    has a single request node per MCP call.
    """
    strace_by_rpc = {}
    for node in strace_nodes:
        if node.get('type') == 'node' and node.get('kind') in ('mcp_request', 'causal_join'):
            rpc = node.get('rpc_id')
            if rpc is not None:
                strace_by_rpc[rpc] = node['id']

    id_map = {}
    for node in native_nodes:
        if node.get('type') != 'node':
            continue
        if node.get('kind') == 'request':
            rpc = node.get('rpc_id')
            if rpc in strace_by_rpc:
                native_id = prefix_id(node)['id']
                id_map[native_id] = strace_by_rpc[rpc]
    return id_map


def remap_ids(record: dict, id_map: dict) -> dict:
    """Replace native IDs that have a strace equivalent."""
    out = dict(record)
    for field in ('id', 'source', 'target'):
        if field in out and out[field] in id_map:
            out[field] = id_map[out[field]]
    return out


def merge(run: Path) -> dict:
    provenance_path = run / 'provenance.jsonl'
    native_path = run / 'native-graph.json'

    strace_records = load_jsonl(provenance_path)
    native_graph = json.loads(native_path.read_text()) if native_path.exists() else None

    if not native_graph:
        print("No native-graph.json found; provenance.jsonl unchanged.", file=sys.stderr)
        return dict(merged=False, reason='no_native_graph')

    native_nodes = native_graph.get('nodes', [])
    native_edges = native_graph.get('edges', [])

    id_map = build_id_map(native_nodes, strace_records)
    merged_nodes = {}  # id -> record
    merged_edges = []
    seen_edge_keys = set()

    for record in strace_records:
        if record.get('type') == 'node':
            merged_nodes[record['id']] = record
        elif record.get('type') == 'edge':
            key = (record.get('source'), record.get('target'), record.get('kind'))
            if key not in seen_edge_keys:
                seen_edge_keys.add(key)
                merged_edges.append(record)

    for node in native_nodes:
        prefixed = prefix_id(node)
        remapped = remap_ids(prefixed, id_map)
        nid = remapped['id']
        if nid in merged_nodes:
            for k, v in remapped.items():
                if k not in merged_nodes[nid]:
                    merged_nodes[nid][k] = v
        else:
            merged_nodes[nid] = remapped

    for edge in native_edges:
        prefixed = prefix_id(edge)
        remapped = remap_ids(prefixed, id_map)
        key = (remapped.get('source'), remapped.get('target'), remapped.get('kind'))
        if key not in seen_edge_keys:
            seen_edge_keys.add(key)
            merged_edges.append(remapped)

    merged = list(merged_nodes.values()) + merged_edges
    provenance_path.write_text(''.join(json.dumps(r) + '\n' for r in merged))

    return dict(
        merged=True,
        strace_nodes=sum(1 for r in strace_records if r.get('type') == 'node'),
        strace_edges=sum(1 for r in strace_records if r.get('type') == 'edge'),
        native_nodes=len(native_nodes),
        native_edges=len(native_edges),
        merged_nodes=len(merged_nodes),
        merged_edges=len(merged_edges),
        request_merges=len(id_map),
    )


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('run', type=Path, help='result directory containing provenance.jsonl and native-graph.json')
    args = p.parse_args()
    result = merge(args.run.resolve())
    print(json.dumps(result, indent=2))
    if result.get('merged') and result.get('request_merges'):
        print(f"\nMerged {result['request_merges']} native request nodes into strace equivalents.")
