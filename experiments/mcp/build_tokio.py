#!/usr/bin/env python3
"""Build the Tokio bridge and bind its executable hash to its source inputs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]


def source_hashes():
    paths = [ROOT/'Cargo.toml', ROOT/'Cargo.lock']
    for name in ['causpan-runtime', 'causpan-tokio-server']:
        directory = ROOT/'crates'/name
        paths += [directory/'Cargo.toml', *directory.rglob('*.rs')]
    return {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(paths)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target-dir', type=Path, default=ROOT/'target/tokio-provenance')
    args = parser.parse_args()
    target = args.target_dir.resolve()
    before = source_hashes()
    flags = '--cfg tokio_unstable'
    command = ['cargo', 'build', '--locked', '-p', 'causpan-tokio-server',
               '--target-dir', str(target), '-j', '2']
    subprocess.run(command, cwd=ROOT, env={**os.environ, 'RUSTFLAGS': flags}, check=True)
    after = source_hashes()
    if before != after:
        raise RuntimeError('Sources changed during compilation; rebuild from stable inputs')
    binary = target/'debug/causpan-tokio-server'
    manifest = dict(sources=after, rustflags=flags, command=command,
                    rustc=subprocess.check_output(['rustc', '-vV'], text=True),
                    binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest())
    path = binary.with_suffix('.build.json')
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(manifest, indent=2)+'\n')
    temporary.replace(path)
    print(path)


if __name__ == '__main__':
    main()
