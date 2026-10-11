"""Run provenance and package integrity. External anchor required; no signatures."""
from __future__ import annotations

import argparse
import csv
import hashlib
import importlib.metadata
import json
import os
import platform
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from experiments.local_global_admissibility.experiment import canonical, digest, verify

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = 'package-manifest.json'


def now():
    return datetime.now(timezone.utc).isoformat()


def file_hash(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def source_provenance(root=ROOT):
    root = Path(root).resolve()
    def git(*args):
        return subprocess.check_output(['git', *args], cwd=root)
    status = git('status', '--porcelain=v1', '-z', '--untracked-files=all').decode()
    paths = git('ls-files', '-z', '--cached', '--others', '--exclude-standard').decode().split('\0')
    snapshot = {}
    for relative in sorted(set(paths) - {''}):
        path = root / relative
        if path.is_symlink():
            snapshot[relative] = digest({'symlink': os.readlink(path)})
        elif path.is_file():
            snapshot[relative] = file_hash(path)
        else:
            snapshot[relative] = 'MISSING'
    diff = git('diff', '--binary', 'HEAD')
    return {'commit': git('rev-parse', 'HEAD').decode().strip(),
            'branch': git('branch', '--show-current').decode().strip() or 'DETACHED',
            'clean': not status, 'status_porcelain': status,
            'tracked_diff_sha256': hashlib.sha256(diff).hexdigest(),
            'source_snapshot_sha256': digest(snapshot), 'source_snapshot': snapshot}


def environment():
    try:
        pytest = importlib.metadata.version('pytest')
    except importlib.metadata.PackageNotFoundError:
        pytest = None
    return {'python': platform.python_version(), 'executable': sys.executable,
            'platform': platform.platform(), 'pytest': pytest,
            'selected_environment': {k: os.environ.get(k) for k in ('PYTHONHASHSEED', 'TZ')}}


def record_command(argv, output, cwd=ROOT):
    """Capture source BEFORE running. Logs may be outside the repository."""
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    record = {'command': list(argv), 'cwd': str(Path(cwd).resolve()),
              'started_at': now(), 'provenance': source_provenance(cwd),
              'environment': environment()}
    # Persist the start record even if the controller/process is interrupted.
    (output / 'run-start.json').write_text(json.dumps(record, indent=2) + '\n')
    try:
        with (output / 'stdout.log').open('w') as log:
            proc = subprocess.run(argv, cwd=cwd, stdout=log, stderr=subprocess.STDOUT)
        exit_code = proc.returncode
    except KeyboardInterrupt:
        exit_code = 130
    except OSError as error:
        exit_code = 127
        (output / 'stdout.log').write_text(f'{type(error).__name__}: {error}\n')
    text = (output / 'stdout.log').read_text()
    counts = {name: int(number) for number, name in re.findall(
        r'(\d+) (passed|failed|skipped|errors?|deselected|xfailed|xpassed|tests collected)', text)}
    record.update(ended_at=now(), exit_code=exit_code, test_counts=counts,
                  stdout_sha256=file_hash(output / 'stdout.log'),
                  working_tree_after=source_provenance(cwd))
    (output / 'run.json').write_text(json.dumps(record, indent=2) + '\n')
    return record


def artifact_map(root):
    root = Path(root)
    artifacts = {}
    for path in sorted(root.rglob('*')):
        if path.is_symlink():
            raise ValueError('symlink evidence artifacts are not allowed')
        if path.is_file() and path.relative_to(root).as_posix() != MANIFEST:
            artifacts[path.relative_to(root).as_posix()] = file_hash(path)
    return artifacts


def seal_package(root):
    """Return canonical manifest SHA-256 for SEPARATE retention by reviewer."""
    root = Path(root)
    manifest = {'schema': 'pr36-evidence-package-v1', 'algorithm': 'sha256',
                'serialization': 'canonical-json-sort-keys-compact-utf8',
                'artifacts': artifact_map(root)}
    anchor = digest(manifest)
    (root / MANIFEST).write_text(canonical(manifest) + '\n')
    return anchor


def verify_package(root, trusted_anchor):
    """Integrity against supplied anchor, NOT provenance authentication.

    The anchor is never accepted from the package being verified. JSON/CSV,
    provenance, config, fixtures, logs and reports are all digest-covered.
    Semantic consistency is additionally checked for the primary traces.
    """
    root = Path(root)
    try:
        manifest = json.loads((root / MANIFEST).read_text())
        if (not isinstance(trusted_anchor, str) or len(trusted_anchor) != 64
                or digest(manifest) != trusted_anchor
                or manifest.get('schema') != 'pr36-evidence-package-v1'
                or manifest.get('algorithm') != 'sha256'
                or manifest['artifacts'] != artifact_map(root)):
            return False
        data = json.loads((root / 'traces.json').read_text())
        for mode, rows in data['arms'].items():
            if (not rows or not verify(rows, data['metadata']['terminal_hashes'][mode])
                    or rows[-1]['total_after'] != data['metadata']['observed_totals'][mode]):
                return False
            records = []
            for index, row in enumerate(rows):
                if (row['seq'] != index or row['before'] != records
                        or digest(row['action']) != row['action_hash']
                        or row['request_binding'] != row['action_hash']
                        or row['principal'] != row['action']['args']['agent_id']
                        or row['session_id'] != row['action']['args']['session_id']):
                    return False
                if row['executed']:
                    if (row['execution_decision']['verdict'] != 'PERMIT'
                            or row['execution_decision']['permitted'] is not True):
                        return False
                    records += row['action']['args']['records']
                if (row['after'] != records or row['total_before'] != len(row['before'])
                        or row['total_after'] != len(records)):
                    return False
        flattened = [row for rows in data['arms'].values() for row in rows]
        with (root / 'traces.csv').open(newline='') as handle:
            csv_rows = list(csv.DictReader(handle))
        if len(csv_rows) != len(flattened):
            return False
        for csv_row, row in zip(csv_rows, flattened):
            if not csv_row or any(
                    key not in row or value != (canonical(row[key]) if isinstance(row[key], dict)
                                               else str(row[key]))
                    for key, value in csv_row.items()):
                return False
        return True
    except (OSError, ValueError, KeyError, TypeError, IndexError, AttributeError):
        return False


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest='operation', required=True)
    record = sub.add_parser('record')
    record.add_argument('--output', type=Path, required=True)
    record.add_argument('command', nargs=argparse.REMAINDER)
    seal = sub.add_parser('seal')
    seal.add_argument('root', type=Path)
    check = sub.add_parser('verify')
    check.add_argument('root', type=Path)
    check.add_argument('--anchor', required=True)
    args = parser.parse_args()
    if args.operation == 'record':
        command = args.command[1:] if args.command[:1] == ['--'] else args.command
        if not command:
            parser.error('record requires a command after --')
        result = record_command(command, args.output)
        print(json.dumps({k: result[k] for k in ('exit_code', 'test_counts')}, indent=2))
        sys.exit(result['exit_code'])
    elif args.operation == 'seal':
        print(seal_package(args.root))
    else:
        valid = verify_package(args.root, args.anchor)
        print('VERIFIED' if valid else 'REJECTED')
        sys.exit(0 if valid else 1)


if __name__ == '__main__':
    main()
