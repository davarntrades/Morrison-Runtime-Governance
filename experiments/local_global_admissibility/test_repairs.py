"""Repair-specific counterexamples; original 43 focused cases remain untouched."""
import copy
import csv
import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path

import pytest

from experiments.local_global_admissibility.experiment import (
    IsolatedExecutor, candidate, send, run, digest, canonical,
)
from experiments.local_global_admissibility.evidence_tools import (
    source_provenance, record_command, seal_package, verify_package,
)
from experiments.local_global_admissibility.review import (
    fault_review, matched_boundary_review, concurrent_review, reconstruct, identity_review,
)


@pytest.mark.parametrize('kind', ['exception', 'timeout', 'malformed', 'unavailable'])
def test_local_permit_preserved_on_global_failure(kind):
    row = fault_review(kind)
    assert row['global_verdict']['exception_message']
    assert row['global_verdict']['exception_traceback']
    assert row['local_verdict']['verdict'] == 'PERMIT'
    assert row['global_verdict']['verdict'] == 'ERROR'
    assert row['execution_decision']['verdict'] == 'BLOCK'


@pytest.mark.parametrize('field', ['reason', 'layer', 'rule', 'omega_domain'])
def test_nonserializable_authority_metadata_blocks_before_effect(field):
    from multi_agent_eval.governance_modes import Decision
    executor = IsolatedExecutor()
    response = Decision('shared_global', True, 'PERMIT', 'fixture', None, None, 'valid')
    setattr(response, field, object())
    executor.mode.global_.decide = lambda *args: response
    row = send(executor, candidate(0))
    assert row['local_verdict']['verdict'] == 'PERMIT'
    assert row['global_verdict']['verdict'] == 'ERROR'
    assert field in row['global_verdict']['exception_message']
    assert row['execution_decision']['verdict'] == 'BLOCK'
    assert row['before'] == row['after'] == executor.snapshot() == []
    assert len(executor.trace()) == 1


def test_local_failure_global_genuinely_not_evaluated():
    executor = IsolatedExecutor()
    def failed(*args):
        raise RuntimeError('local failed first')
    executor.mode.local.decide = failed
    row = send(executor, candidate(0))
    assert row['local_verdict']['verdict'] == 'ERROR'
    assert row['global_verdict']['verdict'] == 'NOT_EVALUATED'
    assert [(e['tier'], e['event']) for e in row['evaluation_events']] == [('local', 'START'), ('local', 'ERROR')]
    assert row['after'] == []


def test_layer_error_context_preserved():
    executor = IsolatedExecutor()
    def failed(*args):
        raise TimeoutError('layer timeout context')
    executor.mode.global_.gov.evaluate = failed
    row = send(executor, candidate(0))
    assert row['local_verdict']['verdict'] == 'PERMIT'
    assert row['global_verdict']['verdict'] == 'ERROR'
    assert row['global_verdict']['enforcement_verdict'] == 'BLOCK'
    assert 'TimeoutError: layer timeout context' in row['global_verdict']['reason']
    assert not row['executed']


def test_prevalidation_has_no_evaluation_events():
    executor = IsolatedExecutor()
    row = executor.submit(candidate(0), principal='agent-0')
    assert row['evaluation_events'] == []
    assert row['local_verdict']['verdict'] == row['global_verdict']['verdict'] == 'NOT_EVALUATED'


def test_control_records_completed_layer_error():
    executor = IsolatedExecutor('local_only')
    from experiments.local_global_admissibility.experiment import local_layer
    layer = local_layer()
    def failed(*args):
        raise ConnectionError('control unavailable')
    layer.evaluate = failed
    executor.mode._layers['agent-0'] = layer
    row = send(executor, candidate(0))
    assert row['local_verdict']['verdict'] == 'ERROR'
    assert row['global_verdict']['verdict'] == 'NOT_EVALUATED'
    assert not row['executed']


def test_authority_boundary_equivalence_and_reverse_order():
    result = matched_boundary_review()
    assert result['equivalent_authority_entry'] and result['same_submit_implementation']
    assert result['same_lock_type'] and result['reverse_order_equal']


def test_paired_concurrent_workload_20_trials_per_arm():
    runs = concurrent_review()
    assert len(runs) == 40
    assert {r['total'] for r in runs if r['mode'] == 'local_only'} == {240}
    assert {r['total'] for r in runs if r['mode'] == 'hierarchical'} == {90}


def test_independent_state_reconstruction():
    for rows in run().values():
        assert reconstruct(rows) == rows[-1]['after']


def test_identity_artifact_and_binding_substitution():
    result = identity_review()
    assert set(result) == {'session', 'principal', 'binding', 'forged_artifact', 'replay'}
    assert all(not row['executed'] for row in result.values())


@pytest.fixture
def git_source(tmp_path):
    root = tmp_path / 'repository'
    root.mkdir()
    def git(*args):
        subprocess.run(['git', *args], cwd=root, check=True, capture_output=True)
    git('init', '-b', 'fixture-source')
    (root / 'source.txt').write_text('original\n')
    git('add', 'source.txt')
    git('-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', 'commit', '-m', 'fixture')
    return root


def test_clean_and_dirty_source_provenance(git_source):
    clean = source_provenance(git_source)
    assert clean['clean'] and clean['branch'] == 'fixture-source'
    (git_source / 'source.txt').write_text('modified\n')
    (git_source / 'new-source.txt').write_text('untracked\n')
    dirty = source_provenance(git_source)
    assert not dirty['clean'] and dirty['commit'] == clean['commit']
    assert dirty['tracked_diff_sha256'] != clean['tracked_diff_sha256']
    assert dirty['source_snapshot_sha256'] != clean['source_snapshot_sha256']
    assert 'new-source.txt' in dirty['source_snapshot']


def test_actual_run_status_environment_timestamps_and_log(git_source, tmp_path):
    argv = [sys.executable, '-c', 'print("executed provenance probe"); raise SystemExit(2)']
    output = tmp_path / 'run'
    record = record_command(argv, output, git_source)
    assert record['command'] == argv and record['exit_code'] == 2
    assert record['provenance']['clean'] and record['test_counts'] == {}
    assert datetime.fromisoformat(record['ended_at']) >= datetime.fromisoformat(record['started_at'])
    assert record['environment']['python'] and record['environment']['pytest']
    assert 'executed provenance probe' in (output / 'stdout.log').read_text()
    assert record['stdout_sha256']


@pytest.fixture
def package(tmp_path):
    root = tmp_path / 'package'
    root.mkdir()
    arms = run()
    metadata = {'source_commit': 'fixture-source-commit',
                'observed_totals': {k: v[-1]['total_after'] for k, v in arms.items()},
                'terminal_hashes': {k: v[-1]['evidence_hash'] for k, v in arms.items()}}
    (root / 'traces.json').write_text(json.dumps({'metadata': metadata, 'arms': arms}))
    with (root / 'traces.csv').open('w', newline='') as handle:
        writer = csv.writer(handle, lineterminator='\n')
        writer.writerow(['mode', 'seq', 'action_hash', 'total_after'])
        for mode, rows in arms.items():
            for row in rows:
                writer.writerow([mode, row['seq'], row['action_hash'], row['total_after']])
    (root / 'config.json').write_text(json.dumps({'local_limit': 40, 'global_limit': 100}))
    (root / 'fixture.json').write_text(json.dumps([candidate(i) for i in range(4)]))
    (root / 'validation.json').write_text(json.dumps({'runs': [{'provenance': {'commit': 'fixture-source-commit'}}]}))
    (root / 'report.md').write_text('Fixture report\n')
    return root, seal_package(root)


def test_unmodified_package_verifies(package):
    root, anchor = package
    assert verify_package(root, anchor)
    assert not verify_package(root, None)
    assert not verify_package(root, '0' * 64)


@pytest.mark.parametrize('target', ['source', 'totals', 'record', 'ordering', 'identity',
                                    'local_verdict', 'global_verdict', 'decision', 'protected_state'])
def test_metadata_and_record_tampering_rejected(package, target):
    root, anchor = package
    path = root / 'traces.json'
    data = json.loads(path.read_text())
    row = data['arms']['hierarchical'][-1]
    if target == 'source':
        data['metadata']['source_commit'] = 'forged-source'
    elif target == 'totals':
        data['metadata']['observed_totals']['hierarchical'] = 120
    elif target == 'ordering':
        data['arms']['hierarchical'].reverse()
    elif target == 'identity':
        row['session_id'] = 'forged-session'
    elif target == 'record':
        row['action']['args']['records'].append('synthetic-forged')
    elif target in ('local_verdict', 'global_verdict'):
        row[target]['verdict'] = 'forged-verdict'
    elif target == 'decision':
        row['execution_decision']['verdict'] = 'PERMIT'
    else:
        row['after'].append('synthetic-forged-state')
    path.write_text(json.dumps(data))
    assert not verify_package(root, anchor)
    # Regenerating a consistent manifest still cannot match the RETAINED anchor.
    assert seal_package(root) != anchor
    assert not verify_package(root, anchor)


@pytest.mark.parametrize('target', ['traces.csv', 'config.json', 'fixture.json', 'validation.json', 'report.md', 'manifest', 'missing', 'extra'])
def test_other_covered_artifact_tampering_rejected(package, target):
    root, anchor = package
    if target == 'manifest':
        path = root / 'package-manifest.json'
        data = json.loads(path.read_text())
        data['artifacts']['traces.json'] = '0' * 64
        path.write_text(canonical(data))
    elif target == 'missing':
        (root / 'traces.csv').unlink()
    elif target == 'extra':
        (root / 'forged-extra.txt').write_text('extra')
    else:
        with (root / target).open('a') as handle:
            handle.write('tampered')
    assert not verify_package(root, anchor)


def test_self_supplied_replacement_anchor_does_not_authenticate_source(package):
    root, original_anchor = package
    path = root / 'traces.json'
    data = json.loads(path.read_text())
    data['metadata']['source_commit'] = 'forged-source'
    path.write_text(json.dumps(data))
    replacement = seal_package(root)
    assert not verify_package(root, original_anchor)
    assert verify_package(root, replacement)  # Hash consistency, not authenticity.
