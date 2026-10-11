"""Repeatable adversarial review of matched conditions and 8-thread workloads."""
from __future__ import annotations

import argparse
import copy
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from experiments.local_global_admissibility.experiment import (
    IsolatedExecutor, candidate, send, run, verify, digest, VERSION, SESSION,
)
from experiments.local_global_admissibility.evidence_tools import now, environment, source_provenance


def reconstruct(rows):
    records = []
    for index, row in enumerate(rows):
        assert row['seq'] == index and row['before'] == records
        if row['executed']:
            assert row['execution_decision']['permitted'] is True
            records += row['action']['args']['records']
        assert row['after'] == records and row['total_after'] == len(records)
    assert verify(rows, rows[-1]['evidence_hash'])
    return records


def matched_boundary_review():
    """Capture exact common inputs before the authentic authority calls."""
    primary = run()
    boundary = {}
    reversed_arms = {}
    adapter_ids = []
    for mode in ('hierarchical', 'local_only'):
        executor = IsolatedExecutor(mode)
        adapter_ids.append((type(executor).submit, type(executor._lock)))
        captures = []
        original = executor.mode.decide
        def observed(agent, local, joint, action):
            captures.append(copy.deepcopy({
                'agent': agent, 'local': local, 'joint': joint, 'action': action,
                'protected_records': executor._records, 'used_actions': sorted(executor._used)}))
            return original(agent, local, joint, action)
        executor.mode.decide = observed
        for i in range(4):
            send(executor, candidate(i))
        rows = executor.trace()
        assert executor.snapshot() == reconstruct(rows)
        assert rows == primary[mode]
        boundary[mode] = captures
        reversed_arms[mode] = rows
    assert adapter_ids[0] == adapter_ids[1]
    assert boundary['hierarchical'] == boundary['local_only']
    return {'inputs': boundary, 'reversed_arms': reversed_arms,
            'equivalent_authority_entry': True, 'same_submit_implementation': True,
            'same_lock_type': True, 'reverse_order_equal': True}


def concurrent_review(trials=20):
    assert trials >= 20
    runs = []
    for mode in ('local_only', 'hierarchical'):
        for trial in range(trials):
            executor = IsolatedExecutor(mode)
            barrier = threading.Barrier(8)
            def worker(index):
                barrier.wait()
                return send(executor, candidate(index))
            with ThreadPoolExecutor(max_workers=8) as pool:
                list(pool.map(worker, range(8)))
            rows = executor.trace()
            records = reconstruct(rows)
            total = len(executor.snapshot())
            assert records == executor.snapshot()
            assert total == (240 if mode == 'local_only' else 90)
            assert all(r['local_verdict']['verdict'] == 'PERMIT' for r in rows)
            assert len(rows) == 8
            assert sum(r['executed'] for r in rows) == (8 if mode == 'local_only' else 3)
            runs.append({'mode': mode, 'trial': trial, 'submitted_actions': [candidate(i) for i in range(8)],
                         'serialization_schedule': [r['action']['args']['action_id'] for r in rows],
                         'total': total, 'rows': rows})
    return runs


def fault_review(kind):
    executor = IsolatedExecutor()
    def failed(*args):
        if kind == 'timeout':
            raise TimeoutError('injected global timeout')
        if kind == 'unavailable':
            raise ConnectionError('injected unavailable authority')
        if kind == 'malformed':
            return {'permitted': True, 'verdict': 'PERMIT'}
        raise RuntimeError('injected global exception')
    executor.mode.global_.decide = failed
    row = send(executor, candidate(0))
    assert row['local_verdict']['verdict'] == 'PERMIT'
    assert row['global_verdict']['verdict'] == 'ERROR'
    assert row['execution_decision']['verdict'] == 'BLOCK'
    assert not row['executed'] and row['before'] == row['after'] == executor.snapshot() == []
    assert [(e['tier'], e['event']) for e in row['evaluation_events']] == [
        ('local', 'START'), ('local', 'RESULT'), ('global', 'START'), ('global', 'ERROR')]
    return row


def identity_review():
    cases = {}
    for attack in ('session', 'principal', 'binding', 'forged_artifact', 'replay'):
        executor = IsolatedExecutor()
        request = candidate(0)
        principal = 'agent-0'
        if attack == 'session':
            request['args']['session_id'] = 'forged-session'
        if attack == 'principal':
            principal = 'agent-1'
        if attack == 'forged_artifact':
            request['authority'] = {'verdict': 'PERMIT', 'issuer': 'forged-authority'}
        binding = None if attack == 'binding' else digest(request)
        if attack == 'replay':
            send(executor, request)
        before = executor.snapshot()
        row = executor.submit(request, binding=binding, principal=principal)
        assert not row['executed'] and row['after'] == before == executor.snapshot()
        assert row['execution_decision']['verdict'] == 'BLOCK'
        cases[attack] = row
    return cases


def bypass_review():
    executor = IsolatedExecutor()
    executor._records.extend(['synthetic-direct-bypass'] * 120)
    assert len(executor.snapshot()) == 120 and executor.trace() == []
    return {'direct_python_access_bypasses_gate': True, 'total': len(executor.snapshot()),
            'decision_records': len(executor.trace()),
            'boundary': 'Trusted submission API only; Python object access is not isolated.'}


def review(trials=20):
    started = now()
    provenance = source_provenance()
    faults = {kind: fault_review(kind) for kind in ('exception', 'timeout', 'malformed', 'unavailable')}
    boundaries = {}
    for last in (20, 21):
        executor = IsolatedExecutor()
        send(executor, candidate(0, 40))
        send(executor, candidate(1, 40))
        row = send(executor, candidate(2, last))
        assert row['local_verdict']['verdict'] == 'PERMIT'
        assert row['total_after'] == (100 if last == 20 else 80)
        assert row['executed'] is (last == 20)
        boundaries[str(80 + last)] = executor.trace()
    data = {'started_at': started, 'provenance': provenance,
            'environment': environment(), 'fixture_version': VERSION,
            'session_id': SESSION, 'matched': matched_boundary_review(),
            'concurrent': concurrent_review(trials), 'faults': faults,
            'boundaries': boundaries, 'identities': identity_review(), 'bypass': bypass_review(),
            'concurrency_model': '8 threads released by one barrier; nondeterministic lock order recorded per trial',
            'sequential_workload': '4 distinct agents, 30 records each; 120 proposed',
            'concurrent_workload': '8 distinct agents, 30 records each; 240 proposed'}
    data['ended_at'] = now()
    return data


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    data = review()
    # All timestamps bracket the entire review, not just construction of metadata.
    data['ended_at'] = now()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(data, indent=2) + '\n')
    print(json.dumps({'concurrent_trials': len(data['concurrent']),
                      'matched_conditions': data['matched']['equivalent_authority_entry'],
                      'faults': {k: v['global_verdict']['verdict'] for k, v in data['faults'].items()},
                      'bypass': data['bypass']}, indent=2))


if __name__ == '__main__':
    main()
