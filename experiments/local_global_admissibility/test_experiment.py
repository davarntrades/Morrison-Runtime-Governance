import copy
from concurrent.futures import ThreadPoolExecutor
import threading

import pytest

from experiments.local_global_admissibility.experiment import (
    IsolatedExecutor, candidate, digest, run, send, verify,
)


def test_paired_cross_agent_composition():
    arms = run()
    assert [r['action'] for r in arms['local_only']] == [r['action'] for r in arms['hierarchical']]
    assert all(r['local_verdict']['verdict'] == 'PERMIT' for rows in arms.values() for r in rows)
    assert [r['executed'] for r in arms['local_only']] == [True] * 4
    assert [r['executed'] for r in arms['hierarchical']] == [True, True, True, False]
    assert arms['hierarchical'][-1]['global_verdict']['rule'] == 'fixture_joint_session_records_le_100'


@pytest.mark.parametrize('mode', ['local_only', 'hierarchical'])
@pytest.mark.parametrize('count,expected', [(1, True), (40, True), (41, False)])
def test_local_boundary(mode, count, expected):
    executor = IsolatedExecutor(mode)
    row = send(executor, candidate(0, count))
    assert row['executed'] is expected
    assert len(executor.snapshot()) == (count if expected else 0)


@pytest.mark.parametrize('last,total,execute', [(20, 100, True), (21, 80, False)])
def test_global_100_and_101(last, total, execute):
    executor = IsolatedExecutor()
    send(executor, candidate(0, 40))
    send(executor, candidate(1, 40))
    row = send(executor, candidate(2, last))
    assert row['local_verdict']['verdict'] == 'PERMIT'
    assert row['executed'] is execute
    assert len(executor.snapshot()) == total
    if not execute:
        assert row['before'] == row['after']


def test_reset_is_new_trusted_instance_and_snapshot_not_mutable():
    first = IsolatedExecutor()
    for i in range(4):
        send(first, candidate(i))
    snapshot = first.snapshot()
    snapshot.clear()
    assert len(first.snapshot()) == 90
    fresh = IsolatedExecutor()
    assert fresh.snapshot() == [] and fresh.trace() == []
    assert send(fresh, candidate(0))['total_before'] == 0


@pytest.mark.parametrize('attack', ['forged_session', 'missing_binding', 'wrong_binding', 'forged_principal', 'wrong_tool', 'empty_records'])
def test_boundary_fail_closed(attack):
    executor = IsolatedExecutor()
    request = candidate(0)
    principal = 'agent-0'
    if attack == 'forged_session':
        request['args']['session_id'] = 'attacker-reset-session'
    if attack == 'forged_principal':
        principal = 'agent-1'
    if attack == 'wrong_tool':
        request['tool'] = 'other_export'
    if attack == 'empty_records':
        request['args']['records'] = []
    binding = digest(request)
    if attack == 'missing_binding':
        binding = None
    if attack == 'wrong_binding':
        binding = digest(candidate(1))
    row = executor.submit(request, binding=binding, principal=principal)
    assert row['execution_decision']['verdict'] == 'BLOCK'
    assert not row['executed'] and row['before'] == row['after'] == []


@pytest.mark.parametrize('tier', ['local', 'global', 'whole_authority'])
def test_authority_failure(tier, monkeypatch):
    executor = IsolatedExecutor()
    def crash(*args):
        raise RuntimeError('injected authority failure')
    target = executor.mode if tier == 'whole_authority' else getattr(executor.mode, 'local' if tier == 'local' else 'global_')
    monkeypatch.setattr(target, 'decide', crash)
    row = send(executor, candidate(0))
    assert not row['executed'] and row['before'] == row['after'] == []
    assert row['execution_decision']['verdict'] == 'BLOCK'


@pytest.mark.parametrize('tier', ['local', 'global'])
def test_layer_failure_uses_existing_fail_closed_mode(tier, monkeypatch):
    executor = IsolatedExecutor()
    def crash(*args):
        raise RuntimeError('injected GovernanceLayer failure')
    if tier == 'global':
        monkeypatch.setattr(executor.mode.global_.gov, 'evaluate', crash)
    else:
        from experiments.local_global_admissibility.experiment import local_layer
        layer = local_layer()
        monkeypatch.setattr(layer, 'evaluate', crash)
        executor.mode.local._layers['agent-0'] = layer
    row = send(executor, candidate(0))
    assert row[f'{tier}_verdict']['rule'] == 'governance_error'
    assert not row['executed']


def test_replay_denied():
    executor = IsolatedExecutor()
    send(executor, candidate(0))
    row = send(executor, candidate(0))
    assert not row['executed'] and row['total_after'] == 30


def test_concurrent_check_and_commit():
    # All submitters start together. Which agent wins is unspecified; invariant isn't.
    for repetition in range(20):
        executor = IsolatedExecutor()
        barrier = threading.Barrier(8)
        def worker(i):
            barrier.wait()
            return send(executor, candidate(i))
        with ThreadPoolExecutor(max_workers=8) as pool:
            rows = list(pool.map(worker, range(8)))
        assert sum(r['executed'] for r in rows) == 3
        assert len(executor.snapshot()) == 90
        trace = executor.trace()
        assert [r['seq'] for r in trace] == list(range(8))
        assert all(a['after'] == b['before'] for a, b in zip(trace, trace[1:]))
        assert all(r['before'] == r['after'] for r in trace if not r['executed'])


def test_tamper_evidence_and_truncation():
    rows = run()['hierarchical']
    terminal = rows[-1]['evidence_hash']
    assert verify(rows, terminal)
    corrupted = copy.deepcopy(rows)
    corrupted[-1]['executed'] = True
    assert not verify(corrupted, terminal)
    assert not verify(rows[:-1], terminal)
    assert not verify(list(reversed(rows)), terminal)


def test_reproducible_trace():
    assert run() == run()


def test_process_privilege_is_outside_demonstrated_mediation():
    # Counterexample: trusted Python holder can bypass the fixture API.
    # This explicitly falsifies any claim of same-process hostile-code isolation.
    executor = IsolatedExecutor()
    executor._records.extend(['synthetic-bypass'] * 120)
    assert len(executor.snapshot()) == 120 and executor.trace() == []


def test_same_agent_local_allowance_is_per_candidate():
    executor = IsolatedExecutor()
    for i in range(3):
        assert send(executor, candidate(i, agent='agent-0'))['executed']
    row = send(executor, candidate(3, agent='agent-0'))
    assert row['local_verdict']['verdict'] == 'PERMIT'
    assert row['global_verdict']['verdict'] == 'BLOCK'
    assert row['total_after'] == 90
