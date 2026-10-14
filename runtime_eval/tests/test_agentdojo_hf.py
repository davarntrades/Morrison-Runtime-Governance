"""Offline controls; these tests are never reported as hosted inference evidence."""
import json

import httpx
import pytest
from openai import OpenAI
pytest.importorskip("agentdojo")

from agentdojo.types import text_content_block_from_string

from runtime_eval.agentdojo_bench.hf_adapter import (
    CHECKPOINT, MODEL, HFSettings, HFBudget, HFLLM, message_to_wire,
)
from runtime_eval.agentdojo_bench.anthropic_adapter import BudgetExceeded


def client(payload=None, fail=False):
    def respond(request):
        if fail:
            raise httpx.ReadTimeout('ambiguous timeout', request=request)
        return httpx.Response(200, json=payload or {
            'id': 'mock-1', 'object': 'chat.completion', 'created': 1, 'model': CHECKPOINT,
            'choices': [{'index': 0, 'finish_reason': 'stop',
                         'message': {'role': 'assistant', 'content': 'done'}}],
            'usage': {'prompt_tokens': 100, 'completion_tokens': 10, 'total_tokens': 110}},
            headers={'x-request-id': 'mock-request'})
    return OpenAI(api_key='test-only-placeholder', base_url='https://mock.invalid/v1',
                  max_retries=0, http_client=httpx.Client(transport=httpx.MockTransport(respond)))


def test_identity_is_strict():
    with pytest.raises(ValueError):
        HFSettings(model='Qwen/Qwen3-32B')
    with pytest.raises(ValueError):
        HFSettings(base_url='https://api.openai.com/v1')


def test_real_wire_system_role_and_zero_temperature(tmp_path):
    sent = []
    def respond(req):
        sent.append(json.loads(req.content))
        return httpx.Response(200, json={'id':'mock', 'object':'chat.completion', 'created':1,
            'model': CHECKPOINT, 'choices':[{'index':0,'finish_reason':'stop',
            'message':{'role':'assistant','content':'done'}}],
            'usage':{'prompt_tokens':100,'completion_tokens':10,'total_tokens':110}})
    sdk = OpenAI(api_key='placeholder', base_url='https://mock.invalid/v1', max_retries=0,
                 http_client=httpx.Client(transport=httpx.MockTransport(respond)))
    budget = HFBudget(tmp_path/'budget.json')
    llm = HFLLM(HFSettings(), budget, sdk)
    msg = message_to_wire({'role':'system', 'content':[text_content_block_from_string('unchanged')]})
    llm.complete([msg], [])
    assert sent[0]['messages'][0] == {'role':'system','content':'unchanged'}
    assert sent[0]['temperature'] == 0.0
    assert sent[0]['model'] == MODEL
    assert budget.requests[0]['est_cost_usd'] == pytest.approx(0.00006052)


def test_reserve_before_dispatch_and_shared_total(tmp_path):
    budget = HFBudget(tmp_path/'budget.json', max_usd=0.025)
    budget.reserve(HFSettings(), [], [])
    budget.arm = 'none'
    with pytest.raises(BudgetExceeded):
        budget.reserve(HFSettings(), [], [])
    reloaded = HFBudget(tmp_path/'budget.json', max_usd=0.025)
    assert len(reloaded.state['attempts']) == 1
    assert reloaded.state['attempts'][0]['status'] == 'pending'


def test_timeout_keeps_unknown_charge_no_retry(tmp_path):
    budget = HFBudget(tmp_path/'budget.json')
    with pytest.raises(RuntimeError, match='APITimeoutError'):
        HFLLM(HFSettings(), budget, client(fail=True)).complete([], [])
    assert len(budget.requests) == 1
    assert budget.requests[0]['est_cost_usd'] is None
    assert budget.requests[0]['budget_charge_usd'] > 0


def test_no_silent_context_truncation(tmp_path):
    budget = HFBudget(tmp_path/'budget.json')
    with pytest.raises(ValueError, match='context'):
        budget.reserve(HFSettings(), [{'role':'user','content':'x'*30000}], [])
    assert not budget.requests


def test_served_identity_mismatch_stops_after_metering(tmp_path):
    payload = {'id':'mock','object':'chat.completion','created':1,'model':'Qwen/Qwen3-32B',
        'choices':[{'index':0,'finish_reason':'stop','message':{'role':'assistant','content':'done'}}],
        'usage':{'prompt_tokens':100,'completion_tokens':10,'total_tokens':110}}
    budget = HFBudget(tmp_path/'budget.json')
    with pytest.raises(RuntimeError):
        HFLLM(HFSettings(), budget, client(payload)).complete([], [])
    assert budget.requests[0]['status'] == 'failed'
    assert budget.requests[0]['est_cost_usd'] > 0


def test_hf_and_bearer_redaction(tmp_path):
    from runtime_eval.agentdojo_bench.ci import redact_tree
    p = tmp_path/'data.json'
    p.write_text('hf_12345678901234567890 Bearer abcdefghijklmnop')
    found = redact_tree(tmp_path)
    assert found
    assert '1234567890' not in p.read_text()
    assert 'abcdefghijklmnop' not in p.read_text()


def test_missing_usage_keeps_reservation(tmp_path):
    payload = {'id':'mock','object':'chat.completion','created':1,'model':CHECKPOINT,
        'choices':[{'index':0,'finish_reason':'stop','message':{'role':'assistant','content':'done'}}]}
    budget = HFBudget(tmp_path/'budget.json')
    with pytest.raises(RuntimeError):
        HFLLM(HFSettings(), budget, client(payload)).complete([], [])
    assert budget.summary()['unknown_charge_requests'] == 1


def test_canary_requires_actual_structured_call(monkeypatch, tmp_path):
    from runtime_eval.agentdojo_bench import hf_runner
    monkeypatch.setattr(hf_runner, 'HFLLM', lambda settings,budget: HFLLM(settings,budget,client()))
    with pytest.raises(RuntimeError, match='structured tool call'):
        hf_runner.canary(HFSettings(), HFBudget(tmp_path/'budget.json'))


def test_hf_pipeline_has_same_executor_except_enforcement(monkeypatch, tmp_path):
    from runtime_eval.agentdojo_bench.live import build_pipeline, register_model_name
    from runtime_eval.agentdojo_bench import hf_adapter
    monkeypatch.setattr(hf_adapter, 'HFLLM', lambda settings,budget: HFLLM(settings,budget,client()))
    budget = HFBudget(tmp_path/'budget.json')
    a, ea = build_pipeline('hf', MODEL, 'banking', 'none', budget=budget,settings=HFSettings())
    b, eb = build_pipeline('hf', MODEL, 'banking', 'morrison',budget=budget,settings=HFSettings())
    assert type(ea) is type(eb)
    assert ea.enforce is False and eb.enforce is True
    assert a.elements[3].settings == b.elements[3].settings
    assert register_model_name('hf', MODEL) == 'Qwen'


def test_repository_download_denial_does_not_block_hosted_canary(monkeypatch):
    from runtime_eval.agentdojo_bench import hf_adapter as hf
    monkeypatch.setenv('HF_TOKEN', 'offline-placeholder')
    def metadata(url, token=None):
        if 'expand=sha' in url:
            return {'id':CHECKPOINT, 'sha':hf.SOURCE_REVISION, 'gated':'auto',
                    'inferenceProviderMapping':{'featherless-ai':{'status':'live','providerId':CHECKPOINT}}}
        if 'api.featherless.ai' in url:
            return {'id':CHECKPOINT,'status':'active','features':{'tool_use':True},
                    'pricing':{'prompt':0.000000408,'completion':0.000001972}}
        if 'whoami-v2' in url:
            return {'name':'Davarn11'}
        return {'data':[]}
    monkeypatch.setattr(hf, 'get_json', metadata)
    class FileClient:
        def __init__(self, **kwargs): pass
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def get(self, *args, **kwargs): return type('Reply', (), {'status_code':403})()
    monkeypatch.setattr(hf.httpx, 'Client', FileClient)
    report = hf.preflight()
    assert report['ok'] is True
    assert report['repository_file_http_status'] == 403
    assert report['inference_access'] == 'UNVERIFIED until paid canary'
    assert report['router_catalogue_lists_checkpoint'] is False
