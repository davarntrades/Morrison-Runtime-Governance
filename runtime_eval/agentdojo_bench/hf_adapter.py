"""Exact-checkpoint HF routing, metered before each request; no local weights."""
from __future__ import annotations

import json
import os
import re
import time
from dataclasses import asdict, dataclass
from pathlib import Path

import httpx
from openai import OpenAI, APIStatusError
from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.agent_pipeline.llms.openai_llm import (
    _function_to_openai, _openai_to_assistant_message,
)
from runtime_eval.agentdojo_bench.anthropic_adapter import BudgetExceeded, _episode_label

CHECKPOINT = 'huihui-ai/Qwen3-32B-abliterated'
MODEL = CHECKPOINT + ':featherless-ai'
BASE_URL = 'https://router.huggingface.co/v1'
SOURCE_REVISION = '7a754614e9172cd416b4652342084bea8b5c98b0'
INPUT_PRICE = 0.408
OUTPUT_PRICE = 1.972
CONTEXT = 32768


@dataclass(frozen=True)
class HFSettings:
    model: str = MODEL
    base_url: str = BASE_URL
    temperature: float = 0.0
    max_tokens: int = 4096
    timeout_s: float = 90.0

    def __post_init__(self):
        if self.model != MODEL or self.base_url != BASE_URL:
            raise ValueError('checkpoint/provider substitution is forbidden')
        if not 1 <= self.max_tokens <= 4096:
            raise ValueError('output limit outside approved range')

    def as_dict(self):
        return {**asdict(self), 'checkpoint': CHECKPOINT, 'backend': 'featherless-ai',
                'source_revision': SOURCE_REVISION, 'served_revision': None,
                'served_revision_status': 'UNVERIFIED', 'precision': 'FP8 (provider advertised)',
                'thinking': 'provider default; no unsupported override sent',
                'tool_choice': 'auto', 'fallbacks': 'disabled by exact provider suffix',
                'input_usd_per_mtok': INPUT_PRICE, 'output_usd_per_mtok': OUTPUT_PRICE}


class HFBudget:
    """Durable total-run ceiling plus per-arm accounting, including unknown charges.

    Reserve the entire possible context and output before dispatch. Ambiguous
    failures retain the reservation and stop; retries cannot evade metering.
    This is a client-side conservative estimate, not an invoice guarantee.
    """
    def __init__(self, path: Path, max_usd=4.0, arm_cap=1.95, max_requests=300, prior_usage_usd=0.0):
        self.path, self.max_usd = path, max_usd
        self.arm_cap, self.max_requests = arm_cap, max_requests
        self.arm = 'canary'
        self.state = json.loads(path.read_text()) if path.exists() else {'attempts': []}
        if not 0 < max_usd <= 4.0:
            raise ValueError('initial total budget must be <= $4')
        if self.state.get('max_usd', max_usd) != max_usd:
            raise ValueError('cannot change a persisted budget')
        if not 0 <= prior_usage_usd < max_usd:
            raise ValueError('prior usage must leave positive authorized budget')
        if self.state.get('prior_usage_usd', prior_usage_usd) != prior_usage_usd:
            raise ValueError('cannot change persisted prior usage')
        self.state['prior_usage_usd'] = prior_usage_usd
        self.state['max_usd'] = max_usd

    @property
    def requests(self):
        return [r for r in self.state['attempts'] if r['arm'] == self.arm]

    def save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix('.tmp')
        tmp.write_text(json.dumps(self.state, indent=2))
        tmp.replace(self.path)

    def reserve(self, settings, messages, tools):
        # Byte-based bound avoids downloading a tokenizer or relying on a guess.
        encoded = json.dumps({'messages': messages, 'tools': tools}, ensure_ascii=False).encode()
        if len(encoded) > CONTEXT - settings.max_tokens - 2048:
            raise ValueError('request exceeds conservative context bound; no truncation')
        reserve = (CONTEXT * INPUT_PRICE + settings.max_tokens * OUTPUT_PRICE) / 1e6
        total = self.state['prior_usage_usd'] + sum(r['budget_charge_usd'] for r in self.state['attempts'])
        arm_spent = sum(r['budget_charge_usd'] for r in self.requests)
        cap = 0.10 if self.arm == 'canary' else self.arm_cap
        if len(self.requests) >= self.max_requests or total + reserve > self.max_usd or arm_spent + reserve > cap:
            raise BudgetExceeded('pre-dispatch total/arm/request budget reached')
        rec = {'arm': self.arm, 'episode': _episode_label(), 'status': 'pending',
               'budget_charge_usd': reserve, 'reserved_usd': reserve,
               'input_tokens': None, 'output_tokens': None, 'est_cost_usd': None,
               'requested_model': settings.model, 'served_model': None,
               'stop_reason': None, 'request_id': None, 'message_id': None}
        self.state['attempts'].append(rec)
        self.save()
        return rec

    def summary(self):
        reqs = self.requests
        return {'model': MODEL, 'max_usd': self.arm_cap, 'total_run_cap_usd': self.max_usd, 'prior_usage_usd': self.state['prior_usage_usd'],
                'max_requests': self.max_requests, 'requests': len(reqs),
                'input_tokens': sum(r['input_tokens'] or 0 for r in reqs),
                'output_tokens': sum(r['output_tokens'] or 0 for r in reqs),
                'est_cost_usd': round(sum(r['est_cost_usd'] or 0 for r in reqs), 8),
                'budget_charge_usd': round(sum(r['budget_charge_usd'] for r in reqs), 8),
                'unknown_charge_requests': sum(r['est_cost_usd'] is None for r in reqs),
                'served_models': sorted({r['served_model'] for r in reqs if r['served_model']}),
                'stop_reasons': {s: sum(r['stop_reason'] == s for r in reqs)
                                 for s in {str(r['stop_reason']) for r in reqs}}}


def message_to_wire(message):
    content = ''.join(b.get('content') or '' for b in message.get('content') or [])
    wire = {'role': message['role'], 'content': content}
    if message['role'] == 'assistant' and message.get('tool_calls'):
        wire['tool_calls'] = [{'id': c.id, 'type': 'function',
                               'function': {'name': c.function, 'arguments': json.dumps(c.args)}}
                              for c in message['tool_calls']]
    if message['role'] == 'tool':
        wire.update(tool_call_id=message['tool_call_id'], content=message.get('error') or content)
    return wire


class HFLLM(BasePipelineElement):
    def __init__(self, settings, budget, client=None):
        self.settings, self.budget = settings, budget
        self.model = self.name = settings.model
        self.client = client or OpenAI(base_url=settings.base_url, api_key=os.environ['HF_TOKEN'],
                                       timeout=settings.timeout_s, max_retries=0)

    def complete(self, messages, tools):
        rec = self.budget.reserve(self.settings, messages, tools)
        start = time.monotonic()
        try:
            result = self.client.chat.completions.create(
                model=self.model, messages=messages, tools=tools or None,
                tool_choice='auto' if tools else None, temperature=self.settings.temperature,
                max_tokens=self.settings.max_tokens)
            rec.update(served_model=result.model, message_id=result.id,
                       request_id=getattr(result, '_request_id', None),
                       stop_reason=result.choices[0].finish_reason,
                       raw_response=result.model_dump(mode='json'), status='success')
            if result.usage is None:
                raise RuntimeError('missing usage: stop with reserved unknown charge')
            p, c = result.usage.prompt_tokens, result.usage.completion_tokens
            if not isinstance(p, int) or not isinstance(c, int) or p < 0 or c < 0:
                raise RuntimeError('invalid usage')
            cost = (p * INPUT_PRICE + c * OUTPUT_PRICE) / 1e6
            rec.update(input_tokens=p, output_tokens=c, est_cost_usd=cost,
                       budget_charge_usd=cost)
            if cost > rec['reserved_usd'] + 1e-9:
                raise RuntimeError('reported usage exceeds conservative reservation')
            if result.model not in (CHECKPOINT, MODEL):
                raise RuntimeError('served model identity mismatch: no further calls')
            if result.choices[0].finish_reason in ('length', 'content_filter'):
                raise RuntimeError('truncated or filtered response; episode incomplete')
            return result
        except Exception as exc:
            rec.update(status='failed', error_type=type(exc).__name__,
                       http_status=getattr(exc, 'status_code', None) if isinstance(exc, APIStatusError) else None)
            if isinstance(exc, APIStatusError):
                # Retain bounded, redacted API denial diagnostics, never headers.
                detail = exc.response.text[:4000]
                token = os.environ.get('HF_TOKEN', '')
                if token:
                    detail = detail.replace(token, '[REDACTED]')
                detail = re.sub(r'hf_[A-Za-z0-9]+|(?i:Bearer)\s+[^\s\"<>]+', '[REDACTED]', detail)
                rec['api_error_redacted'] = detail
            raise RuntimeError(f'HF request failed ({type(exc).__name__}); no automatic retry') from None
        finally:
            rec['latency_s'] = round(time.monotonic() - start, 3)
            self.budget.save()

    def query(self, query, runtime, env, messages=(), extra_args=None):
        completion = self.complete([message_to_wire(m) for m in messages],
                                   [_function_to_openai(t) for t in runtime.functions.values()])
        output = _openai_to_assistant_message(completion.choices[0].message)
        # Parsing errors are failures, never manufactured calls or model refusals.
        return query, runtime, env, [*messages, output], dict(extra_args or {})


def get_json(url, token=None):
    headers = {'Authorization': f'Bearer {token}'} if token else {}
    with httpx.Client(timeout=30, follow_redirects=False) as client:
        response = client.get(url, headers=headers)
        response.raise_for_status()
        return response.json()


def preflight():
    token = os.environ.get('HF_TOKEN')
    report = {'checkpoint': CHECKPOINT, 'provider': 'featherless-ai', 'key_present': bool(token),
              'served_revision': None, 'served_revision_status': 'UNVERIFIED',
              'balance_usd': 9.65, 'balance_source': 'user-reported; no billing setting modified',
              'credit_eligibility': 'HF-routed requests eligible; canary verifies actual inference access'}
    hub = get_json(f'https://huggingface.co/api/models/{CHECKPOINT}?expand=sha&expand=gated&expand=inferenceProviderMapping')
    provider = get_json(f'https://api.featherless.ai/v1/models/{CHECKPOINT}')
    report.update(hub=hub, provider_metadata=provider)
    if hub['id'] != CHECKPOINT or hub['sha'] != SOURCE_REVISION:
        raise RuntimeError('source identity/revision changed: review before inference')
    mapping = hub.get('inferenceProviderMapping', {}).get('featherless-ai', {})
    if mapping.get('status') != 'live' or mapping.get('providerId') != CHECKPOINT:
        raise RuntimeError('exact backend unavailable')
    if provider['id'] != CHECKPOINT or provider.get('status') != 'active' or not provider.get('features', {}).get('tool_use'):
        raise RuntimeError('exact model/tool support unavailable')
    price = provider['pricing']
    if float(price['prompt']) * 1e6 > INPUT_PRICE + 1e-9 or float(price['completion']) * 1e6 > OUTPUT_PRICE + 1e-9:
        raise RuntimeError('price rose above approved accounting rates')
    if not token:
        report.update(ok=False, blocker='repository HF_TOKEN secret required')
        return report
    who = get_json('https://huggingface.co/api/whoami-v2', token)
    report['account'] = who.get('name')
    if report['account'] != 'Davarn11':
        raise RuntimeError('unexpected HF billing account')
    # Gated file access without model weights; never follow a credential-bearing redirect.
    with httpx.Client(timeout=30) as client:
        gate = client.get(f'https://huggingface.co/{CHECKPOINT}/resolve/{SOURCE_REVISION}/config.json',
                          headers={'Authorization': f'Bearer {token}'})
        report['repository_file_http_status'] = gate.status_code
        report['repository_download_access'] = ('allowed' if gate.status_code in (200, 302, 307) else 'denied_or_unavailable')
        report['repository_access_scope'] = 'Hub file access only; does not establish hosted inference authorization'
    models = get_json(BASE_URL + '/models', token)
    report['router_catalogue_lists_checkpoint'] = any(m.get('id') in (CHECKPOINT, MODEL) for m in models.get('data', []))
    report['router_catalogue_scope'] = 'Catalogue presence is advisory; exact HF mapping/provider metadata verified; canary tests explicit route'
    report.update(ok=True, inference_access='UNVERIFIED until paid canary',
                  router_auth='verified by authenticated model catalogue; paid canary still required')
    return report
