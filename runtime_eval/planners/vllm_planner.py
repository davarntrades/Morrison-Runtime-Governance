"""vLLM planner adapter — high-throughput live planner.

vLLM is the production-throughput option: run as a separate process /
service and the middleware speaks to it over HTTP. This adapter is a
skeleton; fill in the endpoint and the body shape your vLLM deployment
expects. Defaults assume vLLM's OpenAI-compatible chat endpoint."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Optional

from runtime_eval.planners.base import PlannerInfo, ToolCall


_TOOL_CALL_RE = re.compile(
    r"\{[^{}]*\"tool\"\s*:\s*\"[^\"]+\"[^{}]*\"args\"\s*:\s*\{[^{}]*\}[^{}]*\}",
    re.DOTALL,
)


@dataclass
class VLLMPlanner:
    """HTTP client for a running vLLM server."""

    model_id: str
    endpoint: str = "http://localhost:8000/v1/chat/completions"
    api_key: str = "EMPTY"
    temperature: float = 0.0
    max_new_tokens: int = 256
    seed: int = 0
    system_prompt: Optional[str] = None
    tool_inventory: Optional[list[dict]] = None
    info: Optional[PlannerInfo] = None
    timeout_s: float = 60.0

    def __post_init__(self):
        if self.info is None:
            self.info = PlannerInfo(
                name=f"vllm.{self.model_id.split('/')[-1].lower()}",
                model_id=self.model_id, family="vllm",
                deterministic=(self.temperature == 0.0),
                temperature=self.temperature,
                max_new_tokens=self.max_new_tokens, seed=self.seed,
                extras={"endpoint": self.endpoint})

    def _system(self) -> str:
        inv = ""
        if self.tool_inventory:
            inv = "\nAvailable tools:\n" + "\n".join(
                f"  - {t['name']}: {t.get('description','')}"
                for t in self.tool_inventory)
        return (self.system_prompt or
                "You are a tool-using planner. Respond with a single "
                'JSON object {"tool":"<t>","args":{...}} only — no prose.'
                + inv)

    def _request(self, messages: list[dict]) -> str:
        import urllib.request
        body = {
            "model": self.model_id,
            "messages": messages,
            "temperature": self.temperature,
            "max_tokens": self.max_new_tokens,
            "seed": self.seed,
            "stream": False,
        }
        req = urllib.request.Request(
            self.endpoint,
            data=json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json",
                     "Authorization": f"Bearer {self.api_key}"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
        return payload["choices"][0]["message"]["content"]

    @staticmethod
    def _parse(text: str) -> Optional[ToolCall]:
        for blob in (text, text.strip().strip("`").strip()):
            try:
                obj = json.loads(blob)
                if isinstance(obj, dict) and "tool" in obj:
                    obj.setdefault("args", {})
                    if isinstance(obj["args"], dict):
                        return {"tool": str(obj["tool"]), "args": obj["args"]}
            except Exception:
                pass
        m = _TOOL_CALL_RE.search(text)
        if not m:
            return None
        try:
            obj = json.loads(m.group(0))
            if "tool" in obj and isinstance(obj.get("args", {}), dict):
                return {"tool": str(obj["tool"]), "args": obj["args"]}
        except Exception:
            return None
        return None

    def propose(self, observation: dict, history: list[ToolCall]) -> list[ToolCall]:
        msgs = [
            {"role": "system", "content": self._system()},
            {"role": "user",
             "content": ("History: " + json.dumps(history, ensure_ascii=False)
                         + "\nObservation: " + json.dumps(observation, ensure_ascii=False)
                         + "\nReply with one JSON tool-call.")},
        ]
        text = self._request(msgs)
        call = self._parse(text)
        return [call] if call else []
