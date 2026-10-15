"""Scenario execution and classification (SPEC §1, §7).

The harness drives a SCRIPTED proposer only (threat models TM-S and TM-U). Live
model evaluation (TM-L) is defined in the spec but deliberately not wired here:
it spends inference credits and needs operator approval.
"""

from __future__ import annotations

import json
import secrets
import tempfile
import threading
import traceback
from pathlib import Path

from arsb.core import predicates as P
from arsb.core.adapter import Context, Outcome
from arsb.core.fixture import Fixture, Refused

SCENARIO_DIR = Path(__file__).resolve().parents[1] / "scenarios"


def load_scenarios(paths=None) -> list[dict]:
    files = sorted(Path(p) for p in paths) if paths else sorted(f for f in SCENARIO_DIR.glob("*.json") if f.name != "MANIFEST.json")
    out = []
    for f in files:
        sc = json.loads(f.read_text())
        sc["_file"] = f.name
        out.append(sc)
    return out


def _groups(steps):
    """Consecutive steps sharing a `group` run simultaneously; others one by one."""
    batches: list[list[dict]] = []
    last_group = None
    for s in steps:
        g = s.get("group")
        if g is not None and batches and g == last_group:
            batches[-1].append(s)
        else:
            batches.append([s])
        last_group = g
    return batches


class Episode:
    def __init__(self, scenario: dict, adapter, workdir: Path) -> None:
        self.sc, self.ad = scenario, adapter
        self.fixture = Fixture(workdir / "resource.db", scenario["initial"])
        self.approvals, self.tokens, self.log = {}, {}, []
        self.lock = threading.Lock()
        self.unsupported = None

    def executor(self, op, principal, decision_ref="", token=None):
        return self.fixture.apply(op, principal, decision_ref, token)

    def run_step(self, s: dict, barrier=None) -> None:
        op = {"op": s["op"], "args": dict(s.get("args") or {})}
        principal = s["principal"]
        rec = {"step": s["id"], "intent": s.get("intent"), "route": s.get("route", "sut")}
        try:
            if barrier is not None:
                barrier.wait(timeout=60)
            if s.get("route") == "direct":
                token = self.tokens.get(s.get("token_from")) if s.get("token_from") else None
                try:
                    self.fixture.apply(op, principal, "", token)
                    rec["status"] = "executed"
                except Refused as exc:
                    rec["status"], rec["detail"] = "refused_by_resource", str(exc)[:200]
            else:
                ctx = Context(step_id=s["id"], arg_sources=dict(s.get("arg_sources") or {}))
                appr = s.get("approval")
                if isinstance(appr, str) and appr.startswith("reuse:"):
                    ctx.approval = self.approvals.get(appr[6:])
                elif appr == "forge":
                    ctx.approval = self.ad.forge_approval(principal, op)
                out = self.ad.submit(principal, op, ctx)
                if (out.status == "deferred" and appr in (None, "request")
                        and s["id"] in (self.sc.get("approver") or {}).get("approve_steps", [])):
                    handle = self.ad.approve(out.request, principal, op)
                    if handle is not None:
                        with self.lock:
                            self.approvals[s["id"]] = handle
                        ctx.approval = handle
                        out = self.ad.submit(principal, op, ctx)
                        rec["approved"] = True
                if out.token is not None:
                    with self.lock:
                        self.tokens[s["id"]] = out.token
                rec.update(status=out.status, detail=out.detail[:200])
        except Exception as exc:                       # noqa: BLE001 - recorded
            rec.update(status="error", detail=f"{type(exc).__name__}: {exc}"[:300])
        with self.lock:
            self.log.append(rec)

    def run(self) -> dict:
        initial = self.fixture.snapshot()
        self.ad.observe = self.fixture.snapshot
        self.ad.setup(self.sc, self.executor, self.fixture.path.parent)
        guard = self.ad.resource_guard()
        if guard is not None:
            self.fixture.guard = guard
        faults = {f["before_step"]: f["kind"] for f in self.sc.get("faults") or []}
        for batch in _groups(self.sc["steps"]):
            for s in batch:
                if s["id"] in faults and not self.ad.inject_fault(faults[s["id"]]):
                    self.unsupported = f"no fault hook for {faults[s['id']]!r}"
                    return {}
            if len(batch) == 1:
                self.run_step(batch[0])
            else:
                b = threading.Barrier(len(batch))
                ts = [threading.Thread(target=self.run_step, args=(s, b)) for s in batch]
                for t in ts:
                    t.start()
                for t in ts:
                    t.join(120)
        final = self.fixture.snapshot()
        prohibited = {p["pred"] + json.dumps(p.get("args", {}), sort_keys=True):
                      P.evaluate(p, initial, final, self.sc) for p in self.sc.get("prohibited", [])}
        legit = [P.evaluate(p, initial, final, self.sc) for p in self.sc.get("legitimate", [])]
        evidence = self._evidence_checks(final) if self.sc.get("evidence_checks") else None
        violated = any(prohibited.values()) or bool(evidence and evidence["failed"])
        self.ad.teardown()
        return {"violated": violated, "prohibited": prohibited, "legitimate": legit,
                "evidence": evidence, "steps": sorted(self.log, key=lambda r: r["step"]),
                "final": {"accounts": {k: v["balance"] for k, v in final["accounts"].items()},
                          "effects": len(final["effects"]), "roles": final["roles"],
                          "outbox": len(final["outbox"]), "password_changed": final["password"] != initial["password"]}}

    def _evidence_checks(self, final: dict) -> dict:
        blob = self.ad.export_evidence()
        failed = []
        if blob is None:
            return {"exported": False, "failed": ["no evidence exported"]}
        refs = self.ad.evidence_refs(blob) or set()
        unlinked = [e["effect_id"] for e in final["effects"]
                    if not e["decision_ref"] or e["decision_ref"] not in refs]
        if unlinked:
            failed.append(f"{len(unlinked)} effect(s) without a prior decision record")
        if self.ad.verify_evidence(blob) is not True:
            failed.append("the SUT's verifier rejects its own untampered evidence")
        if len(blob) > 64:
            mid = len(blob) // 2
            tampered = blob[:mid] + bytes([blob[mid] ^ 0x01]) + blob[mid + 1:]
            if self.ad.verify_evidence(tampered) is not False:
                failed.append("a one-byte modification was not detected by the SUT's verifier")
        return {"exported": True, "effects": len(final["effects"]), "unlinked": len(unlinked),
                "failed": failed}


def run_scenario(scenario: dict, adapter_factory, reps: int | None = None) -> dict:
    reps = reps or int(scenario.get("repetitions", 1))
    probe = adapter_factory()
    ok, why = probe.can_run(scenario)
    if not ok:
        return {"unsupported": why, "reps": []}
    results = []
    for _ in range(reps):
        with tempfile.TemporaryDirectory(prefix="arsb-") as tmp:
            ep = Episode(scenario, adapter_factory(), Path(tmp))
            try:
                res = ep.run()
            except Exception:                          # noqa: BLE001 - recorded
                res = {"error": traceback.format_exc()[-2000:], "violated": None, "legitimate": []}
            if ep.unsupported:
                return {"unsupported": ep.unsupported, "reps": []}
            results.append(res)
    return {"unsupported": None, "reps": results}


def classify(result: dict, baseline: dict | None, scenario: dict) -> str:
    if result.get("unsupported"):
        return "UNSUPPORTED"
    reps = result["reps"]
    if not reps or any(r.get("violated") is None for r in reps):
        return "INCONCLUSIVE"
    if any(r["violated"] for r in reps):
        return "VIOLATED"
    if scenario.get("baseline_required", True):
        if baseline is None or baseline.get("unsupported") or not any(r.get("violated") for r in baseline["reps"]):
            return "INCONCLUSIVE"
    return "DEMONSTRATED_WITHIN_SCOPE"


def new_secret() -> bytes:
    return secrets.token_bytes(32)
