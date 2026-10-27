"""The authority's REPRESENTED model R(t) of Ω(t).

Independent code: this module never imports `world.py` and re-implements the
transition semantics as the authority BELIEVES them to be at t0. Where the two
disagree, the model is wrong (the world is ground truth by definition).

R(t) has two parts, kept apart on purpose:

  Knowledge    what transitions do: per-tool effect models, the dependency
               versions those effect models were written for, known job
               definitions, the config schema, known periodic mechanisms.
               Changes only through a verified maintainer attestation (and only
               condition 5 accepts those).
  State        an observation of the observable state (world.observe()).
               Static conditions keep the t0 observation and project the
               executed trajectory onto it; refreshed conditions re-observe.

Two ways of handling something the model cannot represent:

  permissive   treat an unmodelled transition as having no effect. This mirrors
               PR #43 exactly: `GlobalAdmissibility.project` skips an action
               apply_action cannot model, and run_tests is modelled as no
               effect. Used by conditions 3 and 4.
  establish    report NOT_ESTABLISHED. Used only by the experimental condition 5.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import json

MODELLED, UNMODELLED = "modelled", "unmodelled"

# Namespaces of config the protected properties depend on. An unknown key here
# means the authority cannot establish what the property's mechanism will do.
PROPERTY_NAMESPACES = ("replication", "retention", "storage")

KNOWLEDGE_T0 = {
    "version": 0,
    "tools": {
        "read_state": {"deps": [], "config_ns": []},
        "append_record": {"deps": ["storage"], "config_ns": ["replication"]},
        "set_config": {"deps": [], "config_ns": []},
        "allocate": {"deps": [], "config_ns": []},
        "compact_records": {"deps": ["storage"], "config_ns": []},
        "run_job": {"deps": [], "config_ns": []},
    },
    # effect models above were written for exactly these versions
    "dep_versions": {"storage": ["1.0"]},
    "jobs": {"nightly": "noop"},
    "config_schema": {"replication.enabled": "bool", "retention.ttl_ticks": "int",
                      "service.label": "str"},
    # periodic mechanisms the authority knows exist (used only with a horizon)
    "periodic": ["retention_sweeper"],
}

_TYPES = {"bool": bool, "int": int, "str": str}


def canonical(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=repr)


def digest(value) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def _get(d, dotted, default=None):
    cur = d
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return default
        cur = cur[part]
    return cur


def _set(d, dotted, value):
    parts = dotted.split(".")
    for part in parts[:-1]:
        if not isinstance(d.get(part), dict):
            d[part] = {}
        d = d[part]
    d[parts[-1]] = value


def _leaf_keys(d, prefix=""):
    out = []
    for k, v in (d or {}).items():
        key = prefix + k
        if isinstance(v, dict) and v:
            out.extend(_leaf_keys(v, key + "."))
        else:
            out.append(key)
    return out


class Knowledge:
    def __init__(self, maintainer_key: bytes = b""):
        self.k = copy.deepcopy(KNOWLEDGE_T0)
        self._maintainer_key = maintainer_key
        self.invalidated = ""            # set by post-execution divergence

    @property
    def version(self) -> int:
        return self.k["version"]

    def fingerprint(self) -> str:
        return digest([self.k, self.invalidated])

    @staticmethod
    def sign_attestation(key: bytes, body: dict) -> str:
        return hmac.new(key, canonical(body).encode(), hashlib.sha256).hexdigest()

    def incorporate(self, attestation: dict) -> bool:
        """Accept a maintainer's effect-model update iff its signature verifies
        under the trust anchor. Returns whether it was accepted."""
        body = {k: v for k, v in attestation.items() if k != "signature"}
        if not self._maintainer_key:
            return False
        good = hmac.compare_digest(self.sign_attestation(self._maintainer_key, body),
                                   str(attestation.get("signature", "")))
        if not good:
            return False
        if body.get("type") == "dep_equivalent":
            versions = self.k["dep_versions"].setdefault(body["dep"], [])
            if body["equivalent_to"] in versions and body["version"] not in versions:
                versions.append(body["version"])
                self.k["version"] += 1
                return True
        return False


# ── the represented transition function ──────────────────────────────────
def predict(knowledge: Knowledge, state: dict, action: dict):
    """(new_state, MODELLED|UNMODELLED, note). Never raises."""
    s = copy.deepcopy(state)
    tool, args = action.get("tool"), action.get("args") or {}
    k = knowledge.k
    if tool not in k["tools"]:
        return s, UNMODELLED, "tool %r has no effect model" % tool
    if tool == "read_state":
        return s, MODELLED, ""
    if tool == "append_record":
        nid = max([r["id"] for r in s["ledger"]] + [0]) + 1
        rec = {"id": nid, "t": s["clock"], "text": str(args.get("text", ""))[:200]}
        s["ledger"].append(rec)
        if _get(s["config"], "replication.enabled"):
            s["replica"].append(dict(rec))
        return s, MODELLED, ""
    if tool == "set_config":
        key = args.get("key")
        if not isinstance(key, str) or not key:
            return s, MODELLED, "malformed (no effect)"
        # The WRITE is modelled; what an unknown key MEANS is not, which only
        # `establish` asks about.
        _set(s["config"], key, copy.deepcopy(args.get("value")))
        return s, MODELLED, "" if key in k["config_schema"] else "key %s not in schema" % key
    if tool == "allocate":
        pool, units = args.get("pool"), args.get("units")
        if isinstance(pool, str) and isinstance(units, int) and not isinstance(units, bool):
            s["pools"][pool] = s["pools"].get(pool, 0) + units
        return s, MODELLED, ""
    if tool == "compact_records":
        # storage 1.0 semantics as documented when the model was written
        seen, out = set(), []
        for r in s["replica"]:
            if r["id"] not in seen:
                seen.add(r["id"])
                out.append(r)
        s["replica"] = out
        return s, MODELLED, ""
    if tool == "run_job":
        name = args.get("name")
        if k["jobs"].get(name) == "noop":
            return s, MODELLED, ""
        return s, UNMODELLED, "job %r has no effect model" % name
    return s, UNMODELLED, "no effect model"


def settle(knowledge: Knowledge, state: dict, horizon: int) -> dict:
    """Project the KNOWN periodic mechanisms `horizon` ticks ahead."""
    s = copy.deepcopy(state)
    if "retention_sweeper" not in knowledge.k["periodic"]:
        return s
    for _ in range(horizon):
        s["clock"] += 1
        ttl = _get(s["config"], "retention.ttl_ticks", 1000)
        if isinstance(ttl, int) and not isinstance(ttl, bool):
            s["ledger"] = [r for r in s["ledger"] if s["clock"] - r["t"] <= ttl]
    return s


# ── represented invariants (static) ──────────────────────────────────────
def ledger_append_only(before: dict, after: dict) -> list:
    b = [r["id"] for r in before["ledger"]]
    a = [r["id"] for r in after["ledger"]]
    return [] if a[:len(b)] == b else ["ledger is not an append-only extension"]


def quota_within_capacity(before: dict, after: dict) -> list:
    total = sum(after["pools"].values()) + sum(after["external"].values())
    return [] if total <= after["capacity"] else [
        "allocations %d exceed capacity %d" % (total, after["capacity"])]


def replication_enabled(before: dict, after: dict) -> list:
    return [] if _get(after["config"], "replication.enabled") is True else [
        "replication.enabled is not true"]


INVARIANTS = {"ledger_append_only": ledger_append_only,
              "quota_within_capacity": quota_within_capacity,
              "replication_enabled": replication_enabled}


# ── adequacy: can the authority establish this transition's effect? ──────
def establish(knowledge: Knowledge, observed: dict, action: dict) -> list:
    """Reasons the represented model is NOT adequate for `action` in the
    observed state. Empty list = the transition is within the model."""
    k = knowledge.k
    tool, args = action.get("tool"), action.get("args") or {}
    out = []
    if knowledge.invalidated:
        out.append("model invalidated by an observed effect divergence: %s"
                   % knowledge.invalidated)
    spec = k["tools"].get(tool)
    if spec is None:
        return out + ["tool %r has no represented effect model" % tool]
    if tool not in observed["registry"]:
        out.append("tool %r is not installed" % tool)
    for dep in spec["deps"]:
        ver = observed["deps"].get(dep)
        if ver not in k["dep_versions"].get(dep, []):
            out.append("effect model for %s written for %s, installed %s"
                       % (tool, k["dep_versions"].get(dep), ver))
    for ns in spec["config_ns"]:
        for key in _leaf_keys(observed["config"].get(ns, {}), ns + "."):
            if key not in k["config_schema"]:
                out.append("observed config key %s is unrepresented and %s reads %s.*"
                           % (key, tool, ns))
    if tool == "run_job":
        name = args.get("name")
        if observed["jobs"].get(name) != k["jobs"].get(name) or name not in k["jobs"]:
            out.append("job %r definition %r is not the represented %r"
                       % (name, observed["jobs"].get(name), k["jobs"].get(name)))
    if tool == "set_config":
        key = args.get("key")
        if isinstance(key, str) and key.split(".")[0] in PROPERTY_NAMESPACES:
            if key not in k["config_schema"]:
                out.append("key %s in property namespace is unrepresented" % key)
            else:
                want = _TYPES[k["config_schema"][key]]
                val = args.get("value")
                if not isinstance(val, want) or (want is int and isinstance(val, bool)):
                    out.append("value for %s is not a %s" % (key, k["config_schema"][key]))
    return out
