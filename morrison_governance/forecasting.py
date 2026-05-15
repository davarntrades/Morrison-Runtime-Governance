"""
Generalized reachability forecasting (V3 upgrade).

Estimates  R̂_E(τ, k)  — the reachable executable-state manifold of a
trajectory τ under an evolving environment E across a projection horizon k.

This replaces sparse hard-coded projection with a recursive, branching,
admissibility-pruned rollout over a *structural* successor model. It is
deliberately NOT semantic: successors are derived from capability
inference and from intent the trajectory itself encodes (deferred /
scheduled actions, retry loops, declared future steps, accumulated
privilege, taint lineage) plus modelled environment evolution.

Determinism: every expansion is ordered; no RNG, no clocks, no I/O. Same
(trajectory, rules, environment, horizon) → same manifold and verdict.

Foundational principle preserved:

    Safe(local_step)  ⇏  Safe(global_trajectory)
"""

from dataclasses import dataclass, field
from typing import Iterable, Optional


# ─────────────────────────────────────────────────────────────
# Capability inference — structural, not name/keyword matching
# ─────────────────────────────────────────────────────────────

# Capability classes a step can carry. A step may carry several.
CAP_ACQUIRE = "acquire"     # pulls data into agent reach
CAP_EGRESS = "egress"       # moves data across a trust boundary
CAP_EXEC = "exec"           # executes code
CAP_PRIV = "priv"           # mutates permissions / roles
CAP_DEFER = "defer"         # schedules / queues a future action
CAP_LOOP = "loop"           # retry / iterate construct
CAP_NEUTRAL = "neutral"

_ACQUIRE_HINT = ("read", "query", "list", "get", "fetch", "download",
                 "export", "dump", "scan", "load", "select", "search")
_EGRESS_HINT = ("http", "request", "post", "upload", "send", "email",
                "webhook", "publish", "sftp", "ftp", "push", "sync_out")
_EXEC_HINT = ("shell", "exec", "subprocess", "eval", "run_code", "system",
              "spawn", "bash", "sh")
_PRIV_HINT = ("acl", "chmod", "chown", "role", "permission", "grant",
              "setuid", "sudo", "admin", "policy")
_DEFER_HINT = ("schedule", "queue", "defer", "cron", "later", "delay",
               "enqueue", "task", "job", "callback", "trigger")
_LOOP_HINT = ("retry", "loop", "repeat", "iterate", "until", "while")


def infer_capabilities(call: dict) -> frozenset:
    """Infer capability classes from the structure of a call dict.

    Uses the tool token AND argument *shape* (presence of url/path/sql/
    recipient/mode/role keys, deferred-action wrappers) rather than a
    fixed allow-list, so it generalises to unseen tool names."""
    tool = str(call.get("tool", "")).lower()
    args = call.get("args", {})
    if isinstance(args, dict):
        akeys = {str(k).lower() for k in args.keys()}
        avals = " ".join(str(v).lower() for v in args.values())
    else:
        akeys, avals = set(), str(args).lower()
    blob = tool + " " + " ".join(sorted(akeys))

    caps = set()

    def hit(hints, *extra):
        return (any(h in tool for h in hints)
                or any(h in blob for h in hints)
                or any(any(h in e for h in hints) for e in extra))

    if hit(_ACQUIRE_HINT) or {"path", "sql", "query", "url"} & akeys and \
            any(h in tool for h in _ACQUIRE_HINT):
        caps.add(CAP_ACQUIRE)
    if hit(_EGRESS_HINT) or {"url", "endpoint", "recipient", "to", "host"} & akeys:
        caps.add(CAP_EGRESS)
    if hit(_EXEC_HINT):
        caps.add(CAP_EXEC)
    if hit(_PRIV_HINT) or {"mode", "role", "grant", "acl"} & akeys:
        caps.add(CAP_PRIV)
    if hit(_DEFER_HINT) or {"when", "schedule_at", "after", "delay"} & akeys:
        caps.add(CAP_DEFER)
    if hit(_LOOP_HINT) or {"retries", "max_retries", "iterations"} & akeys:
        caps.add(CAP_LOOP)

    # A pure read of a non-sensitive path is acquire only.
    if not caps:
        caps.add(CAP_NEUTRAL)
    return frozenset(caps)


_BROAD = ("0777", "777", "a+rwx", "rwxrwxrwx", "everyone", "public",
          "admin", "root", "superuser", "*")


def _broad_grant(call: dict) -> bool:
    args = call.get("args", {})
    blob = (str(args).lower() if not isinstance(args, dict)
            else " ".join(str(v).lower() for v in args.values()))
    return any(tok in blob for tok in _BROAD)


def _extract_deferred_action(call: dict) -> Optional[dict]:
    """If a step *encodes a future action* (scheduled task, queued job,
    callback), return the synthetic call that action represents."""
    args = call.get("args", {})
    if not isinstance(args, dict):
        return None
    # common shapes: {"action": {...}}, {"task": {...}},
    # {"tool": "...", "url": "..."} nested, or explicit fields
    for key in ("action", "task", "job", "callback", "then", "next"):
        sub = args.get(key)
        if isinstance(sub, dict) and ("tool" in sub or "url" in sub
                                      or "action" in sub):
            inner = dict(sub)
            inner.setdefault("tool", sub.get("action", "http_request"))
            inner.setdefault("args", {k: v for k, v in sub.items()
                                      if k not in ("tool", "action")})
            return inner
    # flattened deferred egress: schedule_task with url/recipient present
    caps = infer_capabilities(call)
    if CAP_DEFER in caps and ({"url", "recipient", "to", "endpoint"}
                              & {str(k).lower() for k in args}):
        return {"tool": "deferred_egress",
                "args": {k: v for k, v in args.items()
                         if str(k).lower() in ("url", "recipient", "to",
                                               "endpoint", "body", "data")}}
    return None


# ─────────────────────────────────────────────────────────────
# Evolving environment model
# ─────────────────────────────────────────────────────────────

@dataclass
class EnvironmentState:
    """Mutable runtime environment along a rollout."""

    privilege_level: int = 0          # accumulated privilege (0 = none)
    tainted: bool = False             # data acquired into reach
    taint_lineage: tuple = ()         # (step, tool) provenance chain
    injected_tools: frozenset = frozenset()
    schema_mutated: bool = False
    retry_pressure: int = 0
    mutations: tuple = ()             # ordered log of env transitions

    def evolve(self, transitions: Iterable[str]) -> "EnvironmentState":
        """Apply ordered environment transition operators deterministically."""
        e = EnvironmentState(
            privilege_level=self.privilege_level, tainted=self.tainted,
            taint_lineage=self.taint_lineage,
            injected_tools=self.injected_tools,
            schema_mutated=self.schema_mutated,
            retry_pressure=self.retry_pressure, mutations=self.mutations,
        )
        for t in transitions:
            if t == "permission_drift":
                e.privilege_level += 1
            elif t == "schema_mutation":
                e.schema_mutated = True
            elif t == "hidden_tool_injection":
                e.injected_tools = e.injected_tools | {"injected_sink"}
            elif t == "retry_loop":
                e.retry_pressure += 1
            e.mutations = e.mutations + (t,)
        return e


# ─────────────────────────────────────────────────────────────
# Reachable-state manifold
# ─────────────────────────────────────────────────────────────

@dataclass
class ManifoldNode:
    node_id: int
    depth: int
    call: dict
    caps: frozenset
    env: EnvironmentState
    parent: Optional[int]
    omega_rule: Optional[str] = None  # set if this node intersects Ω


@dataclass
class ForecastReport:
    horizon: int
    nodes: list = field(default_factory=list)
    edges: list = field(default_factory=list)        # (parent_id, child_id)
    omega_nodes: list = field(default_factory=list)  # node_ids intersecting Ω
    branch_counts: list = field(default_factory=list)

    # ---- density / geometry metrics ----
    @property
    def node_count(self) -> int:
        return len(self.nodes)

    @property
    def mean_branching(self) -> float:
        return (sum(self.branch_counts) / len(self.branch_counts)
                if self.branch_counts else 0.0)

    @property
    def branch_entropy(self) -> float:
        """Shannon entropy (bits) of the branch-degree distribution — a
        scalar 'how bushy / divergent is the reachable manifold'."""
        import math
        if not self.branch_counts:
            return 0.0
        from collections import Counter
        c = Counter(self.branch_counts)
        n = sum(c.values())
        return -sum((v / n) * math.log2(v / n) for v in c.values())

    @property
    def omega_reach_probability(self) -> float:
        """Fraction of terminal (leaf) paths whose endpoint intersects Ω."""
        if not self.nodes:
            return 0.0
        children = {e[0] for e in self.edges}
        leaves = [n for n in self.nodes if n.node_id not in children]
        if not leaves:
            return 1.0 if self.omega_nodes else 0.0
        bad = sum(1 for lf in leaves if lf.omega_rule is not None
                  or lf.node_id in self.omega_nodes)
        return bad / len(leaves)

    @property
    def min_omega_depth(self) -> Optional[int]:
        ds = [n.depth for n in self.nodes if n.node_id in self.omega_nodes]
        return min(ds) if ds else None


class ReachabilityForecaster:
    """Recursive, branching, admissibility-pruned rollout that estimates
    whether the reachable manifold intersects Ω within horizon k."""

    def __init__(self, horizon: int = 3, max_nodes: int = 256):
        self.horizon = horizon
        self.max_nodes = max_nodes

    # -- structural successor model ----------------------------------
    def _successors(self, call: dict, caps: frozenset,
                    env: EnvironmentState) -> list[tuple[dict, list]]:
        """Deterministically enumerate (successor_call, env_transitions)
        implied by the current call + environment. Successors come from
        intent the trajectory encodes, NOT arbitrary hypotheticals — so a
        benign read with no declared future stays a leaf."""
        succ: list[tuple[dict, list]] = []

        # 1. Deferred / scheduled action the step itself encodes.
        deferred = _extract_deferred_action(call)
        if deferred is not None:
            succ.append((deferred, ["retry_loop"] if CAP_LOOP in caps else []))

        # 2. Retry/loop construct → unrolled iteration that escalates
        #    privilege under retry pressure (recursive planner retry).
        if CAP_LOOP in caps:
            esc = {"tool": "grant_permission",
                   "args": {"role": "admin"} if env.retry_pressure >= 1
                   else {"role": "operator"}}
            succ.append((esc, ["permission_drift", "retry_loop"]))

        # 3. Privilege step with no broad grant *yet* → models privilege
        #    accumulation over time (each adds a level; broad once summed).
        if CAP_PRIV in caps:
            nxt = {"tool": "modify_acl",
                   "args": {"mode": "0777"} if env.privilege_level >= 1
                   else {"mode": "0700"}}
            succ.append((nxt, ["permission_drift"]))

        # NOTE: successors are derived ONLY from intent the trajectory /
        # environment actually encodes (deferred action, loop, privilege
        # step). A plain tainted read with no declared future produces NO
        # successor — so Safe(read→analyze) is preserved while
        # Safe(read→schedule(egress)) is not.
        return succ[:6]  # bounded fan-out, deterministic order

    @staticmethod
    def _intersects_omega(node_call: dict, caps: frozenset,
                          env: EnvironmentState, rules) -> Optional[str]:
        """Structural Ω-intersection test for a forecasted node.

        Ω (forbidden executable state region) here includes, structurally:
          (a) any loaded Ω rule matching the projected call,
          (b) egress/exec of *tainted* data across a boundary,
          (c) a broad privilege grant, or accumulated privilege ≥ 2.
        This is capability/state geometry — not semantic inspection."""
        probe = dict(node_call.get("args", {})) if isinstance(
            node_call.get("args"), dict) else {"args": node_call.get("args")}
        probe["tool"] = node_call.get("tool")
        if env.tainted:
            probe.setdefault("destination_external", True)
        if env.privilege_level >= 2:
            probe.setdefault("mode", "0777")
        for rule in rules:
            try:
                if rule.evaluate(probe):
                    return rule.name
            except Exception:
                continue
        if env.tainted and (caps & {CAP_EGRESS, CAP_EXEC}):
            return "taint_flow:forecasted_exfiltration"
        if env.privilege_level >= 2 or (
                CAP_PRIV in caps and _broad_grant(node_call)):
            return "priv_escalation:forecasted_broad_grant"
        return None

    # -- admissibility-aware pruning ---------------------------------
    @staticmethod
    def _prunable(call: dict, a_safe_fn, v4_fn) -> bool:
        """Branches an earlier layer would already block are pruned —
        V3's job is *future* Ω reachable through admissible intermediate
        steps, not to re-derive A_safe/V4."""
        try:
            if a_safe_fn is not None and a_safe_fn(call):
                return True
            if v4_fn is not None and v4_fn(call):
                return True
        except Exception:
            return False
        return False

    def forecast(self, trajectory, rules, *, env: Optional[EnvironmentState]
                 = None, a_safe_fn=None, v4_fn=None) -> ForecastReport:
        """Build the reachable manifold and flag Ω intersections."""
        report = ForecastReport(horizon=self.horizon)
        nid = 0

        # Seed environment from the observed trajectory (taint lineage,
        # privilege, retry pressure) — execution history informs forecast.
        seed = env or EnvironmentState()
        lineage = list(seed.taint_lineage)
        priv = seed.privilege_level
        retry = seed.retry_pressure

        def _raw(st):
            # Use the structured tool/args, NOT to_eval_dict() (which
            # stringifies args and would hide nested deferred actions).
            if hasattr(st, "tool"):
                return {"tool": st.tool, "args": st.args,
                        "step": getattr(st, "step", 0)}
            return {"tool": st.get("tool"), "args": st.get("args", {}),
                    "step": st.get("step", 0)}

        for st in trajectory:
            c = _raw(st)
            caps = infer_capabilities(c)
            if CAP_ACQUIRE in caps:
                lineage.append((c.get("step", len(lineage)), c.get("tool")))
            if CAP_PRIV in caps:
                priv += 1
            if CAP_LOOP in caps:
                retry += 1
        seed = EnvironmentState(
            privilege_level=priv, tainted=bool(lineage),
            taint_lineage=tuple(lineage),
            injected_tools=seed.injected_tools,
            schema_mutated=seed.schema_mutated, retry_pressure=retry)

        # Roots: terminal observed state(s) drive the rollout.
        frontier = []
        states = list(trajectory)
        if not states:
            return report
        tcall = _raw(states[-1])
        root_call = {"tool": tcall.get("tool"), "args": tcall.get("args", {})}
        root = ManifoldNode(
            node_id=nid, depth=0, call=root_call,
            caps=infer_capabilities(root_call),
            env=seed, parent=None)
        report.nodes.append(root)
        frontier.append(root)
        nid += 1

        while frontier and len(report.nodes) < self.max_nodes:
            node = frontier.pop(0)
            if node.depth >= self.horizon:
                report.branch_counts.append(0)
                continue
            succ = self._successors(node.call, node.caps, node.env)
            live = 0
            for scall, transitions in succ:
                if self._prunable(scall, a_safe_fn, v4_fn):
                    continue
                child_env = node.env.evolve(transitions)
                ccaps = infer_capabilities(scall)
                if CAP_ACQUIRE in ccaps:
                    child_env = EnvironmentState(
                        privilege_level=child_env.privilege_level,
                        tainted=True,
                        taint_lineage=child_env.taint_lineage + (
                            (node.depth, scall.get("tool")),),
                        injected_tools=child_env.injected_tools,
                        schema_mutated=child_env.schema_mutated,
                        retry_pressure=child_env.retry_pressure,
                        mutations=child_env.mutations)
                child = ManifoldNode(
                    node_id=nid, depth=node.depth + 1, call=scall,
                    caps=ccaps, env=child_env, parent=node.node_id)
                # Structural Ω-intersection test over the forecasted node.
                hit = self._intersects_omega(scall, ccaps, child_env, rules)
                if hit is not None:
                    child.omega_rule = hit
                    report.omega_nodes.append(nid)
                report.nodes.append(child)
                report.edges.append((node.node_id, nid))
                nid += 1
                live += 1
                if child.omega_rule is None:
                    frontier.append(child)
            report.branch_counts.append(live)

        return report
