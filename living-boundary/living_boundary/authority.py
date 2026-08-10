"""The authority boundary, stated as executable checks.

    The system may discover that the map is wrong.
    It does not receive authority to redraw the border.

This module makes that sentence something a run can VERIFY rather than
something a README asserts. It provides three independent kinds of check, and
`run_lb0` performs all three on every run:

  1. STATIC — an AST scan of this package for imports, calls and file writes
     that would give the Living Boundary a route into production governance.
     Static analysis is the right instrument here because the property is
     "there is no such code path", which no amount of runtime observation can
     establish.

  2. LIVE REFUSAL — the promotion lifecycle is exercised and must refuse.
     `CandidatePrimitive.advance(ENFORCED)` raising is a stronger statement
     than the absence of a call site, because it holds for callers that do not
     exist yet.

  3. FINGERPRINT — the production ruleset hash, capability policy and policy
     values are captured before and after the experiment and compared. The
     ruleset hash binds executable rule LOGIC (see
     `morrison_governance/kernel/evidence.py`), so this catches a mutation that
     left every rule name unchanged.

The scan deliberately EXCLUDES `tests/`. Test modules must name the forbidden
surfaces in order to prove they are refused, and a scanner that flagged its own
proof would force the proof to be deleted.
"""

from __future__ import annotations

import ast
from pathlib import Path

from living_boundary._repo_paths import ARTIFACTS_ROOT, PACKAGE_ROOT

# ── what LB-0 may import from the production engine ─────────────────────
# Read-only, side-effect-free surfaces only: the capability vocabulary, the
# capability policy table (read, never written), the evidence primitives, and
# the Ω rule registry needed to fingerprint production state.
ALLOWED_MORRISON_MODULES = frozenset({
    "morrison_governance",
    "morrison_governance.core",
    "morrison_governance.domains",
    "morrison_governance.kernel",
    "morrison_governance.kernel.capabilities",
    "morrison_governance.kernel.policy",
    "morrison_governance.kernel.evidence",
})

# Importing any of these would put an enforcement or execution surface within
# reach of the discovery layer.
FORBIDDEN_MORRISON_MODULES = frozenset({
    "morrison_governance.kernel.gate",
    "morrison_governance.kernel.trust",
    "morrison_governance.kernel.attestation",
    "morrison_governance.kernel.ed25519",
    "morrison_governance.integrations",
    "morrison_governance.interception",
    "morrison_governance.multiagent",
    "morrison_governance.planners",
})

# Call names that would exercise authority rather than observe it.
FORBIDDEN_CALLS = frozenset({
    "authorize", "execute", "submit", "record_remote_execution",
    "issue_approval", "consume_nonce", "add_rule", "add_domain",
    "add_admissibility_check", "verified_approval",
})

# Modules permitted to write to the filesystem at all. Everything else in the
# package is read-only by construction, so a future edit that starts writing
# state from the discovery layer fails this scan rather than shipping.
WRITE_CAPABLE_MODULES = frozenset({"evidence/provenance.py"})

# Filesystem-mutating calls. `open(..., "w")` is not the only way to write a
# file, and checking only for it would leave the obvious `Path.write_text`
# route open.
WRITE_CALLS = frozenset({"write_text", "write_bytes", "mkdir", "makedirs",
                         "unlink", "rmtree", "rename", "replace_file"})

AUTHORITY_INVARIANTS = (
    ("cannot_write_production_policy",
     "No module writes to morrison_governance configuration or source."),
    ("cannot_modify_ontology_versions",
     "Ontology versions are source constants; LB-0 has no setter for them."),
    ("cannot_transition_candidate_to_enforced",
     "The promotion lifecycle refuses APPROVED / SHADOW / ENFORCED."),
    ("cannot_bypass_approval_verification",
     "No approval artifact is constructed, signed or verified anywhere in LB-0."),
    ("cannot_invoke_provider_actions",
     "No execution or provider surface is imported or called."),
    ("cannot_disable_runtime_governance",
     "The production ruleset fingerprint is unchanged across a full run."),
)


class AuthorityViolation(RuntimeError):
    """Raised when a check finds a route from LB-0 into production authority."""


# ═══════════════════════════════════════════════════════════════════════
# 1. Static scan
# ═══════════════════════════════════════════════════════════════════════

def _package_modules(include_tests: bool = False):
    for path in sorted(Path(PACKAGE_ROOT).rglob("*.py")):
        relative = path.relative_to(PACKAGE_ROOT).as_posix()
        if not include_tests and relative.startswith("tests/"):
            continue
        if "__pycache__" in relative:
            continue
        yield relative, path


def _imported_modules(tree) -> list:
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            found.append(node.module)
            for alias in node.names:
                found.append(f"{node.module}.{alias.name}")
    return found


def _call_names(tree) -> list:
    names = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Attribute):
            names.append((func.attr, node))
        elif isinstance(func, ast.Name):
            names.append((func.id, node))
    return names


def write_mode(node) -> bool:
    """Does this `open(...)` call request a writable mode?"""
    for index, arg in enumerate(node.args):
        if index == 1 and isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            return any(ch in arg.value for ch in "wxa+")
    for keyword in node.keywords:
        if keyword.arg == "mode" and isinstance(keyword.value, ast.Constant):
            return any(ch in str(keyword.value.value) for ch in "wxa+")
    return False


def scan_static_authority(include_tests: bool = False) -> list:
    """AST-scan the package for routes into production authority.

    Returns a list of violation strings; empty means the boundary holds.
    """
    violations = []
    for relative, path in _package_modules(include_tests=include_tests):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError as exc:                     # pragma: no cover
            violations.append(f"{relative}: cannot parse ({exc})")
            continue

        for module in _imported_modules(tree):
            root = module.split(".")[0]
            if root != "morrison_governance":
                continue
            if module in FORBIDDEN_MORRISON_MODULES:
                violations.append(
                    f"{relative}: imports enforcement surface {module!r}")
                continue
            # `from morrison_governance.kernel import capabilities as C` yields
            # both the module and module.attr; accept when either form is on the
            # allowlist.
            parent = module.rsplit(".", 1)[0]
            if module not in ALLOWED_MORRISON_MODULES and \
                    parent not in ALLOWED_MORRISON_MODULES:
                violations.append(
                    "{}: imports {!r}, which is outside the read-only "
                    "allowlist".format(relative, module))

        for name, node in _call_names(tree):
            if name in FORBIDDEN_CALLS:
                violations.append(
                    "{}:{}: calls {!r}, an authority-exercising surface".format(
                        relative, getattr(node, "lineno", 0), name))
            if relative in WRITE_CAPABLE_MODULES:
                continue
            if name == "open" and write_mode(node):
                violations.append(
                    "{}:{}: opens a file for writing outside the evidence "
                    "writer".format(relative, getattr(node, "lineno", 0)))
            elif name in WRITE_CALLS:
                violations.append(
                    "{}:{}: calls {!r}, a filesystem mutation outside the "
                    "evidence writer".format(
                        relative, getattr(node, "lineno", 0), name))
    return violations


# ═══════════════════════════════════════════════════════════════════════
# 2. Live refusal
# ═══════════════════════════════════════════════════════════════════════

def check_promotion_refusal() -> list:
    """Exercise the promotion lifecycle and require it to refuse."""
    from living_boundary.ontology.candidate_schema import (
        AuthorityBoundaryError, CandidatePrimitive, CandidateStatus,
    )

    violations = []
    for forbidden in (CandidateStatus.APPROVED, CandidateStatus.SHADOW,
                      CandidateStatus.ENFORCED):
        probe = CandidatePrimitive(candidate_id="AUTH-PROBE",
                                   name="authority_probe", description="probe")
        try:
            probe.advance(forbidden)
        except AuthorityBoundaryError:
            continue
        violations.append(
            "candidate lifecycle accepted transition to {}; the discovery layer "
            "must not be able to promote its own findings".format(forbidden))
    return violations


# ═══════════════════════════════════════════════════════════════════════
# 3. Production fingerprint
# ═══════════════════════════════════════════════════════════════════════

def production_fingerprint() -> dict:
    """A hash of the production enforcement configuration, read-only.

    `ruleset_hash` binds each rule's bytecode, constants, closure values and
    referenced globals — so this detects a rule whose LOGIC changed even when
    its name, domain and severity did not. That is the mutation an ordinary
    "did the config file change?" check would miss entirely.
    """
    from morrison_governance.core import GovernanceLayer
    from morrison_governance.domains import OmegaDomain
    from morrison_governance.kernel import policy as production_policy
    from morrison_governance.kernel.evidence import ruleset_hash

    layer = GovernanceLayer(
        domains=[OmegaDomain.FINANCE, OmegaDomain.CYBERSECURITY,
                 OmegaDomain.DATA_PRIVACY, OmegaDomain.ENTERPRISE],
        log_all=False)
    return {
        "ruleset_hash": ruleset_hash(
            layer.rules,
            extra={"capability_policy": production_policy.CAPABILITY_POLICY,
                   "policy_values": production_policy.DEFAULT_POLICY_VALUES}),
        "rules": len(layer.rules),
        "capability_policy": dict(production_policy.CAPABILITY_POLICY),
        "default_policy_values": dict(production_policy.DEFAULT_POLICY_VALUES),
    }


def compare_fingerprints(before: dict, after: dict) -> list:
    violations = []
    for key in sorted(set(before) | set(after)):
        if before.get(key) != after.get(key):
            violations.append(
                "production governance state changed during the LB-0 run: {} "
                "{!r} -> {!r}".format(key, before.get(key), after.get(key)))
    return violations


# ═══════════════════════════════════════════════════════════════════════
# Combined report
# ═══════════════════════════════════════════════════════════════════════

def artifacts_root_is_isolated() -> bool:
    """The only directory LB-0 writes to sits inside the prototype tree."""
    root = Path(ARTIFACTS_ROOT).resolve()
    return root.parent.name == "living-boundary"


def authority_report(before: dict = None, after: dict = None) -> dict:
    """Run every authority check and summarise. `reachable` must be False."""
    static = scan_static_authority()
    promotion = check_promotion_refusal()
    fingerprint = compare_fingerprints(before or {}, after or {}) \
        if (before is not None and after is not None) else []
    isolation = ([] if artifacts_root_is_isolated()
                 else ["LB-0 artifacts root is outside the prototype tree"])

    violations = static + promotion + fingerprint + isolation
    return {
        "production_authority_reachable": bool(violations),
        "invariants": [{"name": n, "statement": s} for n, s in AUTHORITY_INVARIANTS],
        "checks": {
            "static_import_and_call_scan": {
                "violations": static, "passed": not static},
            "promotion_lifecycle_refusal": {
                "violations": promotion, "passed": not promotion},
            "production_fingerprint_unchanged": {
                "violations": fingerprint, "passed": not fingerprint,
                "checked": bool(before is not None and after is not None)},
            "artifacts_isolated": {
                "violations": isolation, "passed": not isolation},
        },
        "violations": violations,
    }


def require_no_authority(report: dict) -> None:
    if report["production_authority_reachable"]:
        raise AuthorityViolation(
            "LB-0 authority boundary violated:\n  " +
            "\n  ".join(report["violations"]))
