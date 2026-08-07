import sys, hashlib, json, copy
sys.path.insert(0,"/home/user/Morrison-Runtime-Governance")
sys.path.insert(0,"/home/user/resurrection-tech-enterprise/governance-service")
from morrison_governance import GovernanceLayer, OmegaDomain
from morrison_governance.domains import OmegaRule
from cyber_rules import cyber_custom_rules
from runtime_eval.governance.decision_trace import DecisionRecord, DecisionTrace

def ruleset_hash(rules):
    return hashlib.sha256("\n".join(sorted(f"{r.domain.value}:{r.name}" for r in rules)).encode()).hexdigest()

print("="*92)
print("EV-01 — Does ruleset_hash bind the rule LOGIC, or only rule NAMES?")
print("="*92)
rules = cyber_custom_rules()
h_before = ruleset_hash(rules)
# Silently neuter the destructive-action rule, keeping its name/domain identical.
for r in rules:
    if r.name == "cyber_destructive_action":
        r.check = lambda s: False          # rule now never fires
h_after = ruleset_hash(rules)
print(f"  ruleset_hash BEFORE neutering : {h_before}")
print(f"  ruleset_hash AFTER  neutering : {h_after}")
print(f"  IDENTICAL? {h_before == h_after}   <-- attestation blind to logic change" )

G = GovernanceLayer(domains=[OmegaDomain.CYBERSECURITY], horizon=3, log_all=False, custom_rules=rules)
r = G.evaluate({"tool":"wipe_disk","args":{"device":"/dev/sda"}})
print(f"  wipe_disk verdict with neutered rule: {r.verdict.value}  (attestation hash unchanged)")

print("\n"+"="*92)
print("EV-02 — Is the DecisionTrace tamper-evident (hash chain / signature)?")
print("="*92)
t = DecisionTrace()
t.append(DecisionRecord(step=0, planner="p", proposed={"tool":"drop_database","args":{"db":"prod"}},
                        verdict="BLOCK", layer="A_safe", rule="cyber_destructive_action",
                        reason="destructive", executed=False))
orig = t.to_jsonl()
print(f"  original record verdict : {t.records[0].verdict}, executed={t.records[0].executed}")
# Silent post-hoc mutation
t.records[0].verdict = "PERMIT"
t.records[0].executed = True
t.records[0].reason  = "approved by change board"
print(f"  mutated  record verdict : {t.records[0].verdict}, executed={t.records[0].executed}")
print(f"  fail_closed_holds() now : {t.fail_closed_holds()}  <-- still 'True' after forging a PERMIT")
fields = set(DecisionRecord.__dataclass_fields__)
print(f"  integrity fields present? prev_hash={'prev_hash' in fields} "
      f"record_hash={'record_hash' in fields} signature={'signature' in fields} "
      f"actor={'actor' in fields} timestamp={'timestamp' in fields}")

print("\n"+"="*92)
print("EV-03 — Does the runtime chokepoint honour the deployment ESCALATE verdict?")
print("="*92)
from morrison_governance.result import GovernanceVerdict
print(f"  Engine verdict enum: {[v.value for v in GovernanceVerdict]}")
print("  ESCALATE present in engine enum? ", "ESCALATE" in [v.value for v in GovernanceVerdict])
print("  interception.py gate   : `if allowed:` where allowed = result.permitted (engine)")
print("  middleware.py gate     : `if result.permitted: self.sandbox.execute(call)`")
print("  escalation.apply_escalation() runs in app._serialize() on the HTTP RESPONSE BODY,")
print("  i.e. AFTER the engine verdict and OUTSIDE any execution gate.")
