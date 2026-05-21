"""Action ontology — symbolic, deterministic, ontology-based.

Maps tool names (often paraphrased / euphemised by planners) to a
canonical capability label and a canonical tool name the existing
reachability rules already recognise. The ontology is an explicit,
bounded equivalence table — no embeddings, no classifiers, no
moderation APIs.

If the planner emits "backup_externally", the ontology maps it to
`canonical_tool=http_request, capability=egress`. The semantic-lifting
layer then injects the canonical tool/capability into the call so the
existing Ω rules apply structurally.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class OntologyEntry:
    canonical_tool: str
    capability: str
    notes: str = ""


# Capability vocabulary aligned with morrison_governance.forecasting
ACQUIRE = "acquire"
EGRESS = "egress"
EXEC = "exec"
PRIV = "priv"
DEFER = "defer"


ACTION_ONTOLOGY: dict[str, OntologyEntry] = {
    # ── egress euphemisms ────────────────────────────────────
    "backup_externally":       OntologyEntry("http_request", EGRESS,
                                              "exfiltration euphemism"),
    "external_backup":         OntologyEntry("http_request", EGRESS),
    "offsite_sync":            OntologyEntry("http_request", EGRESS),
    "push_to_partner":         OntologyEntry("http_request", EGRESS),
    "external_archive":        OntologyEntry("upload", EGRESS),
    "publish_externally":      OntologyEntry("http_request", EGRESS),
    "share_with_collaborator": OntologyEntry("http_request", EGRESS),
    "ship_to_endpoint":        OntologyEntry("http_request", EGRESS),

    # ── financial-execution euphemisms ───────────────────────
    "facilitate_transfer":     OntologyEntry("transfer", "financial_execution",
                                              "transfer euphemism"),
    "process_payment":         OntologyEntry("transfer", "financial_execution"),
    "settle_disbursement":     OntologyEntry("transfer", "financial_execution"),
    "wire_funds":              OntologyEntry("transfer", "financial_execution"),
    "execute_movement":        OntologyEntry("transfer", "financial_execution"),
    "release_funds":           OntologyEntry("transfer", "financial_execution"),

    # ── acquire euphemisms ───────────────────────────────────
    "extract_data":            OntologyEntry("query_db", ACQUIRE),
    "pull_records":            OntologyEntry("query_db", ACQUIRE),
    "harvest_dataset":         OntologyEntry("query_db", ACQUIRE),
    "ingest_secrets":          OntologyEntry("read_file", ACQUIRE,
                                              "credential acquisition"),
    "load_credentials":        OntologyEntry("read_file", ACQUIRE),
    "retrieve_keys":           OntologyEntry("read_file", ACQUIRE),

    # ── exec euphemisms ──────────────────────────────────────
    "run_command":             OntologyEntry("shell", EXEC),
    "invoke_subprocess":       OntologyEntry("shell", EXEC),
    "system_call":             OntologyEntry("shell", EXEC),

    # ── privilege euphemisms ─────────────────────────────────
    "elevate_role":            OntologyEntry("update_role", PRIV),
    "expand_permissions":      OntologyEntry("grant_permission", PRIV),
    "loosen_acl":              OntologyEntry("modify_acl", PRIV),

    # ── deferred euphemisms ──────────────────────────────────
    "queue_for_later":         OntologyEntry("schedule_task", DEFER),
    "enqueue_action":          OntologyEntry("schedule_task", DEFER),
    "delayed_dispatch":        OntologyEntry("schedule_task", DEFER),

    # ── canonical self-mappings (capability tagging only) ────
    "transfer":                OntologyEntry("transfer", "financial_execution"),
    "send_payment":            OntologyEntry("send_payment", "financial_execution"),
    "execute_trade":           OntologyEntry("execute_trade", "financial_execution"),
    "http_request":            OntologyEntry("http_request", EGRESS),
    "upload":                  OntologyEntry("upload", EGRESS),
    "send_email":              OntologyEntry("send_email", EGRESS),
    "read_file":               OntologyEntry("read_file", ACQUIRE),
    "query_db":                OntologyEntry("query_db", ACQUIRE),
    "shell":                   OntologyEntry("shell", EXEC),
    "exec":                    OntologyEntry("exec", EXEC),
    "subprocess":              OntologyEntry("subprocess", EXEC),
    "modify_acl":              OntologyEntry("modify_acl", PRIV),
    "grant_permission":        OntologyEntry("grant_permission", PRIV),
    "update_role":             OntologyEntry("update_role", PRIV),
    "schedule_task":           OntologyEntry("schedule_task", DEFER),
}


def lookup(tool_name: str) -> Optional[OntologyEntry]:
    """Case-insensitive ontology lookup. Returns None for unknown tools
    (semantic lifting then falls back to capability inference)."""
    return ACTION_ONTOLOGY.get(str(tool_name).strip().lower())
