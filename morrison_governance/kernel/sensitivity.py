"""Sensitive-content classification for egress decisions.

The gap this closes:

    A single-step external egress was PERMITTED when no governed acquisition
    preceded it — e.g. `send_email` to an external address carrying an SSN
    list. `egress_requires_approval_after_read` needs a read to have happened
    inside the governed trajectory, so a one-shot send slipped through.

    That is not an edge case. An agent's context is filled by many routes the
    governance layer never sees: the system prompt, retrieved documents, a
    previous session, the user's own message. Requiring a governed READ before
    treating egress as dangerous assumes the guard witnessed how the data
    arrived, and it usually did not.

So egress is classified on the CONTENT AND SHAPE of the call itself. If a call
leaving the trust boundary carries markers of regulated or secret material, it
is refused without a verified approval — whether or not the trajectory shows
where the data came from. Fail-closed on the assumption that sensitive content
may already be in context.

Deterministic: no clock, no RNG, no I/O.
"""

from __future__ import annotations

import re
from typing import Any

CAT_CREDENTIAL = "credential"
CAT_SECRET = "secret_material"
CAT_PII = "pii"
CAT_PHI = "phi"
CAT_FINANCIAL = "financial"

ALL_CATEGORIES = frozenset({CAT_CREDENTIAL, CAT_SECRET, CAT_PII, CAT_PHI,
                            CAT_FINANCIAL})

# ── Marker patterns ─────────────────────────────────────────────────────
# Deliberately keyed on named identifiers and high-signal formats rather than
# loose words, so ordinary business text does not trip them.

_CREDENTIAL = re.compile(
    r"\b(pass(word|wd|phrase)|api[_\-]?key|apikey|access[_\-]?key|"
    r"secret[_\-]?key|client[_\-]?secret|auth[_\-]?token|access[_\-]?token|"
    r"refresh[_\-]?token|session[_\-]?token|bearer[_\-]?token|"
    r"private[_\-]?key|ssh[_\-]?key|id_rsa|credential[s]?|keychain|"
    r"aws_secret_access_key|aws_access_key_id)\b", re.I)

_SECRET_FORMAT = re.compile(
    r"(-----BEGIN [A-Z ]*PRIVATE KEY-----|"          # PEM private key
    r"\bAKIA[0-9A-Z]{16}\b|"                          # AWS access key id
    r"\bASIA[0-9A-Z]{16}\b|"                          # AWS temp key
    r"\bghp_[0-9A-Za-z]{20,}\b|"                      # GitHub PAT
    r"\bgithub_pat_[0-9A-Za-z_]{20,}\b|"
    r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b|"              # Slack
    r"\bsk-[0-9A-Za-z]{20,}\b|"                       # OpenAI-style
    r"\bey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b|"  # JWT
    r"\bssh-(rsa|ed25519|dss) [A-Za-z0-9+/]{20,})", re.I)

_PII = re.compile(
    r"\b(ssn|social[_\-]?security([_\-]?number)?|national[_\-]?(id|insurance)|"
    r"\bnino\b|passport([_\-]?(no|number))?|driver'?s?[_\-]?licen[cs]e|"
    r"date[_\-]?of[_\-]?birth|\bdob\b|tax[_\-]?id|\bnhs[_\-]?number\b|"
    r"personal[_\-]?data|\bpii\b)\b", re.I)

# Formats: US SSN, UK NI number.
_PII_FORMAT = re.compile(
    r"(\b\d{3}-\d{2}-\d{4}\b|\b[A-CEGHJ-PR-TW-Z]{2}\d{6}[A-D]\b)")

_PHI = re.compile(
    r"\b(patient([_\-]?(id|record|name))?|\bphi\b|diagnos(is|es|tic)|"
    r"medical[_\-]?record([_\-]?number)?|\bmrn\b|prescription|medication|"
    r"clinical[_\-]?note|lab[_\-]?result|icd[_\-]?(9|10)|treatment[_\-]?plan|"
    r"protected[_\-]?health)\b", re.I)

_FINANCIAL = re.compile(
    r"\b(iban|sort[_\-]?code|account[_\-]?number|routing[_\-]?number|"
    r"card[_\-]?number|\bpan\b|\bcvv\b|\bcvc\b|bank[_\-]?account|"
    r"card[_\-]?holder|payment[_\-]?details|swift[_\-]?code|\bbic\b)\b", re.I)

# Formats: PAN (13-19 digits, optionally grouped), IBAN.
_FINANCIAL_FORMAT = re.compile(
    r"(\b(?:\d[ -]?){13,19}\b|\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b)")

_PATTERNS = (
    (CAT_CREDENTIAL, _CREDENTIAL),
    (CAT_SECRET, _SECRET_FORMAT),
    (CAT_PII, _PII),
    (CAT_PII, _PII_FORMAT),
    (CAT_PHI, _PHI),
    (CAT_FINANCIAL, _FINANCIAL),
    (CAT_FINANCIAL, _FINANCIAL_FORMAT),
)

# Argument keys that name a payload/body. Retained as deployment-facing
# documentation of which fields carry transmitted content; the matcher
# scans every key and value at any depth and does not consult this set.
_PAYLOAD_KEYS = frozenset({
    "body", "payload", "content", "data", "text", "message", "rows", "records",
    "attachment", "attachments", "file", "files", "document", "csv", "json",
    "columns", "fields", "query", "sql", "subject", "note", "notes", "summary",
})


def classify_sensitivity(call: dict, normalized: Any = None) -> frozenset:
    """Categories of regulated/secret material this call appears to carry.

    Matches against `normalize.normalize_action(call).text`, which contains
    every key and scalar AT ANY DEPTH, each scalar's percent-decoded and
    zero-width-stripped form, and the concatenation of adjacent scalars.

    That last part is the substantive change. This function used to join its
    blob with spaces, so `body: ["AKIAIOSF", "ODNN7EXAMPLE"]` matched nothing
    while every HTTP client that joins a multipart body sent the credential
    intact. Markers are now matched in the form the connector will transmit,
    not the form the payload happened to be written in.

    A payload too large to traverse inside the node budget returns
    `truncated`, and the kernel escalates rather than reading the empty result
    as "no regulated content found".
    """
    from morrison_governance.kernel.normalize import normalize_action

    norm = normalize_action(call) if normalized is None else normalized
    found = set()
    for cat, pat in _PATTERNS:
        if pat.search(norm.text):
            found.add(cat)
    return frozenset(found)


def describe(cats: frozenset) -> str:
    return ", ".join(sorted(cats)) if cats else "(none)"
