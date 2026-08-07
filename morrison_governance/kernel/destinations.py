"""Trusted destination classification.

The red-team finding this module closes:

    `_is_external()` returned "internal" whenever the CALLER supplied
    `destination_internal: true`. Posting a live AWS secret to
    https://attacker.example became PERMIT and executed.

Internal/external is now resolved ONLY from deployment configuration:
explicit host allowlists, email-domain allowlists, and RFC1918 / loopback /
link-local network resolution. Caller-supplied flags are quarantined upstream
(kernel.trust.AUTHORITY_FIELDS) and never consulted here.

Deny-by-default: anything not provably internal is external.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any, Optional
from urllib.parse import urlparse

_URL_RE = re.compile(r"https?://[^\s\"'<>)]+", re.I)
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
# Public-share ACL values that egress data regardless of hostname.
_PUBLIC_ACL = re.compile(
    r"^\s*(public|public[-_]read|public[-_]read[-_]write|anyone|anyone[-_]with[-_]link|"
    r"all[-_]users|allusers|everyone|world[-_]readable|open)\s*$", re.I)

_DEST_KEYS = ("url", "endpoint", "host", "hostname", "collector", "callback",
              "webhook", "uri", "server", "dest", "destination", "target_url")
_RECIPIENT_KEYS = ("to", "recipient", "recipients", "email", "mailto",
                   "deliver_to", "cc", "bcc", "share_with")
_ACL_KEYS = ("acl", "visibility", "sharing", "permission", "access", "share_with")


@dataclass(frozen=True)
class DestinationVerdict:
    external: bool
    reason: str
    observed: tuple = ()

    def as_dict(self) -> dict:
        return {"external": self.external, "reason": self.reason,
                "observed": list(self.observed)}


def _walk_values(value: Any, depth: int = 0):
    if depth > 6:
        return
    if isinstance(value, dict):
        for k, v in value.items():
            yield str(k), v
            yield from _walk_values(v, depth + 1)
    elif isinstance(value, (list, tuple)):
        for v in value:
            yield "", v
            yield from _walk_values(v, depth + 1)


def _host_is_internal(host: str, internal_url_hosts: tuple, internal_cidrs: tuple) -> bool:
    h = host.strip().lower().rstrip(".")
    if not h:
        return False
    for allowed in internal_url_hosts:
        a = str(allowed).strip().lower().lstrip("*.")
        if not a:
            continue
        if h == a or h.endswith("." + a):
            return True
    # Literal IPs: resolve against loopback/private/link-local and configured CIDRs.
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        return False
    if ip.is_loopback or ip.is_private or ip.is_link_local:
        return True
    for cidr in internal_cidrs:
        try:
            if ip in ipaddress.ip_network(str(cidr), strict=False):
                return True
        except ValueError:
            continue
    return False


def _email_is_internal(addr: str, internal_domains: tuple) -> bool:
    if "@" not in addr:
        return False
    domain = addr.rsplit("@", 1)[1].strip().lower().rstrip(".")
    for allowed in internal_domains:
        a = str(allowed).strip().lower().lstrip("@")
        if a and (domain == a or domain.endswith("." + a)):
            return True
    return False


def classify_destination(call: dict, internal_url_hosts: tuple = (),
                         internal_email_domains: tuple = (),
                         internal_cidrs: tuple = ()) -> DestinationVerdict:
    """Resolve whether this call moves data outside the trust boundary.

    Deny-by-default: an unrecognised or unresolvable destination is EXTERNAL.
    """
    args = call.get("args") if isinstance(call.get("args"), dict) else {}
    observed: list[str] = []
    externals: list[str] = []
    internals: list[str] = []

    for key, value in _walk_values(args):
        if not isinstance(value, (str, int, float)):
            continue
        sval = str(value)
        kl = key.strip().lower()

        # Public-share ACLs are egress regardless of any hostname.
        if kl in _ACL_KEYS and _PUBLIC_ACL.match(sval):
            observed.append(f"{key}={sval}")
            externals.append(f"public share ({key}={sval})")
            continue

        for url in _URL_RE.findall(sval):
            observed.append(url)
            host = (urlparse(url).hostname or "")
            if _host_is_internal(host, internal_url_hosts, internal_cidrs):
                internals.append(host)
            else:
                externals.append(host or url)

        for addr in _EMAIL_RE.findall(sval):
            observed.append(addr)
            if _email_is_internal(addr, internal_email_domains):
                internals.append(addr)
            else:
                externals.append(addr)

        # Bare host/endpoint values without a scheme.
        if kl in _DEST_KEYS and not _URL_RE.search(sval) and sval.strip():
            cand = sval.strip().split("/")[0].split(":")[0]
            if cand and ("." in cand or cand in ("localhost",)):
                observed.append(cand)
                if _host_is_internal(cand, internal_url_hosts, internal_cidrs):
                    internals.append(cand)
                else:
                    externals.append(cand)

        # Bare recipient values.
        if kl in _RECIPIENT_KEYS and "@" in sval and not _EMAIL_RE.search(sval):
            observed.append(sval)
            externals.append(sval)

    if externals:
        return DestinationVerdict(
            True, f"destination resolved as EXTERNAL: {', '.join(sorted(set(externals))[:4])}",
            tuple(dict.fromkeys(observed)))
    if internals:
        return DestinationVerdict(
            False, f"destination resolved as internal by allowlist: "
                   f"{', '.join(sorted(set(internals))[:4])}",
            tuple(dict.fromkeys(observed)))
    return DestinationVerdict(False, "no destination present in call", ())
