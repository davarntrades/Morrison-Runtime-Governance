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
    # A destination no configuration can bring inside the boundary: link-local
    # ranges and the cloud instance-metadata endpoints.
    forbidden: bool = False

    def as_dict(self) -> dict:
        return {"external": self.external, "reason": self.reason,
                "observed": list(self.observed), "forbidden": self.forbidden}


# Addresses that must never resolve as an internal destination, whatever the
# deployment configures. The cloud instance-metadata services hand out live
# role credentials to anything that can issue a plain GET, so a request to one
# is a credential acquisition, not internal traffic.
_FORBIDDEN_HOSTS = frozenset({
    "169.254.169.254",              # AWS / Azure / DO / OpenStack IMDS
    "fd00:ec2::254",                # AWS IMDSv6
    "metadata.google.internal",     # GCP
    "metadata.goog",
    "100.100.100.200",              # Alibaba Cloud
})
_FORBIDDEN_NETS = ("169.254.0.0/16", "fe80::/10")


def _walk_values(value: Any, depth: int = 0):
    """Delegates to `normalize.iter_pairs` — the traversal shared with
    capability and sensitivity classification, with no depth limit.

    `depth` is accepted and ignored so existing call sites keep working.
    """
    from morrison_governance.kernel.normalize import BudgetExhausted, iter_pairs
    try:
        yield from iter_pairs(value)
    except BudgetExhausted:
        return


def _forbidden(host: str) -> bool:
    """Link-local and known metadata endpoints, checked after normalisation."""
    if host in _FORBIDDEN_HOSTS:
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return any(ip in ipaddress.ip_network(n, strict=False)
               for n in _FORBIDDEN_NETS)


def _host_is_internal(host: str, internal_url_hosts: tuple, internal_cidrs: tuple,
                      trust_private_networks: bool = False) -> bool:
    """Resolve a host against DEPLOYMENT CONFIGURATION only.

    Previously any loopback, RFC1918 or link-local literal was internal with no
    allowlist entry required, which decided "internal" as a network fact rather
    than a trust fact. An attacker-controlled collector on the agent's own VPC
    is the ordinary shape of a real exfiltration, and `169.254.169.254` is the
    cloud instance-metadata endpoint — both were classified internal, so every
    rule gated on `dest.external` was skipped for them.

    Private ranges are now internal only when the deployment says so: named in
    `internal_url_hosts`, inside a configured `internal_cidrs` entry, or with
    `trust_private_networks` explicitly enabled. Metadata endpoints are never
    internal under any configuration.
    """
    from morrison_governance.kernel.normalize import normalize_host

    h = normalize_host(host)
    if not h:
        return False
    if _forbidden(h):
        return False
    for allowed in internal_url_hosts:
        a = normalize_host(str(allowed).strip().lstrip("*."))
        if not a:
            continue
        if h == a or h.endswith("." + a):
            return True
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        return False
    for cidr in internal_cidrs:
        try:
            if ip in ipaddress.ip_network(str(cidr), strict=False):
                return True
        except ValueError:
            continue
    if trust_private_networks and (ip.is_loopback or ip.is_private):
        return True
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
                         internal_cidrs: tuple = (),
                         trust_private_networks: bool = False,
                         extra_args: dict | None = None) -> DestinationVerdict:
    """Resolve whether this call moves data outside the trust boundary.

    Deny-by-default: an unrecognised or unresolvable destination is EXTERNAL.
    """
    from morrison_governance.kernel.normalize import normalize_host

    args = dict(call.get("args") or {}) if isinstance(call.get("args"), dict) else {}
    # Fields the trust boundary quarantined out of the authority namespace are
    # still DESTINATION EVIDENCE. Quarantine removes their power to authorise,
    # not the fact that they name where the data is going: naming a collector
    # argument `policy` or `external` used to delete it from this resolver
    # entirely, so the call resolved as having no destination at all.
    if extra_args:
        args.update(extra_args)
    observed: list[str] = []
    externals: list[str] = []
    internals: list[str] = []

    for key, value in _walk_values(args):
        if not isinstance(value, (str, int, float)):
            continue
        from morrison_governance.kernel.normalize import normalize_text
        sval = normalize_text(str(value))
        kl = key.strip().lower()

        # Public-share ACLs are egress regardless of any hostname.
        if kl in _ACL_KEYS and _PUBLIC_ACL.match(sval):
            observed.append(f"{key}={sval}")
            externals.append(f"public share ({key}={sval})")
            continue

        for url in _URL_RE.findall(sval):
            observed.append(url)
            host = normalize_host(urlparse(url).hostname or "")
            if _forbidden(host):
                externals.append(f"{host} (metadata/link-local endpoint)")
            elif _host_is_internal(host, internal_url_hosts, internal_cidrs,
                                   trust_private_networks):
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
                cand = normalize_host(cand)
                observed.append(cand)
                if _forbidden(cand):
                    externals.append(f"{cand} (metadata/link-local endpoint)")
                elif _host_is_internal(cand, internal_url_hosts, internal_cidrs,
                                       trust_private_networks):
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
            tuple(dict.fromkeys(observed)),
            forbidden=any("metadata/link-local" in e for e in externals))
    if internals:
        return DestinationVerdict(
            False, f"destination resolved as internal by allowlist: "
                   f"{', '.join(sorted(set(internals))[:4])}",
            tuple(dict.fromkeys(observed)))
    return DestinationVerdict(False, "no destination present in call", ())
