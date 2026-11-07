# Security policy

> [!IMPORTANT]
> **Draft, not yet in effect.** This is a proposed coordinated
> vulnerability-disclosure process. It has not been approved. It deliberately
> contains no security contact, no response-time commitments and no
> key-custody guarantees, because none of those have been approved yet. Do not
> treat anything here as a service-level commitment.

## Reporting a vulnerability (interim)

Until a dedicated security contact is approved and published here:

- **Do not** report suspected vulnerabilities in a public GitHub issue, pull
  request or discussion.
- If GitHub private vulnerability reporting is enabled for this repository, use
  it (the **Security** tab → **Report a vulnerability**). If it is not
  enabled, no private reporting channel has been published yet.

## Proposed process

The following is proposed for adoption. Owners, contacts and timelines are
deliberately left as placeholders.

1. **Intake.** Reports arrive through a private channel (`[security contact:
   to be approved]`). Each report gets an internal tracking reference.
2. **Acknowledgement.** The reporter is told the report was received
   (`[target: to be approved]`).
3. **Triage.** The report is reproduced against the current default branch and
   assessed for severity and affected components (kernel, adapters, lease
   verification, evidence chain, evaluation harnesses, hosted console).
4. **Remediation.** A fix is developed privately, with a regression test that
   reproduces the issue.
5. **Coordinated disclosure.** A disclosure date is agreed with the reporter
   (`[default embargo: to be approved]`). The fix, an advisory and credit (if
   the reporter wants it) are published together.
6. **Record.** Accepted findings are recorded alongside the repository's
   existing adversarial-evaluation reports.

## Scope (proposed)

In scope:

- `morrison_governance/` (the kernel, adapters, lease verification and evidence
  chain).
- Documentation that makes a security claim this repository's code does not
  support.

Out of scope until separately defined:

- The hosted console at resurrection-tech.com. Its data handling is still
  pending technical verification (see
  [docs/VERIFICATION_STATUS.md](docs/VERIFICATION_STATUS.md#hosted-console-data-handling)).
- Any separately deployed governance service. It is not part of this
  repository and has not been audited here.
- Evaluation harnesses and research scripts (`runtime_eval/`, `redteam/`,
  `experiments/`, `arsb/`), except where they ship in the package.

## Known limitations (not vulnerabilities)

The documented enforcement boundary, partial fail-closed behaviour, in-memory
evidence, host-supplied identity and approval-key custody are known
limitations. They are described in
[morrison_governance/DEPLOYMENT.md](morrison_governance/DEPLOYMENT.md#enforcement-boundary-read-before-deploying).
A report showing that one of them is worse than documented is in scope.

## Key custody

No key-custody guarantee is made. Key custody will be defined for each supported
deployment model, and customer-controlled keys are preferred where feasible.
The current key-management behaviour has not yet been audited.

## Items to approve before this policy takes effect

- [ ] Security contact (mailbox or GitHub private vulnerability reporting)
- [ ] Acknowledgement and remediation targets
- [ ] Default embargo period
- [ ] Owner responsible for triage
- [ ] Safe-harbour wording for good-faith research (legal review)
- [ ] Whether the hosted console and any governance service come into scope
