# Pre-fix evidence classification erratum

The immutable `pre_fix_evidence.json` records six `AUTHORIZATION_FAILURE`
labels. One is an oracle-application error discovered while constructing the
post-fix replay, not a changed definition:

- `CHANGED_TENANT_DECISION_REDEMPTION` is legitimate at the authorization
  point (tenant A) and prohibited only when the already-issued Decision is
  presented for redemption in tenant B. Its pre-fix execution is therefore an
  `ENFORCEMENT_FAILURE`, not an `AUTHORIZATION_FAILURE`.

The frozen definitions in `failure_definitions.json` remain unchanged. The
corrected pre-fix aggregate is therefore:

- `AUTHORIZATION_FAILURE`: 5
- `ENFORCEMENT_FAILURE`: 6
- `OVERBLOCK_FAILURE`: 0
- `INSTRUMENT_FAILURE`: 0

The original file and its commit are retained verbatim so the correction is
auditable rather than silently rewriting frozen evidence.
