"""LB-0 test suite.

These modules are the only place in the package permitted to name the
production enforcement surfaces or the ground-truth oracle: proving that the
Living Boundary cannot reach production authority, and that the discovery layer
cannot reach the oracle, requires referring to both.
`authority.scan_static_authority` therefore excludes `tests/` — a scanner that
flagged its own proof would force the proof to be deleted.
"""

from __future__ import annotations
