"""Pytest configuration for the Morrison Runtime Governance suite.

Governed history is now process-wide by default, keyed to the persistent
execution identity rather than to a session. That is the correct production
default — it is what closes trajectory fragmentation across sessions, threads
and workers — but it means state outlives a single test, and two tests using the
same principal would otherwise contaminate each other in file order.

The autouse fixture wipes the process-wide store between tests. It restores
per-test isolation ONLY; it does not weaken any assertion, and no test opts out
of continuity by using it. Tests that need to prove continuity build several
kernels inside ONE test, which is exactly the shape of the attack.
"""

import pytest

from morrison_governance.kernel.continuity import reset_default_store


@pytest.fixture(autouse=True)
def _isolate_governed_history():
    reset_default_store()
    yield
    reset_default_store()
