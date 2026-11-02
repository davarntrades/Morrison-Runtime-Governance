"""Run ARSB with the provenance-aware Morrison variants registered.

    python -m experiments.utility_gap.run --output DIR [--sut NAME ...]

Uses the frozen ARSB runner and scenarios unchanged; only the adapter registry
is extended.
"""

from __future__ import annotations

import sys

import arsb.__main__ as arsb_main

from experiments.utility_gap.adapters import MorrisonMediatedProvenance, MorrisonProvenance

_frozen_registry = arsb_main.adapters


def adapters() -> dict:
    registry = dict(_frozen_registry())
    registry[MorrisonProvenance.name] = MorrisonProvenance
    registry[MorrisonMediatedProvenance.name] = MorrisonMediatedProvenance
    return registry


def main(argv=None) -> int:
    arsb_main.adapters = adapters
    return arsb_main.main(argv)


if __name__ == "__main__":
    sys.exit(main())
