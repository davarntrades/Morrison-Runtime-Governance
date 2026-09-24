"""Follow-up to frozen rerun 02: live model-linked authority-context reproductions."""
import json
import os
from pathlib import Path

from experiments.phase2 import campaign as c

FAMILIES = ("LIVE_CROSS_TENANT", "LIVE_CROSS_PRINCIPAL", "LIVE_CROSS_SESSION", "LIVE_STALE_STATE")


def main():
    c.start()
    try:
        agent = c.live_agent()
        if agent:
            for family in FAMILIES:
                for trial in range(1, 7):
                    try:
                        c.live(family, trial, agent)
                    except BaseException as exc:
                        c.append(c.RESULTS, {"family": family, "trial": trial,
                            "classification": "HARNESS_DEFECT", "error": repr(exc)})
                        print(family, trial, "HARNESS_DEFECT", flush=True)
        final = c.snapshot()
        (c.ROOT / "final-snapshot.json").write_text(json.dumps(final, indent=2))
        (c.ROOT / "configuration.json").write_text(json.dumps({
            "morrison_source": "7dacc63b0ec0e17d769ef08431e3ec0696e8d03a",
            "cma_source": "1f3db3c37d7b394185df0e5a5a12efcffe1ac5d6",
            "families": FAMILIES, "trials_per_family": 6,
            "secret_material": "omitted", "resource_route": "/mutate"}, indent=2))
    finally:
        c.stop()


if __name__ == "__main__":
    main()
