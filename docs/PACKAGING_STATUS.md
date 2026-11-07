# Packaging status

**Status: no supported package distribution.** Morrison Runtime Governance is
currently evaluated from a source checkout. Do not rely on a `pip install`
command until the items below are resolved.

## PyPI publication: unverified

Earlier documentation told readers to run `pip install morrison-governance`.
Whether a package of that name is published on PyPI, who published it, and
whether it matches this repository have not been verified. Publication and
provenance are being reconciled against PyPI, the source repository and the
release configuration. Until that is done, no PyPI package should be treated as
an official or supported Morrison distribution.

## The in-repository package definition does not build

The package definition is `morrison_governance/pyproject.toml`. As of this
writing it has these defects:

| Item | Detail | How it was checked |
|---|---|---|
| Build backend does not exist | `build-backend = "setuptools.backends._legacy:_Backend"` (line 3). Importing `setuptools.backends` fails with `ModuleNotFoundError` on setuptools 68.1.2, which satisfies the declared `setuptools>=68.0`. The standard backend is `setuptools.build_meta`. | Import attempted directly |
| README file missing | `readme = "README.md"` resolves relative to `morrison_governance/`, and `morrison_governance/README.md` does not exist. | File check |
| Package discovery probably finds nothing | `include = ["morrison_governance*"]` is evaluated from inside `morrison_governance/`, whose sub-packages are named `kernel` and `global_verification`. | Not tested, inferred from the configuration |
| Contact address differs from other docs | `authors` lists `davarn@resurrectiontech.com`; the rest of the repository uses `resurrection-tech.com`. | Text comparison; which is correct needs confirming |

These are packaging defects only. They do not affect running the code from a
source checkout (`python3 quickstart.py`, the test suite).

## Before a package is offered

1. Fix the build configuration and confirm a clean build and install in an
   isolated environment.
2. Reconcile the PyPI project (if any) with this repository and the release
   process, including who holds publishing rights.
3. Publish with provenance (signed or attested releases) and an SBOM.
4. Then restore installation instructions to the README and ENTERPRISE.md.
