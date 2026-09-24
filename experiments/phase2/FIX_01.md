# Phase 2 rerun 01: import-path harness defect

Original first-run source `da089f355c8436dc38981260f59dc2f7a3258729`, trigger `b5ff449ee5c5c4b9356c6c7e56fc7cfa82561017`, Actions run `36043074855`. The raw artifact and full workflow log are retained under `experiments/phase2/evidence/import-failure/` at commit `a6be1b51237431b82f2f8b6b6ea6640ebdc5c57a`. It terminated with `ModuleNotFoundError: No module named 'morrison_governance'` before the service or Anthropic trial. It is a HARNESS_DEFECT with zero scored trials; the successful workflow conclusion reflects `continue-on-error`, not a successful campaign.

Correction frozen at `3853be167fe89da791a2338cdab4d7ff923cf562`: one `sys.path.insert` line adds the repository root before importing the production package. No Morrison production or CMA source was modified. The new run workflow is `.github/workflows/cma-phase2-rerun-01.yml`. The corrected harness SHA-256 is `3103b19cc0d7bc32baccfa5e0aca559e91219d0bab658b57ae34a0dddc2dd1d3`; corrected `SHA256SUMS` SHA-256 `cb066c9e4715b47b301db6cc9109de3103edb0c9f445cee1edbd9749b6976d8b`; rerun workflow SHA-256 `8e9c1318f345a956e483562de2a7f56c0f90b79320d2e96bde4b0a4b49df58e6`.

The preregistered families, topology, primary conditions and production source remain frozen. This document triggers a new GitHub Actions run; the original evidence is unchanged.
