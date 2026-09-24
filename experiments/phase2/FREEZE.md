# Pre-run freeze

The preregistration was remotely frozen first at commit `3246cf1c97e3a578b3565e93bc6d02833db6c601` (SHA-256 `7937e29a1656a7af611079d7be0b93197058255b77b59b8528c6628fb8f39898`). No scored Phase 2 API or resource trials had run at that point.

The exact service, harness, workflow and hash manifest are frozen at source commit `da089f355c8436dc38981260f59dc2f7a3258729`, tree `9e5d5820e99e4b2b6b0713a8540f1b98a3f13026`. This file is the only addition in the triggering commit. The GitHub Actions workflow checks `SHA256SUMS` before the first scored trial and records the run commit. The source hashes are:

- `experiments/phase2/campaign.py`: `1ac1577af0c6d7f5ceb11876aabb9bdab3d389812da65e3be30e65abe345bcbd`
- `experiments/phase2/service.py`: `129af2440d63958c12cc37e9407b658fd250477a526983c65cacc5632264c8ef`
- `.github/workflows/cma-phase2-persistent.yml`: `4cf5685fd6dc23a83b88eb9e18042168136c2ae5057f6faf1471534b6976fd25`
- `experiments/phase2/SHA256SUMS`: `e8d7cdcc82cd9b7995155d485d580c8cdab0d6eb` (Git blob; its text includes SHA-256 values above)

Production Morrison baseline remains commit `7dacc63b0ec0e17d769ef08431e3ec0696e8d03a`; production package differences are checked as empty. Frozen CMA prototype remains `1f3db3c37d7b394185df0e5a5a12efcffe1ac5d6`. Agent/API keys and resource signing/identity credentials are never committed or logged.

Any discovered defect will be frozen as an immutable original artifact and, if corrected, tested from a *new* commit with a separate artifact and explicit result label.
