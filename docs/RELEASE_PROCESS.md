# Stable GitHub release process

DORAOps treats source-tree version promotion and public distribution as separate
decisions. `release/publish-policy.json` records the owner authorization for the
single `v1.0.0` Git tag and GitHub Release. It explicitly excludes package-index,
container and deployment actions.

## Exact-main gate

`.github/workflows/publish-release.yml` reacts only to successful `main` push runs
from this repository. Its read-only gate checks the live `main` ref and requires the
latest attempt of every workflow named in the publication policy to be successful
on the same 40-character commit SHA. Fork, pull-request, branch, missing, stale,
queued, cancelled and failed runs cannot authorize a write.

Each policy workflow path/name pair must match a committed workflow. The separately
listed check contexts must match `configs/repository-governance-policy.json` exactly.
Permission, rate-limit and GitHub service errors fail closed rather than being
treated as absence.

## Separate writer and no-overwrite policy

The gate job has only read permissions. A separate job receives `contents: write`
only after the gate succeeds, checks out the exact SHA, and repeats the live gate.
It creates `v1.0.0` only when the tag is absent, re-reads direct or annotated tag
objects to a bounded commit, repeats the gate after tag verification, then creates
the release with the committed notes.

An existing tag is never moved. An existing published release is never edited. A
matching tag left by an interrupted run may be completed only at the same candidate
SHA; an inconsistent tag, draft, prerelease, title or notes body blocks publication.

The release contains GitHub's source archives and release notes. It does not publish
wheel/container artifacts, reach a package registry, deploy infrastructure, or turn
the stable-reference maturity label into a production/compliance assertion.
