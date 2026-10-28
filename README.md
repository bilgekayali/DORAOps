# DORAOps

**Open operational resilience control plane for DORA ICT risk, incidents, testing, third-party risk and verifiable regulatory evidence.**

DORAOps is an open-source reference architecture for structuring and evidencing Digital Operational Resilience Act governance across ICT-supported business functions, assets/services, ICT risk, incidents, continuity/recovery, resilience testing, ICT third parties, assurance views, cryptographic evidence integrity, deployment controls and machine-readable control/evidence mappings.

Current stable package boundary: **DORAOps v1.0.0**.

> [!IMPORTANT]
> DORAOps v1.0.0 denotes a stable package/API/schema reference surface. It is not a legal-compliance certification, production-readiness attestation, supervisory approval, disaster-recovery executor or autonomous regulatory decision maker.

## v1.0.0 stable reference surface

v1.0 promotes the validated v0.9 release candidate without expanding the frozen functional surface:

```text
stable declared API symbols
  + pinned public schema identities
  + CI / CodeQL / evidence / security / deployment / matrix gates
  -> DORAOps 1.0.0 stable reference package
```

The v1 stable boundary provides:

- a declared-symbol stable API contract; breaking changes to that contract require a future major version;
- a stable schema contract pinned to exact Git blob identities, with the final governance-dossier release metadata promoted to `1.0.0`;
- deterministic governance dossiers and offline verification;
- financial-entity scoped security context, Ed25519 OIDC/JWT reference verification and AES-256-GCM entity-bound evidence encryption;
- signed-regulatory-evidence verification, build provenance, dependency SBOM and exact-byte release-evidence manifests;
- hardened deployment-reference and operational-control evidence contracts;
- a machine-readable DORA control/evidence matrix that reports evidence coverage as `represented` or `gap`, never a compliance percentage;
- CodeQL plus dedicated CI gates for security, release evidence, deployment hardening, control/evidence matrix, incident reporting and resilience assurance;
- an offline release verifier that confirms the frozen API/schema contracts and the `1.0.0` stable-reference gate.

The stable-reference gate is **eligible=true** at `1.0.0`. Repository governance enforcement is still explicitly recorded as `false` unless separately verified from GitHub repository administration. Production readiness, DORA compliance and supervisory acceptance remain explicitly undetermined.

The separately authorized [`v1.0.0` GitHub publication](https://github.com/bilgekayali/DORAOps/releases/tag/v1.0.0) exists only when every required workflow succeeds on the same current `main` SHA. The publication workflow creates an immutable tag and a no-overwrite release; the source-tree version alone does not prove that publication succeeded. See [`docs/RELEASE_PROCESS.md`](docs/RELEASE_PROCESS.md).

The GitHub Release does not publish a package to a package index, publish a container or deploy a service. Those remain separate, unauthorized actions.

## Capability history retained in v1

- **v0.8** — DORA source/article/topic → control → expected evidence → accountable role → verification mapping; no automated legal/compliance score.
- **v0.7** — hardened deployment reference and operational-control evidence.
- **v0.6** — signed regulatory-evidence verification, build provenance, deterministic direct-dependency SBOM and release-evidence integrity.
- **v0.5** — security / financial-entity boundary, entity-bound encryption and PostgreSQL RLS reference.
- **v0.4** — resilience assurance positions and portfolio/provider exposure views.
- **v0.3** — human-owned incident-reporting workflow evidence.
- **v0.2** — continuity/recovery objectives, exercises, remediation/retest and dependency-impact evidence.
- **v0.1** — entity inventory, ICT risk/control, incident, testing and ICT third-party governance foundation.

## CLI

```bash
doraops --version
doraops digest evidence.json
doraops schema schema.json evidence.json
doraops dossier verify governance-dossier.json
```

Release-evidence preview generation:

```bash
python scripts/build_release_evidence_preview.py \
  --wheel dist/doraops-1.0.0-py3-none-any.whl \
  --source-revision <40-character-git-sha>
```

## Regulatory design posture

Primary design inputs include Regulation (EU) 2022/2554 (DORA), Commission Delegated Regulations (EU) 2024/1774 and 2024/1773, Commission Implementing Regulation (EU) 2024/2956, Commission Delegated Regulation (EU) 2025/301, and Commission Implementing Regulation (EU) 2025/302 with Annex I.

DORAOps deliberately separates machine-verifiable evidence integrity, reference stability and operational coverage from legal interpretation, supervisory interpretation, real-world control effectiveness and accountable human decisions.

## Explicit non-claims

DORAOps v1.0.0 does **not** by itself establish DORA compliance, legal applicability, supervisory acceptance, production infrastructure effectiveness, successful disaster recovery, production IAM/KMS effectiveness, real-world signer authority, formal production build attestation, complete transitive software-composition coverage, vulnerability absence, legal concentration risk, legal incident reportability, or any compliance/maturity percentage.

## Versioning

The declared v1 API and pinned stable schema contract are compatibility commitments for the 1.x line. Deliberate breaking changes to those frozen contracts require a future major version.

## License

Apache License 2.0.
