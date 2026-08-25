# DORAOps

**Open operational resilience control plane for DORA ICT risk, incidents, testing, third-party risk and verifiable regulatory evidence.**

DORAOps is an open-source reference architecture for structuring and evidencing Digital Operational Resilience Act governance across ICT-supported business functions, assets/services, ICT risk, incidents, continuity/recovery, resilience testing, ICT third parties, assurance views, cryptographic evidence integrity, deployment controls and machine-readable control/evidence mappings.

Current package boundary: **DORAOps v0.8.0**.

> [!IMPORTANT]
> DORAOps is not a legal-compliance engine, disaster-recovery executor, regulator filing gateway, certification product or autonomous operational-resilience decision maker. Machine-verifiable coverage does not establish legal applicability, DORA compliance, production effectiveness or supervisory acceptance.

## v0.8.0 DORA control / evidence matrix

v0.8 adds a machine-readable relationship:

```text
DORA source/article/topic
  -> institution-owned control
  -> expected evidence types
  -> accountable role
  -> verification method
  -> represented / gap
  -> human review
```

The checked-in reference matrix maps selected Regulation (EU) 2022/2554 Articles 5, 6, 8, 9, 10, 11, 12, 17, 18, 19, 24, 28 and 30. Every mapping keeps `applicability_basis=institution_determined`; the matrix explicitly keeps `complete_legal_mapping_claimed=false`.

Runtime assessment reports only evidence-coverage states: `represented` or `gap`. It does not produce a compliance percentage, maturity score or legal conclusion. Matrix and assessment artifacts structurally keep `dora_compliance_determined=false`, `legal_applicability_determined=false`, `supervisory_acceptance_determined=false` and `requires_human_review=true`.

See [`docs/CONTROL_EVIDENCE_MATRIX.md`](docs/CONTROL_EVIDENCE_MATRIX.md) and [`configs/dora-control-evidence-matrix.json`](configs/dora-control-evidence-matrix.json).

## Retained v0.7 deployment hardening

v0.7 retains immutable image references, non-root/read-only runtime, no privilege escalation, dropped Linux capabilities, RuntimeDefault seccomp, disabled service-account token automount, default-deny network posture, external secrets/key evidence, resource limits/probes, backup/restore evidence requirements and secret-free operational evidence. The Kubernetes file remains a non-production `.invalid` reference.

See [`docs/DEPLOYMENT_HARDENING.md`](docs/DEPLOYMENT_HARDENING.md).

## Retained v0.6 signed evidence and provenance

v0.6 retains canonical regulatory-evidence statements bound to verified governance-dossier digests, external Ed25519 verification, build provenance, deterministic direct-dependency SBOM generation and exact-byte release-evidence manifests.

See [`docs/RELEASE_EVIDENCE.md`](docs/RELEASE_EVIDENCE.md).

## Retained v0.5 security / entity boundary

v0.5 retains EdDSA/Ed25519 JWT verification, exact financial-entity binding, `TenantContext`, AES-256-GCM entity-bound evidence encryption, external key references, secret-free observability and PostgreSQL `ENABLE` + `FORCE ROW LEVEL SECURITY` using a `NOBYPASSRLS` application role.

See [`docs/SECURITY_BOUNDARY.md`](docs/SECURITY_BOUNDARY.md).

## Retained governance and resilience layers

- **v0.4** — verified-dossier assurance positions, provider exposure aggregation and append-only portfolio snapshots.
- **v0.3** — human-owned incident-reporting applicability/route evidence, report revision chains and imported submission evidence.
- **v0.2** — continuity/recovery objectives, exercises, observations, remediation/retest and dependency-impact evidence.
- **v0.1** — entity inventory/dependencies, ICT risk/control state, incident evidence, resilience tests and ICT third-party governance.

## CLI

```bash
doraops --version
doraops digest evidence.json
doraops schema schema.json evidence.json
doraops dossier verify governance-dossier.json
```

Release-evidence previews:

```bash
python scripts/build_release_evidence_preview.py \
  --wheel dist/doraops-0.8.0-py3-none-any.whl \
  --source-revision <40-character-git-sha>
```

## Regulatory design posture

Primary design inputs include Regulation (EU) 2022/2554 (DORA), Commission Delegated Regulations (EU) 2024/1774 and 2024/1773, Commission Implementing Regulation (EU) 2024/2956, Commission Delegated Regulation (EU) 2025/301, and Commission Implementing Regulation (EU) 2025/302 with Annex I.

DORAOps deliberately separates evidence integrity and operational coverage from legal interpretation and accountable human decisions.

## Explicit non-claims

DORAOps v0.8.0 does **not** by itself establish DORA compliance, complete legal mapping, legal applicability, supervisory acceptance, production infrastructure effectiveness, successful disaster recovery, production IAM/KMS effectiveness, signer authority, formal build attestation, complete transitive SCA coverage, vulnerability absence, legal concentration risk, legal incident reportability, or any compliance/maturity percentage.

## Roadmap

`v0.1 governance foundation -> v0.2 continuity/recovery -> v0.3 incident reporting -> v0.4 resilience assurance -> v0.5 security/entity boundary -> v0.6 signed evidence/provenance -> v0.7 deployment hardening -> v0.8 DORA control/evidence matrix -> v0.9 release candidate -> v1.0 stable API/schema`

## License

Apache License 2.0.
