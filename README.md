# DORAOps

**Open operational resilience control plane for DORA ICT risk, incidents, testing, third-party risk and verifiable regulatory evidence.**

DORAOps is an open-source reference architecture for structuring and evidencing Digital Operational Resilience Act governance across ICT-supported business functions, assets/services, ICT risk, incidents, continuity/recovery, resilience testing, ICT third parties, assurance views, cryptographic evidence integrity, deployment controls and machine-readable control/evidence mappings.

Current package boundary: **DORAOps v0.9.0 release candidate**.

> [!IMPORTANT]
> DORAOps is not a legal-compliance engine, disaster-recovery executor, regulator filing gateway, certification product or autonomous operational-resilience decision maker. Stable-reference validation and machine-verifiable evidence do not establish legal applicability, DORA compliance, production effectiveness or supervisory acceptance.

## v0.9.0 release candidate

v0.9 freezes the intended v1 stable reference surface and adds release governance:

```text
v0.8 control/evidence runtime
  -> declared stable API contract
  -> pinned stable schema contract
  -> CodeQL + existing CI/evidence/security/deployment/matrix gates
  -> versioned repository-governance policy
  -> release-candidate verifier
  -> v1 stable-reference promotion
```

The v0.9 boundary adds:

- a declared-symbol stable API contract covering the supported governance, security, release-evidence, deployment and DORA control-matrix interfaces;
- a stable schema contract pinned to exact Git blob SHA-1 identities;
- an offline fail-closed release-candidate verifier;
- CodeQL Python analysis;
- a dedicated Release Candidate workflow;
- a versioned repository-governance expectation for `main` with zero mandatory reviewers for single-maintainer development;
- explicit separation between the versioned governance expectation and actual GitHub repository enforcement;
- a formal stable-reference gate that remains false at `0.9.0` and becomes eligible only when the package boundary is deliberately promoted to `1.0.0` with the frozen contracts still valid.

The repository currently records `repository_governance_enforcement_verified=false`; that is not represented as enabled merely because the policy file exists.

## Retained capabilities

- **v0.8** — machine-readable DORA source/article/topic → control → expected evidence → accountable role → verification mapping with only `represented` / `gap` coverage states and no compliance percentage.
- **v0.7** — hardened deployment reference and operational-control evidence with immutable image, non-root/read-only runtime, default-deny network posture, external secrets and explicit production-effectiveness non-claims.
- **v0.6** — canonical signed regulatory-evidence boundary, external Ed25519 verification, build provenance, deterministic direct-dependency SBOM and exact-byte release-evidence manifests.
- **v0.5** — Ed25519 OIDC/JWT reference validation, financial-entity binding, AES-256-GCM evidence encryption, external key references, secret-free observability and PostgreSQL RLS reference.
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
  --wheel dist/doraops-0.9.0-py3-none-any.whl \
  --source-revision <40-character-git-sha>
```

## Regulatory design posture

Primary design inputs include Regulation (EU) 2022/2554 (DORA), Commission Delegated Regulations (EU) 2024/1774 and 2024/1773, Commission Implementing Regulation (EU) 2024/2956, Commission Delegated Regulation (EU) 2025/301, and Commission Implementing Regulation (EU) 2025/302 with Annex I.

DORAOps deliberately separates evidence integrity, reference stability and operational coverage from legal interpretation, real-world effectiveness and accountable human decisions.

## Explicit non-claims

DORAOps v0.9.0 does **not** by itself establish DORA compliance, complete legal mapping, legal applicability, supervisory acceptance, production infrastructure effectiveness, successful disaster recovery, production IAM/KMS effectiveness, signer authority, formal build attestation, complete transitive SCA coverage, vulnerability absence, legal concentration risk, legal incident reportability, or any compliance/maturity percentage.

## Roadmap

`v0.1 governance foundation -> v0.2 continuity/recovery -> v0.3 incident reporting -> v0.4 resilience assurance -> v0.5 security/entity boundary -> v0.6 signed evidence/provenance -> v0.7 deployment hardening -> v0.8 DORA control/evidence matrix -> v0.9 release candidate -> v1.0 stable API/schema`

## License

Apache License 2.0.
