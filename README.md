# DORAOps

**Open operational resilience control plane for DORA ICT risk, incidents, testing, third-party risk and verifiable regulatory evidence.**

DORAOps is an open-source reference architecture for structuring and evidencing Digital Operational Resilience Act governance across ICT-supported business functions, assets/services, ICT risk, incidents, continuity/recovery, resilience testing, ICT third parties, assurance views, cryptographic evidence integrity and deployment-control evidence.

Current package boundary: **DORAOps v0.7.0**.

> [!IMPORTANT]
> DORAOps is not a legal-compliance engine, disaster-recovery executor, production failover controller, regulator filing gateway, certification product or autonomous operational-resilience decision maker. Reference validation, cryptographic integrity and configuration hardening do not establish production effectiveness, legal authority or supervisory acceptance.

## v0.7.0 deployment hardening and operational-control evidence

v0.7 adds a hardened deployment reference and a fail-closed evidence contract:

```text
immutable image + hardened runtime + default-deny network + external secrets
  -> DeploymentControlProfile
  -> imported control evidence digests
  -> validator identity + negative-path verification
  -> OperationalControlEvidence
  -> human review
```

The v0.7 boundary requires:

- immutable `@sha256` image references;
- non-root execution, read-only root filesystem, no privilege escalation, all Linux capabilities dropped and `RuntimeDefault` seccomp;
- service-account token automount disabled;
- default-deny egress posture and TLS requirement;
- no runtime dependency installation;
- external secret injection and external key-management evidence;
- explicit resource limits, readiness/liveness probes and backup/restore testing requirement;
- raw evidence logging disabled;
- exactly one distinct evidence artifact for every required operational control;
- validator identity and `negative_path_verified=true` for each control;
- structural non-claims: `production_effectiveness_determined=false`, `dora_compliance_determined=false`, `supervisory_acceptance_determined=false`, `requires_human_review=true`.

`deployment/kubernetes-reference.yaml` intentionally uses an `.invalid` registry and is a hardening template, not a production deployment manifest. See [`docs/DEPLOYMENT_HARDENING.md`](docs/DEPLOYMENT_HARDENING.md).

## Retained v0.6 signed regulatory evidence and release provenance

v0.6 retains canonical regulatory-evidence statements bound to verified governance-dossier digests, external Ed25519 signing/verification, build provenance, a deterministic CycloneDX-shaped direct-dependency SBOM and exact-byte release-evidence manifests with tamper verification. Repository/runtime code does not handle production signing private keys.

See [`docs/RELEASE_EVIDENCE.md`](docs/RELEASE_EVIDENCE.md).

## Retained v0.5 security and financial-entity boundary

v0.5 retains EdDSA/Ed25519 JWT verification using separately supplied public keys, issuer/audience/time/MFA/role checks, exact `FinancialEntity.entity_id` binding, `TenantContext`, AES-256-GCM entity-bound evidence encryption, external key references, secret-free observability and PostgreSQL `ENABLE` + `FORCE ROW LEVEL SECURITY` using a non-superuser `NOBYPASSRLS` application role.

See [`docs/SECURITY_BOUNDARY.md`](docs/SECURITY_BOUNDARY.md).

## Retained governance and resilience layers

- **v0.4** — verified-dossier assurance positions, provider exposure aggregation and append-only portfolio snapshots; no compliance/maturity score.
- **v0.3** — human-owned incident-reporting applicability and route evidence, report revision chains, imported submission receipts and acknowledgements.
- **v0.2** — continuity/recovery objectives, exercises, observations, findings, remediation/retest evidence and dependency-impact snapshots.
- **v0.1** — financial-entity inventory/dependencies, ICT risk/control state, incident evidence, resilience tests and ICT third-party governance.

## Governance dossier

`GovernanceDossierBuilder` starts from the exact current inventory snapshot and packages canonical payloads for represented governance artifacts. Offline verification recomputes the dossier digest, embedded artifact digests and supported semantic cross-bindings. Dossier states remain `current`, `with_gaps` and `revalidation_required`.

## CLI

```bash
doraops --version
doraops digest evidence.json
doraops schema schema.json evidence.json
doraops dossier verify governance-dossier.json
```

Release-evidence previews are built separately:

```bash
python scripts/build_release_evidence_preview.py \
  --wheel dist/doraops-0.7.0-py3-none-any.whl \
  --source-revision <40-character-git-sha>
```

## Regulatory design posture

Primary design inputs include Regulation (EU) 2022/2554 (DORA), Commission Delegated Regulations (EU) 2024/1774 and 2024/1773, Commission Implementing Regulation (EU) 2024/2956, Commission Delegated Regulation (EU) 2025/301, and Commission Implementing Regulation (EU) 2025/302 with Annex I.

DORAOps deliberately separates machine-verifiable integrity and institution-owned policy evidence from legal applicability, supervisory interpretation and accountable human decisions.

## Explicit non-claims

DORAOps v0.7.0 does **not** by itself establish:

- DORA compliance, certification, legal applicability or supervisory acceptance;
- production Kubernetes/container/network-policy effectiveness;
- production backup/restore, failover, restoration or absence of data loss;
- production IAM, JWKS/revocation/key-rotation, KMS/HSM or secret-management effectiveness;
- real-world signer identity/authority or formal build attestation;
- a complete transitive SBOM, vulnerability assessment or vulnerability-free dependency set;
- production logging, monitoring or retention effectiveness;
- legal ICT concentration risk, critical-provider designation or legal incident reportability;
- an operational-resilience, compliance or maturity score.

## Roadmap

`v0.1 governance foundation -> v0.2 continuity/recovery -> v0.3 incident reporting -> v0.4 resilience assurance -> v0.5 security/entity boundary -> v0.6 signed evidence/provenance -> v0.7 deployment hardening -> v0.8 DORA control/evidence matrix -> v0.9 release candidate -> v1.0 stable API/schema`

## License

Apache License 2.0.
