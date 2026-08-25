# DORAOps

**Open operational resilience control plane for DORA ICT risk, incidents, testing, third-party risk and verifiable regulatory evidence.**

DORAOps is an open-source reference architecture for structuring and evidencing Digital Operational Resilience Act governance across ICT-supported business functions, services/processes, information and ICT assets, ICT risk, incidents, resilience testing, continuity/recovery, incident-reporting workflows, ICT third-party dependencies, executive resilience-assurance views and cryptographically verifiable evidence integrity.

Current package boundary: **DORAOps v0.6.0**.

> [!IMPORTANT]
> DORAOps is not a legal-compliance engine, disaster-recovery executor, production failover controller, supervisory reporting service, regulator filing gateway, certification product, legal concentration-risk engine or operational-resilience scoring product. Reference validation and cryptographic integrity do not establish production effectiveness, legal authority or supervisory acceptance.

## v0.6.0 signed regulatory evidence and release provenance

v0.6 adds a deterministic integrity layer around governance dossiers and release artifacts:

```text
verified governance dossier
  -> canonical regulatory evidence statement
  -> external Ed25519 signing boundary
  -> trusted public-key verification

built wheel
  -> direct-dependency CycloneDX-shaped SBOM
  -> build provenance
  -> exact-byte release evidence manifest
  -> tamper verification
```

The v0.6 boundary adds:

- canonical regulatory-evidence statements bound to the exact verified governance-dossier SHA-256 digest;
- signer ID, external key ID, signing time, purpose, entity, DORAOps release and source-revision bindings;
- external Ed25519 signature assembly and verification using a separately supplied trusted raw public key;
- no runtime/repository API for generating, loading or using signing private keys;
- build provenance binding a full Git source revision to builder/invocation identity, source material and exact subject artifact bytes;
- deterministic CycloneDX-shaped direct-dependency SBOM generation with explicit `complete_transitive_inventory=false` and `vulnerability_assessment_performed=false` non-claims;
- release-evidence manifests using normalized relative paths, SHA-256, exact byte size and media type for every represented artifact;
- cross-verification between provenance subjects, release-manifest artifacts, source revision and package identity;
- fail-closed rejection of path traversal, missing/extra artifacts, byte tampering, package/version drift, source-revision drift, signature tampering and untrusted key IDs;
- strict Draft 2020-12 evidence schemas and a dedicated Release Evidence Integrity CI gate;
- a preview builder for wheel + SBOM + provenance + manifest generation and verification.

Cryptographic verification establishes integrity relative to the supplied trusted key and exact represented bytes. It does **not** establish real-world signer authority, legal effect, formal artifact attestation, complete software-composition coverage, DORA compliance or supervisory acceptance.

See [`docs/RELEASE_EVIDENCE.md`](docs/RELEASE_EVIDENCE.md).

## Retained v0.5 security and financial-entity boundary

The v0.5 boundary remains intact:

```text
pre-resolved Ed25519 OIDC/JWT
  -> issuer/audience/time/MFA/role checks
  -> exact financial-entity binding
  -> TenantContext
  -> entity-bound AES-256-GCM evidence envelope
  -> metadata-only security observation
  -> PostgreSQL RLS deployment reference
```

It retains EdDSA/Ed25519 JWT verification with separately supplied public keys, issuer/audience/time/MFA/role checks, exact `FinancialEntity.entity_id` binding, explicit `TenantContext`, AES-256-GCM evidence encryption, external key references, secret-free observability and PostgreSQL `ENABLE` + `FORCE ROW LEVEL SECURITY` with a non-superuser `NOBYPASSRLS` application role.

The repository does **not** fetch live JWKS, discover an identity provider, perform revocation checks, hold production encryption keys, validate a real KMS/HSM, or prove production PostgreSQL isolation.

See [`docs/SECURITY_BOUNDARY.md`](docs/SECURITY_BOUNDARY.md).

## Retained v0.4 resilience assurance and portfolio views

The v0.4 assurance layer remains intact:

```text
verified governance dossier -> entity assurance position -> provider exposure aggregation -> portfolio assurance snapshot
```

It provides institution-owned assurance policies, verified-dossier-only aggregation, deterministic domain summaries, fail-closed `revalidation_required > breached > incomplete > attention > healthy` precedence, provider exposure aggregation, append-only portfolio snapshots and historical-vs-current verification.

Assurance artifacts structurally keep `dora_compliance_determined=false`, `operational_resilience_determined=false`, `supervisory_acceptance_determined=false` and `requires_human_review=true`. Provider/portfolio concentration artifacts additionally keep `legal_concentration_risk_determined=false`.

See [`docs/RESILIENCE_ASSURANCE.md`](docs/RESILIENCE_ASSURANCE.md).

## Retained v0.3 incident-reporting evidence

The incident-reporting workflow remains an offline, append-only governance chain:

```text
incident snapshot -> human classification review -> human reporting-applicability decision
-> route -> report package/revision -> external submission receipt
-> optional authority acknowledgement -> workflow assessment -> governance dossier
```

It retains pinned reference profiles `EU-2025-301@2025-02-20` and `EU-2025-302-ANNEX-I@2025-02-20`, deterministic deadline evidence, revision chains, imported receipts/acknowledgements and explicit separation between represented evidence and legal/supervisory conclusions.

See [`docs/INCIDENT_REPORTING.md`](docs/INCIDENT_REPORTING.md).

## Retained v0.2 continuity and recovery evidence

v0.2 remains the continuity/recovery evidence layer:

```text
inventory/dependency topology -> recovery objective -> exercise plan -> execution
-> recovery observation -> objective assessment -> finding/remediation/retest -> dossier
```

It preserves institution-owned disruption/RTO/RPO/service-level objectives, deterministic threshold assessment, stale-topology revalidation, remediation/retest evidence and bounded dependency-impact traversal. A `met` assessment means represented observations satisfy configured thresholds; it is not proof of successful production recovery or operational resilience.

## Retained v0.1 DORA governance foundation

The original executable foundation remains intact:

```text
inventory/dependencies -> ICT risk/control state -> incident evidence
-> resilience testing -> third-party register/concentration/exit evidence -> governance dossier
```

Core controls retain financial-entity scoped inventory, explicit human criticality decisions, deterministic ICT risk treatment, append-only incident evidence, resilience test/remediation evidence, third-party arrangement/supply-chain evidence and institution-owned gap/freshness/exit policies.

## Governance dossier

`GovernanceDossierBuilder` starts from the exact current inventory snapshot and packages canonical payloads for represented governance artifacts. Packaging revalidates current-state bindings instead of trusting historical status labels.

Dossier states remain:

- `current` — represented evidence is current for checked relationships;
- `with_gaps` — evidence is internally consistent but required governance/recovery/reporting/closure inputs are incomplete or breached;
- `revalidation_required` — a prior result is stale or no longer matches current governed evidence.

The dossier contains an exact inventory snapshot manifest and an outer SHA-256 digest. Offline verification recomputes the outer digest, embedded artifact digests and supported semantic cross-bindings. v0.6 can additionally bind that verified dossier digest into an externally signed regulatory-evidence statement.

## CLI

The wheel installs the `doraops` command:

```bash
doraops --version
doraops digest evidence.json
doraops schema schema.json evidence.json
doraops dossier verify governance-dossier.json
```

`digest` canonicalizes JSON before hashing. `schema` validates Draft 2020-12 schemas. `dossier verify` checks the dossier envelope, embedded artifact digests, aggregate state/findings consistency, inventory snapshot-manifest binding and supported continuity/reporting cross-bindings without network access.

Release-evidence previews are built separately:

```bash
python scripts/build_release_evidence_preview.py \
  --wheel dist/doraops-0.6.0-py3-none-any.whl \
  --source-revision <40-character-git-sha>
```

## Regulatory design posture

Primary design inputs include Regulation (EU) 2022/2554 (DORA), Commission Delegated Regulations (EU) 2024/1774 and 2024/1773, Commission Implementing Regulation (EU) 2024/2956, Commission Delegated Regulation (EU) 2025/301, and Commission Implementing Regulation (EU) 2025/302 with Annex I.

DORAOps maps technical/governance evidence to these sources while deliberately separating machine validation from legal applicability, supervisory interpretation and institution-owned policy decisions.

## Explicit non-claims

DORAOps v0.6.0 does **not** by itself establish:

- DORA compliance, certification, legal applicability or supervisory acceptance;
- real-world signer identity, authorization or legal authority merely because an Ed25519 signature verifies;
- production signing-key custody, HSM-backed signing or formal build attestation;
- a complete transitive SBOM, vulnerability assessment or vulnerability-free dependency set;
- production tenant isolation or production IAM effectiveness;
- real IdP/JWKS/revocation/key-rotation validation;
- production KMS/HSM or key-management effectiveness;
- production logging, monitoring or retention effectiveness;
- an operational-resilience, compliance or maturity score;
- legal ICT concentration risk;
- critical ICT third-party provider designation;
- correct legal incident reportability or competent-authority jurisdiction;
- successful regulator submission merely because a receipt is represented;
- successful disaster recovery, production failover, restoration or absence of data loss;
- absence of vulnerabilities or regulator-recognized TLPT;
- lawful risk acceptance or contractual sufficiency.

## Design principles

- exact financial-entity and governed-snapshot binding;
- deterministic canonical JSON and SHA-256 evidence;
- cryptographic integrity separated from signer authority and regulatory conclusions;
- explicit human criticality, applicability, treatment, classification, recovery, provider and assurance decisions;
- fail-closed stale, incomplete, conflicting, dangling, cross-scope and tampered references;
- immutable historical evidence rather than silent overwrite;
- historical verification separated from current eligibility;
- security context bound to the existing entity governance model rather than a parallel tenant namespace;
- external key references and separately supplied trusted verification keys rather than repository-held production secrets;
- qualified or regulatory claims require explicit evidence rather than inference from labels;
- governance core does not execute production recovery, failover or autonomous regulatory submission.

## Roadmap direction

`v0.1 governance foundation -> v0.2 continuity/recovery -> v0.3 incident reporting -> v0.4 resilience assurance -> v0.5 security/entity boundary -> v0.6 signed regulatory evidence/provenance -> v0.7 deployment hardening -> v0.8 DORA control/evidence matrix -> v0.9 release candidate -> v1.0 stable API/schema`

## License

Apache License 2.0.
