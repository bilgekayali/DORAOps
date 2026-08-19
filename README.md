# DORAOps

**Open operational resilience control plane for DORA ICT risk, incidents, testing, third-party risk and verifiable regulatory evidence.**

## Summary

DORAOps is an open-source reference architecture for structuring and evidencing Digital Operational Resilience Act governance across ICT-supported business functions, services/processes, information and ICT assets, ICT risk, incidents, resilience testing, business-service continuity/recovery and ICT third-party dependencies.

Current package boundary: **DORAOps v0.2.0**.

The project is not a legal-compliance engine, disaster-recovery executor, production failover controller, supervisory reporting service, regulator filing gateway, or certification product.

## v0.2.0 business-service continuity and recovery evidence

v0.2.0 extends the v0.1.0 foundation with explicit institution-owned recovery objectives and deterministic continuity/recovery evidence:

`inventory/dependency topology → recovery objective → continuity exercise plan → execution → recovery observation → objective assessment → finding/remediation/retest → governance dossier`

The new boundary includes:

- exact recovery-objective profiles for governed business functions, business processes and ICT services;
- institution-owned maximum tolerable disruption, recovery-time objective, recovery-point objective and minimum-service-level values;
- integer seconds and basis points for deterministic threshold representation rather than floating-point control thresholds;
- continuity/recovery exercise plans bound to the exact current inventory/dependency snapshot and recovery-objective digest;
- accountable exercise owner, optional independent reviewer, explicit scenario, activation assumptions and exact governed scope nodes;
- immutable execution evidence and recovery observations for restoration duration, represented recovery-point loss and achieved service level;
- deterministic `met`, `breached` and `incomplete` objective assessment;
- missing metrics and conflicting latest observations fail closed rather than defaulting to success;
- stale objective/plan evidence requires revalidation after the governed topology changes;
- continuity findings, remediation and retest evidence, including independent-review requirements for passed blocking-finding closure;
- deterministic modeled dependency-impact traversal over the registered topology with explicit inbound/outbound/both direction and bounded depth;
- topology traversal is evidence about the registered dependency graph only and explicitly does not claim runtime impact discovery;
- typed continuity/recovery artifacts are packaged into the deterministic governance dossier and cross-bound offline;
- offline verification checks objective→plan→execution→observation→assessment and finding→remediation→retest→resolution references after validating artifact and outer-document digests;
- strict Draft 2020-12 schemas cover recovery objectives, exercise evidence, assessments, finding lifecycle and dependency-impact snapshots;
- Python 3.11/3.12/3.13 CI, schema validation, wheel build and clean-wheel CLI/API smoke remain release gates.

A `met` assessment means the supplied current observation satisfies the configured represented thresholds. It does **not** establish that the institution is operationally resilient or that a production recovery/failover would succeed.

## v0.1.0 foundation retained

The v0.1.0 executable foundation remains intact:

`inventory/dependencies → ICT risk/control state → incident evidence → resilience testing → third-party register/concentration/exit evidence → governance dossier`

Retained controls include:

- financial-entity scoped inventory, dependency and ICT third-party supply-chain references;
- explicit human critical/important-function classification;
- exact inventory snapshot digests and fail-closed dangling/cross-scope references;
- deterministic ICT inherent/residual risk decisions bound to scenario, policy and control evidence;
- explicit treatment semantics and stale-risk revalidation;
- append-only ICT incident timelines, impact observations and classification readiness;
- human-reviewed incident classification rather than autonomous legal reportability decisions;
- resilience test planning, execution, findings, remediation and independent retest evidence;
- blocking high/critical findings and qualified-TLPT evidence boundaries;
- contractual third-party arrangement, provider/service/function and subcontractor linkage;
- explicit provider designation, substitutability and concentration observations;
- institution-owned third-party gap/freshness policy and exit/transition-plan evidence.

Existing resilience-test governance and v0.2 continuity/recovery governance are intentionally separate domains. A continuity exercise does not become a penetration test or TLPT merely because both are operational-resilience evidence.

## Governance dossier

`GovernanceDossierBuilder` starts from the exact current inventory snapshot and packages canonical payloads for represented governance artifacts. During packaging it revalidates current-state bindings rather than trusting historical status labels.

Dossier artifacts carry one of three states:

- `current` — represented evidence is current for the checked relationships;
- `with_gaps` — evidence is internally consistent but configured governance inputs, recovery objectives or closure evidence are missing/breached;
- `revalidation_required` — a previously generated decision/result is stale or no longer matches current governed evidence.

The dossier contains an `inventory_snapshot_manifest` whose canonical digest reproduces the exact `InventoryRegistry.snapshot_digest`. The outer dossier also carries its own SHA-256 digest. Offline verification recomputes the outer digest, every embedded artifact digest and supported semantic cross-bindings before accepting the document.

The v1 dossier envelope is retained in v0.2.0 because its structural envelope did not change; the `release_version` advances to `0.2.0` and continuity artifacts are carried as a new governed domain.

A dossier state is an integrity/governance status for the represented evidence. It is not a compliance conclusion.

## CLI

The wheel installs the `doraops` command:

```bash
doraops --version
doraops digest evidence.json
doraops schema schema.json evidence.json
doraops dossier verify governance-dossier.json
```

`digest` canonicalizes JSON before hashing. `schema` validates Draft 2020-12 schemas. `dossier verify` checks the dossier envelope, embedded artifact digests, aggregate state/findings consistency, inventory snapshot-manifest binding and supported continuity cross-bindings without network access.

## Regulatory design posture

Primary design inputs include:

- Regulation (EU) 2022/2554 (DORA), including identification/classification, ICT risk management, incident governance, response/recovery, digital operational resilience testing and ICT third-party governance;
- Commission Delegated Regulation (EU) 2024/1774 on ICT risk-management tools, methods, processes and policies;
- Commission Implementing Regulation (EU) 2024/2956 on standard templates for the register of information and ICT third-party supply-chain relationships.

DORAOps maps technical/governance evidence to these sources while deliberately separating machine validation from legal applicability, supervisory interpretation and institution-owned policy decisions.

The internal `EU-2024-2956-support-v1` third-party mapping profile is intended to support transformation work. It is not represented as a regulator-submitted register or an authority-approved template implementation.

## Explicit non-claims

DORAOps v0.2.0 does **not** by itself establish:

- DORA compliance or legal applicability;
- supervisory or competent-authority acceptance;
- successful regulatory filing or receipt;
- operational resilience, business-continuity adequacy or production safety;
- legal/regulatory sufficiency of configured RTO, RPO, maximum-tolerable-disruption or minimum-service-level objectives;
- successful disaster recovery, production failover, restoration or absence of data loss;
- runtime dependency impact merely because a registered topology traversal produces impacted nodes;
- absence of vulnerabilities;
- successful or regulator-recognized TLPT;
- lawful/approved risk acceptance;
- critical ICT third-party provider designation;
- contractual sufficiency;
- correct legal incident reportability or reporting deadlines.

Those conclusions remain institution-, evidence-, regulator- and human-review dependent.

## Design principles

- exact entity and governed-snapshot binding;
- deterministic canonical JSON and SHA-256 evidence;
- explicit human criticality, applicability, treatment, classification, recovery-objective and provider-designation decisions;
- fail-closed stale, incomplete, conflicting, dangling and cross-scope references;
- immutable historical evidence rather than silent overwrite;
- objective assessment over supplied evidence rather than autonomous claims about real-world recovery success;
- qualified or regulatory claims require explicit evidence rather than inference from labels;
- offline-verifiable release evidence where possible;
- governance core does not execute production recovery, failover or autonomous regulatory submission.

## Roadmap direction

`v0.1 DORA governance foundation → v0.2 continuity/recovery evidence → v0.3 advanced incident/reporting workflow evidence → v0.4 resilience assurance/portfolio views → later production hardening`

## License

Apache License 2.0.