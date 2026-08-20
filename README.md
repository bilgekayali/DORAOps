# DORAOps

**Open operational resilience control plane for DORA ICT risk, incidents, testing, third-party risk and verifiable regulatory evidence.**

## Summary

DORAOps is an open-source reference architecture for structuring and evidencing Digital Operational Resilience Act governance across ICT-supported business functions, services/processes, information and ICT assets, ICT risk, incidents, resilience testing, business-service continuity/recovery, incident-reporting workflows, ICT third-party dependencies and executive resilience-assurance views.

Current package boundary: **DORAOps v0.4.0**.

The project is not a legal-compliance engine, disaster-recovery executor, production failover controller, supervisory reporting service, regulator filing gateway, certification product, legal concentration-risk engine or operational-resilience scoring product.

## v0.4.0 resilience assurance and portfolio views

v0.4.0 adds a deterministic, offline assurance layer over verified DORAOps governance dossiers:

`verified governance dossier → entity assurance position → provider exposure aggregation → portfolio assurance snapshot`

The v0.4 boundary includes:

- append-only, institution-owned `AssurancePolicy` versions defining required domains, dossier freshness and executive provider-concentration thresholds;
- verified-dossier ingestion only: aggregate views are derived from dossiers that pass the existing offline semantic verifier;
- deterministic domain summaries for ICT risk, incidents, incident reporting, resilience testing, continuity/recovery and ICT third-party evidence;
- fail-closed state precedence `revalidation_required > breached > incomplete > attention > healthy`;
- high/critical residual ICT risk, major incidents, pending reporting workflows, difficult substitutability and represented high/critical dependency concentration surfaced as `attention`, not promoted into a regulatory breach;
- `breached` reserved for underlying domain evidence that itself represents a breach/block state, such as a reporting-deadline breach, recovery-objective breach or blocked resilience-test lifecycle;
- missing policy-required domains surfaced as `incomplete` rather than silently omitted;
- dossier age exceeding the institution-owned policy threshold surfaced as `revalidation_required` even when historical digests remain valid;
- critical/important business-function references derived from exact inventory evidence;
- direct-provider exposure derived from represented third-party arrangements, including supported functions, critical/important functions and high/critical dependency-concentration observations;
- cross-entity provider aggregation showing entity count, arrangement count and critical-function references;
- institution-owned provider/entity and provider/critical-function thresholds that surface executive `attention` without determining legal ICT concentration risk;
- append-only portfolio snapshot sequences, deterministic rebuild checks and historical-vs-current separation;
- historical snapshots remain verifiable after later dossier/policy drift, while `assert_snapshot_current()` requires latest policy, latest sequence and latest dossier digest for every entity;
- strict Draft 2020-12 schemas and structural non-claims for entity/provider/portfolio assurance artifacts;
- no compliance percentage, maturity score or automatic management-body conclusion;
- generic Python 3.11/3.12/3.13 CI plus a dedicated Resilience Assurance Portfolio Boundary gate.

Entity and portfolio assurance artifacts structurally require `dora_compliance_determined=false`, `operational_resilience_determined=false`, `supervisory_acceptance_determined=false` and `requires_human_review=true`. Provider/portfolio concentration artifacts additionally require `legal_concentration_risk_determined=false`.

See [`docs/RESILIENCE_ASSURANCE.md`](docs/RESILIENCE_ASSURANCE.md) for the detailed aggregate-evidence semantics.

## v0.3.0 advanced incident-reporting workflow evidence retained

v0.3.0 extends the retained incident-evidence foundation with an offline, append-only reporting-governance workflow:

`incident evidence snapshot → human classification review → human reporting-applicability decision → reporting route → report package/revision → external submission receipt → optional authority acknowledgement → workflow assessment → governance dossier`

The retained v0.3 boundary includes:

- exact binding to the existing append-only ICT incident evidence snapshot and accountable human classification review;
- versioned, human-owned reporting-applicability decisions rather than autonomous legal reportability;
- direct, outsourced and aggregated reporting-route evidence with stricter evidence requirements for third-party/aggregated submission;
- report packages for initial notification, intermediate reports, final reports and reclassification notifications;
- pinned reference profiles `EU-2025-301@2025-02-20` and `EU-2025-302-ANNEX-I@2025-02-20`;
- append-only correction/revision chains bound to the exact previous report-package digest;
- imported external submission receipts rather than an embedded regulator-network client;
- alternative-channel submission evidence requiring explicit technical-impossibility evidence;
- imported competent-authority acknowledgement evidence without converting `accepted` into supervisory acceptance;
- initial-deadline evidence representing the four-hour major-classification requirement and 24-hour awareness cap;
- first intermediate deadline represented as 72 hours from initial submission;
- recovery updates represented as `without undue delay` without fabricating a numeric deadline;
- final-report deadline represented using one-calendar-month arithmetic rather than a fixed 30-day duration;
- explicit institution-supplied weekend/bank-holiday adjustment evidence while retaining the original statutory deadline;
- delay-notification evidence that does not convert a late submission into an on-time result;
- deterministic `not_required`, `incomplete`, `pending`, `breached`, `complete` and `revalidation_required` workflow states;
- historical applicability, route, package-revision, receipt, acknowledgement, deadline-adjustment and delay-notice evidence retained separately from current eligibility;
- reporting artifacts integrated into the governance dossier with offline semantic recomputation and tamper-resistant cross-binding;
- strict Draft 2020-12 schemas, adversarial tests, generic CI and a dedicated Incident Reporting Boundary gate.

The reporting core performs no HTTP/API/email submission and does not contain autonomous competent-authority routing or legal-applicability logic.

See [`docs/INCIDENT_REPORTING.md`](docs/INCIDENT_REPORTING.md) for the detailed evidence and deadline semantics.

## v0.2.0 business-service continuity and recovery evidence retained

v0.2.0 introduced explicit institution-owned recovery objectives and deterministic continuity/recovery evidence:

`inventory/dependency topology → recovery objective → continuity exercise plan → execution → recovery observation → objective assessment → finding/remediation/retest → governance dossier`

Retained controls include:

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
- deterministic modeled dependency-impact traversal over the registered topology with explicit direction and bounded depth;
- typed continuity/recovery artifacts packaged into the governance dossier and cross-bound offline.

A `met` recovery assessment means supplied current observations satisfy configured represented thresholds. It does **not** establish operational resilience or successful production recovery/failover.

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

Existing resilience-test, continuity/recovery, incident-reporting and assurance domains remain intentionally distinct. Aggregate evidence does not silently establish a conclusion in an underlying domain and underlying evidence does not silently establish a legal portfolio conclusion.

## Governance dossier

`GovernanceDossierBuilder` starts from the exact current inventory snapshot and packages canonical payloads for represented governance artifacts. During packaging it revalidates current-state bindings rather than trusting historical status labels.

Dossier artifacts carry one of three states:

- `current` — represented evidence is current for the checked relationships;
- `with_gaps` — evidence is internally consistent but configured governance inputs, recovery/reporting objectives or closure evidence are missing/breached;
- `revalidation_required` — a previously generated decision/result is stale or no longer matches current governed evidence.

The dossier contains an `inventory_snapshot_manifest` whose canonical digest reproduces the exact `InventoryRegistry.snapshot_digest`. The outer dossier also carries its own SHA-256 digest. Offline verification recomputes the outer digest, every embedded artifact digest and supported semantic cross-bindings before accepting the document.

The v1 dossier envelope is retained in v0.4.0 because its structural envelope did not change; only `release_version` advances to `0.4.0`. The assurance layer consumes these verified dossiers rather than changing their domain semantics.

A dossier state is an integrity/governance status for represented evidence. It is not a compliance conclusion.

## CLI

The wheel installs the `doraops` command:

```bash
doraops --version
doraops digest evidence.json
doraops schema schema.json evidence.json
doraops dossier verify governance-dossier.json
```

`digest` canonicalizes JSON before hashing. `schema` validates Draft 2020-12 schemas. `dossier verify` checks the dossier envelope, embedded artifact digests, aggregate state/findings consistency, inventory snapshot-manifest binding and supported continuity/reporting cross-bindings without network access.

The v0.4 assurance API is exposed through `doraops.assurance`; it does not add a networked portfolio service or deployment endpoint.

## Regulatory design posture

Primary design inputs include:

- Regulation (EU) 2022/2554 (DORA), including governance, ICT risk management, incident governance/reporting, response/recovery, digital operational resilience testing and ICT third-party governance;
- Commission Delegated Regulation (EU) 2024/1774 on ICT risk-management tools, methods, processes and policies;
- Commission Delegated Regulation (EU) 2024/1773 on contractual arrangements for ICT services supporting critical or important functions;
- Commission Implementing Regulation (EU) 2024/2956 on standard templates for the register of information and ICT third-party supply-chain relationships;
- Commission Delegated Regulation (EU) 2025/301 for major ICT-incident reporting content/timing design;
- Commission Implementing Regulation (EU) 2025/302 and Annex I for the represented major ICT-incident reporting template/procedure workflow.

DORAOps maps technical/governance evidence to these sources while deliberately separating machine validation from legal applicability, supervisory interpretation and institution-owned policy decisions.

The internal `EU-2024-2956-support-v1` third-party mapping profile is intended to support transformation work. It is not represented as a regulator-submitted register or an authority-approved template implementation.

## Explicit non-claims

DORAOps v0.4.0 does **not** by itself establish:

- DORA compliance or legal applicability;
- an operational-resilience or compliance score;
- management-body approval or supervisory acceptance of an assurance snapshot;
- legal ICT concentration risk merely because an institution-owned portfolio threshold is reached;
- critical ICT third-party provider designation;
- correct legal incident reportability or competent-authority jurisdiction;
- supervisory or competent-authority acceptance;
- successful regulatory filing merely because a report package or receipt is represented;
- authenticity of external submission/acknowledgement evidence merely because its digest is bound;
- authority approval of outsourced or aggregated reporting merely because permission evidence is referenced;
- operational resilience, business-continuity adequacy or production safety;
- legal/regulatory sufficiency of configured RTO, RPO, maximum-tolerable-disruption or minimum-service-level objectives;
- successful disaster recovery, production failover, restoration or absence of data loss;
- runtime dependency impact merely because a registered topology traversal produces impacted nodes;
- absence of vulnerabilities;
- successful or regulator-recognized TLPT;
- lawful/approved risk acceptance;
- contractual sufficiency.

Those conclusions remain institution-, evidence-, regulator- and human-review dependent.

## Design principles

- exact entity and governed-snapshot binding;
- deterministic canonical JSON and SHA-256 evidence;
- explicit human criticality, applicability, treatment, classification, reporting-applicability, recovery-objective, provider-designation and assurance-policy decisions;
- fail-closed stale, incomplete, conflicting, dangling and cross-scope references;
- immutable historical evidence rather than silent overwrite;
- historical verification separated from current eligibility;
- executive aggregation over verified evidence rather than autonomous compliance or maturity scoring;
- qualified or regulatory claims require explicit evidence rather than inference from labels;
- offline-verifiable release evidence where possible;
- governance core does not execute production recovery, failover or autonomous regulatory submission.

## Roadmap direction

`v0.1 DORA governance foundation → v0.2 continuity/recovery evidence → v0.3 incident-reporting workflow evidence → v0.4 resilience assurance/portfolio views → later tenant/crypto and production hardening`

## License

Apache License 2.0.
