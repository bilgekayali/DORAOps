# DORAOps v0.4 Resilience Assurance and Portfolio Views

DORAOps v0.4 adds a deterministic, offline assurance aggregation layer over verified DORAOps governance dossiers.

The purpose of this layer is to make existing ICT-risk, incident/reporting, resilience-testing, continuity/recovery and ICT third-party evidence easier to review at entity and portfolio level without converting evidence status into a legal compliance score.

## Boundary

The v0.4 assurance layer consumes governance-dossier documents that already pass the DORAOps offline verifier. It does not call production systems, regulator endpoints, third-party providers, monitoring systems or recovery infrastructure.

The flow is:

`verified governance dossier -> entity assurance position -> provider exposure aggregation -> portfolio assurance snapshot`

The aggregate layer does not replace the underlying domain evidence. A portfolio snapshot is only as current as the exact dossier and policy digests to which it is bound.

## Institution-owned assurance policy

`AssurancePolicy` is versioned and append-only. The institution supplies:

- the domains that are required for the particular assurance view;
- maximum accepted dossier age;
- the number of entities sharing a provider that should surface an executive concentration threshold;
- the number of critical/important-function references sharing a provider that should surface an executive concentration threshold;
- accountable policy ownership and registration time.

These thresholds are governance inputs. They are not encoded as universal DORA legal thresholds and they do not determine legal ICT concentration risk.

## State model

DORAOps v0.4 uses the following precedence:

`revalidation_required > breached > incomplete > attention > healthy`

The meanings are evidence-governance meanings:

- `healthy`: the represented evidence is current and no modeled attention condition was found;
- `attention`: current evidence contains a represented high residual ICT risk, major incident, pending workflow, difficult substitutability, high/critical dependency concentration, third-party gap or portfolio threshold condition;
- `incomplete`: a required assurance domain or represented lifecycle evidence is incomplete;
- `breached`: an underlying domain artifact itself represents a breach/block state, such as a reporting deadline breach, recovery-objective breach or blocked resilience-test lifecycle;
- `revalidation_required`: the underlying artifact, dossier freshness or currentness binding is stale.

The aggregate layer does not promote an `attention` condition into a regulatory breach by itself.

## Entity positions

`EntityAssurancePosition` binds to:

- exact governance-dossier digest;
- dossier generation time and source revision;
- exact assurance-policy digest;
- deterministic domain summaries;
- critical/important business functions represented in inventory evidence;
- direct-provider arrangements and their supported/critical function references;
- current freshness state and findings.

Missing optional domains are not invented. Missing required domains fail closed as `incomplete`.

A dossier older than the institution-owned policy age limit is `revalidation_required`, even when its internal artifacts remain cryptographically valid.

## Provider portfolio exposure

Provider aggregation is derived only from represented third-party arrangement evidence. It can show:

- entities using the same direct provider;
- arrangement count;
- critical/important-function references exposed to that provider;
- count of represented high/critical dependency-concentration observations;
- whether institution-owned entity/function thresholds were reached.

`legal_concentration_risk_determined` is structurally fixed to `false`.

The portfolio view therefore surfaces concentration evidence for human governance review; it does not determine the legal conclusion required by Regulation (EU) 2022/2554.

## History versus currentness

Policies, dossiers and portfolio snapshots are append-only within the registry.

An exact historical snapshot remains verifiable after later policy or dossier drift. `assert_snapshot_current()` is intentionally stricter: it requires the latest policy, latest snapshot sequence and exact latest dossier digest for every entity position.

This separation preserves audit history without allowing stale executive evidence to masquerade as current.

## Structural non-claims

Entity and portfolio assurance artifacts structurally require:

- `dora_compliance_determined = false`;
- `operational_resilience_determined = false`;
- `supervisory_acceptance_determined = false`;
- `requires_human_review = true`.

Portfolio/provider artifacts additionally require:

- `legal_concentration_risk_determined = false`.

DORAOps v0.4 produces no compliance percentage, maturity score or automatic management-body conclusion.

## Regulatory design context

The engineering design is informed by Regulation (EU) 2022/2554, including its governance and ICT-risk-management requirements, continuous monitoring of ICT-risk evolution, incident/response/recovery governance and ICT third-party risk management. Commission Delegated Regulation (EU) 2024/1773 is also relevant to the alignment of critical/important-function third-party arrangements with ICT risk, business continuity and incident-reporting governance.

These sources are design inputs, not executable legal rules. Applicability, proportionality, regulatory interpretation and accountable management decisions remain outside the automated assurance result.
