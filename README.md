# DORAOps

**Open operational resilience control plane for DORA ICT risk, incidents, testing, third-party risk and verifiable regulatory evidence.**

## Summary

DORAOps is an open-source reference architecture for structuring and evidencing Digital Operational Resilience Act governance across ICT-supported business functions, services/processes, information and ICT assets, ICT risk, incidents, resilience testing and ICT third-party dependencies.

The project is not a legal-compliance engine, supervisory reporting service, regulator filing gateway, or certification product.

## Current implementation — v0.1.5 ICT third-party register evidence

The executable boundary retains the inventory/dependency, ICT-risk, incident-evidence and resilience-testing contracts and adds deterministic ICT third-party arrangement governance:

- contractual arrangements bound to an exact financial-entity inventory snapshot;
- exact direct-provider, rank-1 direct-service, supported-function and subcontractor references;
- subcontractor ancestry validation against the arrangement's direct-service roots;
- explicit critical-or-important-function identifiers validated against the existing human-governed function classifications;
- explicit provider-designation state, accountable owner and rationale rather than inference from provider names;
- governed data-location and service-location evidence;
- contract and control-requirement evidence digests;
- explicit substitutability and concentration observations with immutable evidence binding;
- institution-owned freshness and evidence requirements through a versioned third-party governance policy;
- exit/transition-plan evidence with accountable owner, triggers, transition steps and optional alternate-provider reference;
- deterministic policy-driven gaps for missing designation, locations, contract/control evidence, dependency observations, stale observations and required exit plans;
- fail-closed conflicting-latest dependency observations and exit plans;
- historical arrangement/observation/exit-plan evidence that cannot be silently overwritten;
- deterministic register rows preserving supply-chain rank and parent-service relationships;
- an internal `EU-2024-2956-support-v1` mapping profile intended to support register-of-information transformation work without claiming regulator-submission equivalence;
- strict Draft 2020-12 JSON Schemas for arrangement, dependency observation, exit plan, governance policy and register snapshot artifacts;
- Python 3.11/3.12/3.13 CI, wheel build and clean-wheel smoke testing.

A complete register snapshot means the configured **institution-owned governance policy** has no represented gaps for that snapshot. It does not establish DORA compliance, contractual sufficiency, critical-provider designation, supervisory acceptance or regulator-ready filing status.

## Existing governance foundation

DORAOps already provides financial-entity scoped inventory governance, explicit human critical/important-function classification, deterministic ICT-risk and treatment evidence, immutable incident timelines with human-reviewed classification readiness, and evidence-backed resilience-test planning/finding/remediation/retest resolution.

## Regulatory design posture

Primary design inputs include:

- Regulation (EU) 2022/2554 (DORA), including identification/classification, ICT risk management, incident governance, digital operational resilience testing and ICT third-party governance;
- Commission Delegated Regulation (EU) 2024/1774 on ICT risk-management tools, methods, processes and policies;
- Commission Implementing Regulation (EU) 2024/2956 on standard templates for the register of information and ICT third-party supply-chain relationships.

DORAOps maps governance evidence to these sources while separating technical validation from legal applicability, compliance conclusions, critical-provider designation and regulator-submission claims.

## v0.1 roadmap

`inventory/dependencies → ICT risk/control state → incident evidence → resilience testing → third-party register/concentration/exit evidence → deterministic governance dossier`

The remaining v0.1 milestone packages the complete governed state into a deterministic offline-verifiable dossier and CLI release gate.

## Design principles

- exact entity and governed-snapshot binding;
- deterministic machine-readable evidence;
- explicit human criticality, applicability, treatment, classification and provider-designation decisions;
- fail-closed stale, incomplete, dangling and cross-scope references;
- immutable historical evidence rather than silent overwrite;
- qualified or regulatory claims require explicit evidence rather than inference from labels;
- regulatory mappings separated from legal/certification/submission claims;
- governance core does not perform autonomous regulatory submission.

## License

Apache License 2.0.
