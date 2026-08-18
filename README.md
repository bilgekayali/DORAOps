# DORAOps

**Open operational resilience control plane for DORA ICT risk, incidents, testing, third-party risk and verifiable regulatory evidence.**

## Summary

DORAOps is an open-source reference architecture for structuring and evidencing Digital Operational Resilience Act governance across ICT-supported business functions, services/processes, information and ICT assets, ICT risk, incidents, resilience testing and ICT third-party dependencies.

The project is not a legal-compliance engine, supervisory reporting service, regulator filing gateway, or certification product.

## Current implementation — v0.1.4 resilience testing evidence

The executable boundary retains the v0.1.1 inventory/dependency, v0.1.2 ICT-risk and v0.1.3 incident-evidence contracts and adds deterministic digital operational resilience testing governance:

- test plans bound to an exact financial-entity inventory snapshot and exact ICT risk-decision digests;
- deterministic scope references across business functions, processes, ICT services, information/ICT assets and ICT third-party services;
- scenario, objective, accountable test owner and optional independent reviewer metadata;
- scenario-based, vulnerability, network-security, penetration, source-code, physical-security, performance and end-to-end test types;
- threat-led penetration testing represented only when an explicit qualification-evidence digest is supplied;
- test executions that fail closed if the inventory or bound ICT-risk state has changed since planning;
- evidence-bound execution outcome and immutable execution identifiers;
- structured low/medium/high/critical findings bound to the exact plan and execution;
- high/critical findings treated as blocking until remediation and successful retest evidence closes them;
- remediation artifacts and retest artifacts with temporal and reference integrity checks;
- configured independent-reviewer enforcement for successful finding closure;
- deterministic latest-evidence selection with conflicting-latest evidence failing closed;
- prior finding/remediation/retest evidence retained in the resolution history rather than overwritten;
- successful, successful-with-findings, blocked and incomplete test-resolution states;
- strict Draft 2020-12 JSON Schemas for plan, execution, finding, remediation, retest and resolution artifacts;
- Python 3.11/3.12/3.13 CI, wheel build and clean-wheel smoke testing.

A successful resolution is an internal governance result for the represented test evidence. It does **not** prove operational resilience, absence of vulnerabilities, successful TLPT, DORA compliance, supervisory acceptance or production safety.

## Existing governance foundation

DORAOps already provides financial-entity scoped inventory governance, explicit human critical/important-function classification, ICT third-party supply-chain references, deterministic dependency snapshots, configurable ICT risk/treatment evidence, immutable incident timelines and human-reviewed incident classification-readiness evidence.

## Regulatory design posture

Primary design inputs include:

- Regulation (EU) 2022/2554 (DORA), including identification/classification, ICT risk management, incident governance and digital operational resilience testing requirements;
- Commission Delegated Regulation (EU) 2024/1774 on ICT risk-management tools, methods, processes and policies;
- Commission Implementing Regulation (EU) 2024/2956 on standard templates for the register of information and ICT third-party supply-chain relationships.

DORAOps maps governance evidence to these sources while separating technical validation from legal applicability, compliance conclusions, qualified-TLPT determinations and regulator-submission claims.

## v0.1 roadmap

`inventory/dependencies → ICT risk/control state → incident evidence → resilience testing → third-party register/concentration/exit evidence → deterministic governance dossier`

The next milestone is ICT third-party register, concentration and exit evidence. The final v0.1 milestone packages the complete governed state into a deterministic offline-verifiable dossier and CLI release gate.

## Design principles

- exact entity and governed-snapshot binding;
- deterministic machine-readable evidence;
- explicit human criticality, applicability, treatment and classification decisions;
- fail-closed stale, incomplete, dangling and cross-scope references;
- immutable historical evidence rather than silent overwrite;
- qualified testing claims require explicit evidence rather than inference from a test name;
- regulatory mappings separated from legal/certification claims;
- governance core does not perform autonomous regulatory submission.

## License

Apache License 2.0.
