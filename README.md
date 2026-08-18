# DORAOps

**Open operational resilience control plane for DORA ICT risk, incidents, testing, third-party risk and verifiable regulatory evidence.**

## Summary

DORAOps is an open-source reference architecture for structuring and evidencing Digital Operational Resilience Act governance across ICT-supported business functions, services/processes, information and ICT assets, ICT risk, incidents, resilience testing and ICT third-party dependencies.

The project is not a legal-compliance engine, supervisory reporting service, regulator filing gateway, or certification product.

## Current implementation — v0.1.3 ICT incident evidence foundation

The current executable boundary retains the v0.1.1 inventory/dependency and v0.1.2 ICT-risk contracts and adds deterministic incident evidence governance:

- immutable ICT incident identity bound to an exact inventory snapshot;
- affected business-function, process, ICT-service, information/ICT-asset and third-party-service references validated against the governed inventory;
- provider impact derivable through exact affected third-party-service relationships rather than mutable provider names;
- occurred/detected incident timestamps and accountable incident owner;
- append-only, contiguous incident event timelines with immutable event identities;
- detected, escalated, contained, recovered, root-cause, remediation-link and notification-decision event types;
- explicit evidence digests for every timeline event and impact observation;
- structured impact observations across availability, confidentiality, integrity, client, financial, geographic and reputational dimensions;
- institution-configurable classification-readiness policy defining required impact dimensions and evidence classes;
- deterministic missing-input exposure instead of defaulting incomplete incidents to a final classification;
- exact incident evidence-snapshot and policy digest binding;
- fail-closed stale-readiness detection if incident evidence changes before review;
- final classification represented only as an explicit human-reviewed decision (`major`, `non_major` or `undetermined`);
- no fabricated regulator submission timestamps, acknowledgements or authority acceptance evidence;
- strict Draft 2020-12 JSON Schemas for incident, event, impact, readiness and human-review artifacts;
- Python 3.11/3.12/3.13 CI, wheel build and clean-wheel smoke testing.

The incident layer provides classification **readiness evidence**, not an autonomous legal determination that an incident is major or reportable. A human reviewer remains accountable for the recorded classification decision, and institution-specific reporting/legal workflows remain outside this milestone.

## Existing inventory and ICT-risk foundation

DORAOps already provides financial-entity scoped inventory governance, explicit human critical/important-function classification, business-process/ICT-service/information-asset/ICT-asset inventories, ICT third-party provider/service supply-chain semantics, deterministic dependency edges, exact inventory snapshot digests, ICT risk scenarios, evidence-backed control observations, configurable inherent/residual risk decisions, treatment semantics and fail-closed stale-risk detection.

## Regulatory design posture

Primary design inputs include:

- Regulation (EU) 2022/2554 (DORA), including Article 8 identification/classification, ICT incident management/reporting governance, dependency inventory and ICT risk-management requirements;
- Commission Delegated Regulation (EU) 2024/1774 on ICT risk-management tools, methods, processes and policies;
- Commission Implementing Regulation (EU) 2024/2956 on standard templates for the register of information and ICT third-party supply-chain relationships.

DORAOps maps governance evidence to these sources while separating technical validation from legal applicability, compliance conclusions and regulator-submission claims.

## v0.1 roadmap

`inventory/dependencies → ICT risk/control state → incident evidence → resilience testing → third-party register/concentration/exit evidence → deterministic governance dossier`

The next milestone is resilience testing plans, findings and remediation evidence. Later v0.1 milestones add third-party register/concentration/exit evidence and the final deterministic dossier/CLI release gate.

## Design principles

- exact entity and governed-snapshot binding;
- deterministic machine-readable evidence;
- explicit human criticality, applicability, treatment and incident-classification decisions;
- fail-closed stale, incomplete, dangling and cross-scope references;
- append-only historical incident evidence rather than silent overwrite;
- regulatory mappings separated from legal/certification claims;
- governance core does not perform autonomous regulatory submission.

## License

Apache License 2.0.
