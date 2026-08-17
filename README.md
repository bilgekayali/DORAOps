# DORAOps

**Open operational resilience control plane for DORA ICT risk, incidents, testing, third-party risk and verifiable regulatory evidence.**

## Summary

DORAOps is an open-source reference architecture for structuring and evidencing Digital Operational Resilience Act governance across ICT-supported business functions, services/processes, information and ICT assets, ICT risk, incidents, resilience testing and ICT third-party dependencies.

The project is not a legal-compliance engine, supervisory reporting service, regulator filing gateway, or certification product.

## Current implementation — v0.1.2 inventory and ICT risk foundation

The current executable boundary provides:

- financial-entity scoped inventory governance;
- explicit human classification of business functions as standard or critical/important;
- business-process and ICT-service inventory;
- information-asset and ICT-asset inventory;
- ICT third-party provider and service references;
- direct-provider supply-chain rank 1 and subcontractor rank >1 semantics;
- required parent relationships for subcontracted ICT services;
- exact function/process/service/asset/third-party dependency edges;
- fail-closed dangling and cross-entity dependency validation;
- conflicting identity/overwrite protection;
- deterministic canonical JSON and inventory snapshot SHA-256 digests;
- ICT risk scenarios bound to exact affected inventory nodes and accountable risk owners;
- deterministic inherent ICT risk derived from explicit likelihood and impact observations;
- evidence-backed ICT control observations with bounded residual-risk credit;
- entity-scoped, versioned ICT risk policy profiles and deterministic residual-risk decisions;
- explicit mitigate, accept, avoid and transfer treatment semantics;
- mandatory target timestamps for mitigation treatment;
- explicit high/critical residual-risk acceptance and remediation-required state;
- exact inventory-snapshot, scenario, policy and control-evidence digest binding;
- fail-closed stale-risk detection after inventory, scenario, policy or control evidence changes;
- strict Draft 2020-12 JSON Schemas for inventory, dependency and ICT-risk artifacts;
- Python 3.11/3.12/3.13 CI, wheel build and clean-wheel smoke testing.

Critical/important-function status and risk treatment remain accountable governance decisions. Inventory or risk evidence does not itself establish resilience, DORA compliance, supervisory acceptance or lawful risk acceptance.

## Regulatory design posture

Primary design inputs include:

- Regulation (EU) 2022/2554 (DORA), including Article 8 identification/classification, dependency inventory and ICT risk-management requirements;
- Commission Delegated Regulation (EU) 2024/1774 on ICT risk-management tools, methods, processes and policies;
- Commission Implementing Regulation (EU) 2024/2956 on standard templates for the register of information and ICT third-party supply-chain relationships.

DORAOps maps governance evidence to these sources while separating technical validation from legal applicability, compliance conclusions and regulator-submission claims.

## v0.1 roadmap

`inventory/dependencies → ICT risk/control state → incident evidence → resilience testing → third-party register/concentration/exit evidence → deterministic governance dossier`

The next milestone is the ICT incident evidence timeline and classification-readiness layer. Later v0.1 milestones add resilience testing, third-party register/concentration/exit evidence and the final deterministic dossier/CLI release gate.

## Design principles

- exact entity and governed-snapshot binding;
- deterministic machine-readable evidence;
- explicit human criticality, applicability and treatment decisions;
- fail-closed stale, dangling and cross-scope references;
- historical evidence rather than silent overwrite;
- regulatory mappings separated from legal/certification claims;
- governance core does not perform autonomous regulatory submission.

## License

Apache License 2.0.
