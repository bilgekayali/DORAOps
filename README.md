# DORAOps

**Open operational resilience control plane for DORA ICT risk, incidents, testing, third-party risk and verifiable regulatory evidence.**

## Summary

DORAOps is an open-source reference architecture for structuring and evidencing Digital Operational Resilience Act governance across ICT-supported business functions, services/processes, information and ICT assets, ICT risk, incidents, resilience testing and ICT third-party dependencies.

The project is not a legal-compliance engine, supervisory reporting service, regulator filing gateway, or certification product.

## Current implementation — v0.1.1 inventory foundation

The first executable boundary provides:

- financial-entity scoped inventory governance;
- explicit human classification of business functions as standard or critical/important;
- business process and ICT service inventory;
- information-asset and ICT-asset inventory;
- ICT third-party provider and service references;
- direct-provider supply-chain rank 1 and subcontractor rank >1 semantics;
- required parent relationships for subcontracted ICT services;
- exact function/process/service/asset/third-party dependency edges;
- fail-closed dangling and cross-entity dependency validation;
- conflicting identity/overwrite protection;
- deterministic canonical JSON and inventory snapshot SHA-256 digests;
- strict Draft 2020-12 JSON Schemas;
- Python 3.11/3.12/3.13 CI and clean-wheel smoke testing.

Critical/important-function status remains an explicit accountable human decision. Inventory evidence does not itself establish resilience, DORA compliance or supervisory acceptance.

## Regulatory design posture

Primary design inputs include:

- Regulation (EU) 2022/2554 (DORA), including Article 8 identification/classification and dependency inventory requirements;
- Commission Delegated Regulation (EU) 2024/1774 on ICT risk-management tools, methods, processes and policies;
- Commission Implementing Regulation (EU) 2024/2956 on standard templates for the register of information and ICT third-party supply-chain relationships.

DORAOps maps governance evidence to these sources while separating technical validation from legal applicability, compliance conclusions and regulator-submission claims.

## v0.1 roadmap

`inventory/dependencies → ICT risk/control state → incident evidence → resilience testing → third-party register/concentration/exit evidence → deterministic governance dossier`

Later milestones may add signed governance/change control, tenant/crypto hardening, external reporting packages and production-reference deployment patterns.

## Design principles

- exact entity and governed-snapshot binding;
- deterministic machine-readable evidence;
- explicit human criticality/applicability decisions;
- fail-closed stale, dangling and cross-scope references;
- historical evidence rather than silent overwrite;
- regulatory mappings separated from legal/certification claims;
- governance core does not perform autonomous regulatory submission.

## License

Apache License 2.0.
