# DORAOps

**Open operational resilience control plane for DORA ICT risk, incidents, testing, third-party risk and verifiable regulatory evidence.**

## Summary

DORAOps is an open-source reference architecture for structuring and evidencing Digital Operational Resilience Act governance across ICT-supported business functions, services/processes, information and ICT assets, ICT risk, incidents, resilience testing and ICT third-party dependencies.

The project is not a legal-compliance engine, supervisory reporting service, regulator filing gateway, or certification product.

## v0.1.0 foundation release

The v0.1.0 executable boundary provides an end-to-end, deterministic governance evidence chain:

`inventory/dependencies → ICT risk/control state → incident evidence → resilience testing → third-party register/concentration/exit evidence → governance dossier`

Core controls include:

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
- institution-owned third-party gap/freshness policy and exit/transition-plan evidence;
- strict Draft 2020-12 JSON Schemas across release artifacts;
- deterministic v0.1 governance dossier with embedded canonical artifact payloads and SHA-256 digests;
- offline dossier and embedded-artifact tamper detection;
- Python 3.11/3.12/3.13 CI, wheel build and clean-wheel CLI smoke.

## Governance dossier

`GovernanceDossierBuilder` starts from the exact current inventory snapshot and packages canonical payloads for represented governance artifacts. During packaging it revalidates current-state bindings rather than trusting historical status labels.

Dossier artifacts carry one of three states:

- `current` — represented evidence is current for the checked relationships;
- `with_gaps` — evidence is internally consistent but configured governance inputs or closure evidence are missing;
- `revalidation_required` — a previously generated decision/result is stale or no longer matches current governed evidence.

The dossier contains an `inventory_snapshot_manifest` whose canonical digest reproduces the exact `InventoryRegistry.snapshot_digest`. The outer dossier also carries its own SHA-256 digest. Offline verification recomputes the outer digest and every embedded artifact digest before accepting the document.

A dossier state is an integrity/governance status for the represented evidence. It is not a compliance conclusion.

## CLI

The wheel installs the `doraops` command:

```bash
doraops --version
doraops digest evidence.json
doraops schema schema.json evidence.json
doraops dossier verify governance-dossier.json
```

`digest` canonicalizes JSON before hashing. `schema` validates Draft 2020-12 schemas. `dossier verify` checks the dossier envelope, embedded artifact digests, aggregate state/findings consistency and inventory snapshot-manifest binding without network access.

## Regulatory design posture

Primary design inputs include:

- Regulation (EU) 2022/2554 (DORA), including identification/classification, ICT risk management, incident governance, digital operational resilience testing and ICT third-party governance;
- Commission Delegated Regulation (EU) 2024/1774 on ICT risk-management tools, methods, processes and policies;
- Commission Implementing Regulation (EU) 2024/2956 on standard templates for the register of information and ICT third-party supply-chain relationships.

DORAOps maps technical/governance evidence to these sources while deliberately separating machine validation from legal applicability, supervisory interpretation and institution-owned policy decisions.

The internal `EU-2024-2956-support-v1` third-party mapping profile is intended to support transformation work. It is not represented as a regulator-submitted register or an authority-approved template implementation.

## Explicit non-claims

DORAOps v0.1.0 does **not** by itself establish:

- DORA compliance or legal applicability;
- supervisory or competent-authority acceptance;
- successful regulatory filing or receipt;
- operational resilience or production safety;
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
- explicit human criticality, applicability, treatment, classification and provider-designation decisions;
- fail-closed stale, incomplete, dangling and cross-scope references;
- immutable historical evidence rather than silent overwrite;
- qualified or regulatory claims require explicit evidence rather than inference from labels;
- offline-verifiable release evidence where possible;
- governance core does not perform autonomous regulatory submission.

## License

Apache License 2.0.
