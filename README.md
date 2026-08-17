# DORAOps

**Evidence-backed digital operational resilience and ICT third-party risk governance for financial entities.**

## Summary

DORAOps is an open-source reference architecture for structuring and evidencing Digital Operational Resilience Act governance across ICT third-party relationships, critical dependencies, resilience testing, incidents, contractual controls, concentration risk, and exit planning.

Current development milestone: **v0.1.0 — ICT Third-Party Register Core**.

The project is not a legal-compliance engine, supervisory reporting service, or certification product.

## Purpose

DORA obligations span technology, security, procurement, legal, operational risk, business continuity, and third-party management. DORAOps turns those relationships into deterministic governance artifacts rather than treating them as disconnected spreadsheets.

v0.1 deliberately starts below the official reporting-template layer. It builds a normalized institution-scoped graph of ICT providers, supported business functions, and contractual arrangements, then validates structural completeness and critical-function evidence.

## v0.1 control flow

```text
ICTProvider + BusinessFunction + ICTArrangement
                    |
                    v
              RegisterBundle
                    |
                    v
             RegisterValidator
                    |
                    v
       RegisterValidationReport
```

## Safety and regulatory baseline

- no automated legal applicability determination;
- no claim that v0.1 output is a complete 2024/2956 register submission;
- no external provider discovery or contract scraping;
- no network/process capability in the core;
- explicit `regulatory_compliance_determined=false` in validation evidence;
- critical arrangements can be structurally checked for exit-plan and substitutability evidence without asserting supervisory sufficiency.

## Regulatory posture

Design inputs include:

- Regulation (EU) 2022/2554 — DORA: https://eur-lex.europa.eu/eli/reg/2022/2554/oj/eng
- Commission Implementing Regulation (EU) 2024/2956 — register-of-information templates: https://eur-lex.europa.eu/eli/reg_impl/2024/2956

## Roadmap

`v0.1 register core → v0.2 critical dependencies → v0.3 concentration/exit risk → v0.4 incidents → v0.5 resilience testing → official register mapping/hardening → v1.0`

See [docs/ROADMAP.md](docs/ROADMAP.md).

## License

Apache License 2.0.
