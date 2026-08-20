# DORAOps v0.3 Incident Reporting Workflow Evidence

DORAOps v0.3 adds an offline, evidence-backed workflow for preparing and assessing the lifecycle of major ICT-incident reporting. It deliberately separates governance evidence from actual competent-authority submission.

## Regulatory design inputs

The v0.3 reference contract is informed by:

- Regulation (EU) 2022/2554 (DORA), especially the major ICT-incident reporting lifecycle in Article 19;
- Commission Delegated Regulation (EU) 2025/301, used for the represented timing/content workflow;
- Commission Implementing Regulation (EU) 2025/302 and Annex I, used for the represented initial/intermediate/final reporting-template workflow.

These are engineering/control-design inputs. DORAOps does not decide legal applicability, competent-authority jurisdiction, reportability, compliance or supervisory acceptance.

The runtime pins the represented reference versions as:

- `EU-2025-301@2025-02-20`
- `EU-2025-302-ANNEX-I@2025-02-20`

## Evidence chain

The reporting boundary is intentionally downstream from the existing incident evidence and accountable human classification:

`incident evidence snapshot → human classification review → human reporting-applicability decision → reporting route → report package/revision → external submission receipt → optional authority acknowledgement → workflow assessment → governance dossier`

The library never turns a classification-readiness result into an autonomous legal reportability decision.

## Deadline representation

For an incident represented as applicable and human-classified as major, v0.3 models:

- initial notification: four hours from major classification, subject to the represented 24-hour awareness cap; when classification as major occurs later than 24 hours from awareness/detection, four hours from that classification;
- first intermediate report: 72 hours from the represented initial submission;
- recovery update: `without undue delay`, represented as a non-numeric obligation rather than inventing a timestamp;
- final report: one calendar month after the latest represented intermediate/update submission.

The runtime uses integer UTC epoch seconds for deterministic timestamp evidence. `one calendar month` is calendar arithmetic, not a fixed 30-day duration.

### Weekend / bank-holiday adjustments

DORAOps does not contain a hidden holiday calendar or infer a Member State's bank holidays. A later effective deadline can be represented only through explicit `DeadlineAdjustmentEvidence` containing:

- the original statutory due time;
- the later adjusted due time;
- reason exactly `weekend_or_bank_holiday`;
- an accountable owner;
- a digest of the institution-supplied calendar evidence.

The original statutory deadline remains visible in the assessment.

### Delayed reporting

A `DelayNotificationEvidence` may record evidence that the competent authority was informed of a delay by the represented deadline, including reason evidence. This does not convert a late report into an on-time report. A late submission remains `breached`; the finding records whether a timely delay notice was represented.

## Reporting routes

Three route modes are represented:

- `direct`: the financial entity is the submitter;
- `outsourced`: a distinct submitter is bound to outsourcing evidence;
- `aggregated`: a distinct third-party submitter is additionally bound to competent-authority permission evidence and aggregation-scope evidence.

These records prove only the represented governance bindings. They do not prove that an authority actually permits the arrangement unless the supplied evidence itself establishes that outside DORAOps.

## Packages, corrections and submission evidence

`IncidentReportPackage` pins:

- exact incident evidence snapshot;
- exact human classification review;
- exact reporting-applicability decision;
- exact reporting route;
- pinned RTS/ITS profiles;
- required-content evidence digest;
- prepared report-payload digest;
- preparer and preparation time.

Corrections are append-only contiguous revisions. A revision after revision 1 must bind the exact prior package digest.

DORAOps does not transmit the package. `SubmissionReceiptEvidence` is imported evidence that an external system/operator performed a submission. The `alternative` channel additionally requires technical-impossibility evidence; other channels must not carry that field.

`AuthorityAcknowledgementEvidence` is likewise imported evidence. Status values such as `received`, `accepted`, `rejected` and `technical_error` describe the represented external acknowledgement only. Even `accepted` does not make `authority_acceptance_determined` true.

## Historical evidence vs current eligibility

Report revisions, receipts, acknowledgements, deadline adjustments, delay notices, applicability history and route history remain immutable audit evidence.

Current reporting eligibility is separate. A new incident event/impact, a new applicability decision or a new route version can make a previous current-state assessment stale. The workflow then fails closed as `revalidation_required`; historical artifacts remain available rather than being rewritten.

## Governance dossier

`GovernanceDossierBuilder.add_incident_reporting()` requires the exact classification review to have already been added through `add_incident()`. It embeds:

- applicability-decision history;
- all entity reporting-route versions;
- every report-package revision;
- every represented external submission receipt;
- authority acknowledgements;
- deadline adjustments;
- delay notifications;
- the current workflow assessment.

The strict offline verifier recomputes cross-bindings, revision chains, route evidence semantics, receipt chronology, deadline adjustments and the initial/72-hour/final calendar-month deadline relationships from embedded evidence. Rehashing a forged artifact does not bypass these semantic checks.

## Explicit non-claims

DORAOps v0.3 does not:

- submit an incident report, call a regulator API, send email or operate a competent-authority portal;
- autonomously determine legal reportability or DORA applicability;
- determine regulatory compliance;
- determine supervisory/competent-authority acceptance;
- prove the authenticity of supplied external receipts or acknowledgements merely because their digests are bound;
- prove that a competent authority approved an outsourced or aggregated reporting arrangement;
- provide a hidden authoritative weekend/bank-holiday calendar;
- convert a timely delay notice into evidence that a late report met its original deadline;
- establish operational resilience, production recovery success or absence of data loss.
