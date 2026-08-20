from __future__ import annotations

from copy import deepcopy

import pytest

import doraops
from doraops import (
    BusinessFunction,
    DossierState,
    FinancialEntity,
    FunctionClassification,
    GovernanceDossierBuilder,
    GovernanceError,
    HumanClassificationDecision,
    ICTIncident,
    ICTService,
    ImpactDimension,
    ImpactSeverity,
    IncidentClassificationPolicy,
    IncidentEvent,
    IncidentEventType,
    IncidentImpactObservation,
    IncidentReportPackage,
    IncidentReportType,
    IncidentReportingRegistry,
    IncidentReportingRoute,
    IncidentRegistry,
    InventoryRegistry,
    ITS_TEMPLATE_PROFILE,
    NodeKind,
    NodeRef,
    ReportingApplicability,
    ReportingApplicabilityDecision,
    ReportingWorkflowState,
    RTS_CONTENT_PROFILE,
    SubmissionChannel,
    SubmissionMode,
    SubmissionReceiptEvidence,
    assess_classification_readiness,
    assess_reporting_workflow,
    dossier_document,
    package_history,
    review_incident_classification,
    sha256_digest,
    submission_receipts,
    verify_dossier_document,
)


def digest(seed: str) -> str:
    return sha256_digest({"seed": seed})


def reporting_fixture():
    inventory = InventoryRegistry()
    inventory.register_entity(FinancialEntity("bank-a", "Bank A", "DE"))
    inventory.register_node(
        BusinessFunction(
            "bank-a",
            "payments",
            "Payments",
            FunctionClassification.CRITICAL_OR_IMPORTANT,
            "board-owner",
            "human criticality decision",
        )
    )
    inventory.register_node(ICTService("bank-a", "payment-api", "Payment API", "svc-owner", "application"))
    refs = (
        NodeRef("bank-a", NodeKind.BUSINESS_FUNCTION, "payments"),
        NodeRef("bank-a", NodeKind.ICT_SERVICE, "payment-api"),
    )
    incident = ICTIncident(
        entity_id="bank-a",
        incident_id="INC-DOSSIER-1",
        title="Payment API interruption",
        incident_owner_id="incident-owner",
        occurred_at=1_800_000_000,
        detected_at=1_800_000_060,
        inventory_snapshot_digest=inventory.snapshot_digest("bank-a"),
        affected_nodes=refs,
    )
    incidents = IncidentRegistry(inventory)
    incidents.register_incident(incident)
    incidents.append_event(
        IncidentEvent(
            entity_id="bank-a",
            incident_id=incident.incident_id,
            event_id="notification-decision",
            sequence=1,
            event_type=IncidentEventType.NOTIFICATION_DECISION,
            occurred_at=1_800_000_120,
            recorded_at=1_800_000_121,
            actor_id="incident-owner",
            summary="classification/reporting decision evidence available",
            evidence_digest=digest("notification-decision"),
            related_reference="NOTIFY-1",
        )
    )
    incidents.register_impact(
        IncidentImpactObservation(
            entity_id="bank-a",
            incident_id=incident.incident_id,
            impact_id="availability-impact",
            dimension=ImpactDimension.SERVICE_AVAILABILITY,
            severity=ImpactSeverity.SEVERE,
            observed_at=1_800_000_130,
            affected_nodes=(refs[1],),
            summary="Payment API unavailable",
            evidence_digest=digest("impact"),
        )
    )
    policy = IncidentClassificationPolicy(
        entity_id="bank-a",
        policy_id="classification-policy",
        version="1",
        required_impact_dimensions=(ImpactDimension.SERVICE_AVAILABILITY,),
        require_recovery_event=False,
        require_root_cause_reference=False,
        require_remediation_reference=False,
        require_notification_decision=True,
    )
    readiness = assess_classification_readiness(incidents, "bank-a", incident.incident_id, policy)
    review = review_incident_classification(
        incidents,
        readiness,
        policy,
        reviewer_id="incident-classifier",
        decision=HumanClassificationDecision.MAJOR,
        rationale="accountable human major classification",
        reviewed_at=1_800_003_600,
    )
    reporting = IncidentReportingRegistry(incidents)
    applicability = ReportingApplicabilityDecision(
        entity_id="bank-a",
        incident_id=incident.incident_id,
        decision_id="dora-reporting-applicability",
        decision_version=1,
        incident_evidence_snapshot_digest=incidents.evidence_snapshot_digest("bank-a", incident.incident_id),
        classification_review_digest=review.evidence_digest,
        applicability=ReportingApplicability.APPLICABLE,
        decision_owner_id="legal-risk-owner",
        rationale_digest=digest("applicability-rationale"),
        applicability_evidence_digest=digest("applicability-evidence"),
        decided_at=1_800_003_610,
    )
    reporting.register_applicability(applicability, review)
    route = IncidentReportingRoute(
        entity_id="bank-a",
        route_id="primary-route",
        version=1,
        competent_authority_id="DE-NCA",
        member_state="DE",
        submission_mode=SubmissionMode.DIRECT,
        submitter_id="bank-a",
        contact_evidence_digest=digest("route-contact"),
        outsourcing_evidence_digest=None,
        authority_permission_evidence_digest=None,
        aggregation_scope_evidence_digest=None,
        registered_at=1_800_000_000,
    )
    reporting.register_route(route)
    return inventory, incidents, incident, policy, review, reporting, applicability, route


def report_package(kind, sequence, review, applicability, route, prepared_at):
    return IncidentReportPackage(
        entity_id="bank-a",
        incident_id="INC-DOSSIER-1",
        report_type=kind,
        sequence=sequence,
        revision=1,
        incident_evidence_snapshot_digest=applicability.incident_evidence_snapshot_digest,
        classification_review_digest=review.evidence_digest,
        applicability_decision_digest=applicability.evidence_digest,
        route_digest=route.evidence_digest,
        rts_content_profile=RTS_CONTENT_PROFILE,
        its_template_profile=ITS_TEMPLATE_PROFILE,
        required_content_evidence_digest=digest(f"required-{kind.value}-{sequence}"),
        report_payload_digest=digest(f"payload-{kind.value}-{sequence}"),
        prepared_by_id="reporting-officer",
        prepared_at=prepared_at,
        supersedes_package_digest=None,
    )


def submit(reporting, package, submitted_at):
    receipt = SubmissionReceiptEvidence(
        entity_id=package.entity_id,
        incident_id=package.incident_id,
        report_type=package.report_type,
        sequence=package.sequence,
        package_digest=package.evidence_digest,
        submitted_at=submitted_at,
        channel=SubmissionChannel.PORTAL,
        external_submission_evidence_digest=digest(f"submission-{package.report_type.value}-{package.sequence}"),
        authority_reference=f"AUTH-{package.report_type.value}-{package.sequence}",
        technical_impossibility_evidence_digest=None,
    )
    reporting.register_receipt(receipt)
    return receipt


def build_complete_reporting_dossier():
    inventory, incidents, incident, policy, review, reporting, applicability, route = reporting_fixture()
    initial = report_package(
        IncidentReportType.INITIAL,
        1,
        review,
        applicability,
        route,
        prepared_at=1_800_003_620,
    )
    reporting.register_package(initial, decision=applicability, review=review, route=route)
    initial_receipt = submit(reporting, initial, 1_800_004_000)

    intermediate = report_package(
        IncidentReportType.INTERMEDIATE,
        1,
        review,
        applicability,
        route,
        prepared_at=initial_receipt.submitted_at + 100,
    )
    reporting.register_package(intermediate, decision=applicability, review=review, route=route)
    intermediate_receipt = submit(reporting, intermediate, initial_receipt.submitted_at + 3600)

    final = report_package(
        IncidentReportType.FINAL,
        1,
        review,
        applicability,
        route,
        prepared_at=intermediate_receipt.submitted_at + 100,
    )
    reporting.register_package(final, decision=applicability, review=review, route=route)
    final_receipt = submit(reporting, final, intermediate_receipt.submitted_at + 10 * 24 * 3600)

    assessment = assess_reporting_workflow(
        reporting,
        decision=applicability,
        review=review,
        route=route,
        assessed_at=final_receipt.submitted_at + 1,
    )
    assert assessment.state is ReportingWorkflowState.COMPLETE

    builder = GovernanceDossierBuilder(
        inventory,
        entity_id="bank-a",
        generated_at=assessment.assessed_at + 100,
        source_revision="v0.3-contract-under-current-release",
    )
    builder.add_incident(incidents, incident.incident_id, policy, review)
    builder.add_incident_reporting(
        reporting,
        decision=applicability,
        review=review,
        route=route,
        assessment=assessment,
    )
    return reporting, assessment, builder.build()


def test_complete_reporting_workflow_is_packaged_with_full_audit_history_and_verified_offline():
    reporting, assessment, dossier = build_complete_reporting_dossier()
    assert dossier.release_version == doraops.RELEASE_VERSION == doraops.__version__
    assert dossier.state is DossierState.CURRENT
    assert dossier.coverage["incident_reporting"] >= 8
    assert len(package_history(reporting, "bank-a", "INC-DOSSIER-1")) == 3
    assert len(submission_receipts(reporting, "bank-a", "INC-DOSSIER-1")) == 3
    assert assessment.authority_acceptance_determined is False
    document = dossier_document(dossier)
    assert verify_dossier_document(document) == document["dossier_digest"]


def test_rehashed_reporting_deadline_tamper_fails_semantic_offline_verification():
    _, _, dossier = build_complete_reporting_dossier()
    document = deepcopy(dossier_document(dossier))
    assessment = next(
        item
        for item in document["dossier"]["artifacts"]
        if item["domain"] == "incident_reporting" and item["artifact_type"] == "workflow_assessment"
    )
    initial = next(
        item
        for item in assessment["payload"]["deadlines"]
        if item["report_type"] == "initial_notification"
    )
    initial["statutory_due_at"] += 60
    initial["effective_due_at"] += 60
    assessment["digest"] = sha256_digest(assessment["payload"])
    document["dossier_digest"] = sha256_digest(document["dossier"])
    with pytest.raises(GovernanceError, match="initial deadline is inconsistent"):
        verify_dossier_document(document)


def test_public_registry_rejects_applicability_identity_switch_across_versions():
    _, incidents, incident, _policy, review, reporting, first, _route = reporting_fixture()
    second = ReportingApplicabilityDecision(
        entity_id="bank-a",
        incident_id=incident.incident_id,
        decision_id="different-decision-id",
        decision_version=2,
        incident_evidence_snapshot_digest=incidents.evidence_snapshot_digest("bank-a", incident.incident_id),
        classification_review_digest=review.evidence_digest,
        applicability=ReportingApplicability.APPLICABLE,
        decision_owner_id="legal-risk-owner",
        rationale_digest=digest("rationale-v2"),
        applicability_evidence_digest=digest("evidence-v2"),
        decided_at=first.decided_at + 100,
    )
    with pytest.raises(GovernanceError, match="decision_id must remain stable"):
        reporting.register_applicability(second, review)
