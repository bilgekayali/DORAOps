from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone

import pytest

from doraops import (
    BusinessFunction,
    FinancialEntity,
    FunctionClassification,
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
    IncidentRegistry,
    InventoryRegistry,
    NodeKind,
    NodeRef,
    assess_classification_readiness,
    review_incident_classification,
    sha256_digest,
)
from doraops.reporting import (
    AcknowledgementStatus,
    AuthorityAcknowledgementEvidence,
    DeadlineAdjustmentEvidence,
    DeadlineBasis,
    DelayNotificationEvidence,
    IncidentReportPackage,
    IncidentReportType,
    IncidentReportingRegistry,
    IncidentReportingRoute,
    ITS_TEMPLATE_PROFILE,
    ReportingApplicability,
    ReportingApplicabilityDecision,
    ReportingWorkflowState,
    RTS_CONTENT_PROFILE,
    SubmissionChannel,
    SubmissionMode,
    SubmissionReceiptEvidence,
    assess_reporting_workflow,
)


def digest(seed: str) -> str:
    return sha256_digest({"seed": seed})


def fixture(*, detected_at: int = 1_800_000_000):
    inventory = InventoryRegistry()
    inventory.register_entity(FinancialEntity("bank-a", "Bank A", "DE"))
    function = BusinessFunction(
        "bank-a",
        "payments",
        "Payments",
        FunctionClassification.CRITICAL_OR_IMPORTANT,
        "board-owner",
        "human criticality decision",
    )
    service = ICTService("bank-a", "payment-api", "Payment API", "svc-owner", "application")
    inventory.register_node(function)
    inventory.register_node(service)
    refs = (
        NodeRef("bank-a", NodeKind.BUSINESS_FUNCTION, "payments"),
        NodeRef("bank-a", NodeKind.ICT_SERVICE, "payment-api"),
    )
    incident = ICTIncident(
        entity_id="bank-a",
        incident_id="INC-REPORT-1",
        title="Payment interruption",
        incident_owner_id="incident-manager",
        occurred_at=detected_at - 60,
        detected_at=detected_at,
        inventory_snapshot_digest=inventory.snapshot_digest("bank-a"),
        affected_nodes=refs,
    )
    incidents = IncidentRegistry(inventory)
    incidents.register_incident(incident)
    incidents.register_impact(
        IncidentImpactObservation(
            entity_id="bank-a",
            incident_id=incident.incident_id,
            impact_id="impact-1",
            dimension=ImpactDimension.SERVICE_AVAILABILITY,
            severity=ImpactSeverity.SEVERE,
            observed_at=detected_at + 60,
            affected_nodes=(refs[1],),
            summary="Payment API unavailable",
            evidence_digest=digest("impact"),
        )
    )
    return inventory, incidents, incident


def append_event(incidents, incident, *, sequence, event_type, at, related=None):
    item = IncidentEvent(
        entity_id=incident.entity_id,
        incident_id=incident.incident_id,
        event_id=f"event-{sequence}",
        sequence=sequence,
        event_type=event_type,
        occurred_at=at,
        recorded_at=at + 1,
        actor_id="operator",
        summary=f"{event_type.value} evidence",
        evidence_digest=digest(f"event-{sequence}"),
        related_reference=related,
    )
    incidents.append_event(item)
    return item


def classification_policy():
    return IncidentClassificationPolicy(
        entity_id="bank-a",
        policy_id="incident-policy",
        version="1",
        required_impact_dimensions=(ImpactDimension.SERVICE_AVAILABILITY,),
        require_recovery_event=False,
        require_root_cause_reference=False,
        require_remediation_reference=False,
        require_notification_decision=True,
    )


def build_review(incidents, incident, *, decision, reviewed_at):
    existing = incidents.events("bank-a", incident.incident_id)
    if IncidentEventType.NOTIFICATION_DECISION not in {item.event_type for item in existing}:
        append_event(
            incidents,
            incident,
            sequence=len(existing) + 1,
            event_type=IncidentEventType.NOTIFICATION_DECISION,
            at=incident.detected_at + 120,
            related="NOTIFY-DECISION-1",
        )
    readiness = assess_classification_readiness(
        incidents,
        "bank-a",
        incident.incident_id,
        classification_policy(),
    )
    return review_incident_classification(
        incidents,
        readiness,
        classification_policy(),
        reviewer_id="incident-classifier",
        decision=decision,
        rationale="accountable human classification",
        reviewed_at=reviewed_at,
    )


def applicability(incidents, review, *, version=1, decided_at=None, state=ReportingApplicability.APPLICABLE):
    return ReportingApplicabilityDecision(
        entity_id="bank-a",
        incident_id="INC-REPORT-1",
        decision_id="dora-reporting-applicability",
        decision_version=version,
        incident_evidence_snapshot_digest=incidents.evidence_snapshot_digest("bank-a", "INC-REPORT-1"),
        classification_review_digest=review.evidence_digest,
        applicability=state,
        decision_owner_id="legal-risk-owner",
        rationale_digest=digest(f"applicability-rationale-{version}"),
        applicability_evidence_digest=digest(f"applicability-evidence-{version}"),
        decided_at=review.reviewed_at + 10 if decided_at is None else decided_at,
    )


def direct_route(*, version=1, registered_at=1_800_000_000):
    return IncidentReportingRoute(
        entity_id="bank-a",
        route_id="primary-authority-route",
        version=version,
        competent_authority_id="DE-NCA",
        member_state="DE",
        submission_mode=SubmissionMode.DIRECT,
        submitter_id="bank-a",
        contact_evidence_digest=digest(f"authority-contact-{version}"),
        outsourcing_evidence_digest=None,
        authority_permission_evidence_digest=None,
        aggregation_scope_evidence_digest=None,
        registered_at=registered_at,
    )


def package(kind, sequence, review, decision, route, *, prepared_at, revision=1, supersedes=None):
    return IncidentReportPackage(
        entity_id="bank-a",
        incident_id="INC-REPORT-1",
        report_type=kind,
        sequence=sequence,
        revision=revision,
        incident_evidence_snapshot_digest=decision.incident_evidence_snapshot_digest,
        classification_review_digest=review.evidence_digest,
        applicability_decision_digest=decision.evidence_digest,
        route_digest=route.evidence_digest,
        rts_content_profile=RTS_CONTENT_PROFILE,
        its_template_profile=ITS_TEMPLATE_PROFILE,
        required_content_evidence_digest=digest(f"required-{kind.value}-{sequence}-{revision}"),
        report_payload_digest=digest(f"payload-{kind.value}-{sequence}-{revision}"),
        prepared_by_id="incident-reporting-officer",
        prepared_at=prepared_at,
        supersedes_package_digest=supersedes,
    )


def receipt(pkg, submitted_at, *, channel=SubmissionChannel.PORTAL, technical=None):
    return SubmissionReceiptEvidence(
        entity_id=pkg.entity_id,
        incident_id=pkg.incident_id,
        report_type=pkg.report_type,
        sequence=pkg.sequence,
        package_digest=pkg.evidence_digest,
        submitted_at=submitted_at,
        channel=channel,
        external_submission_evidence_digest=digest(f"submission-{pkg.evidence_digest}"),
        authority_reference=f"AUTH-{pkg.report_type.value}-{pkg.sequence}",
        technical_impossibility_evidence_digest=technical,
    )


def setup_major(*, detected_at=1_800_000_000, reviewed_at=None):
    _, incidents, incident = fixture(detected_at=detected_at)
    if reviewed_at is None:
        reviewed_at = detected_at + 3600
    review = build_review(
        incidents,
        incident,
        decision=HumanClassificationDecision.MAJOR,
        reviewed_at=reviewed_at,
    )
    reporting = IncidentReportingRegistry(incidents)
    decision = applicability(incidents, review)
    reporting.register_applicability(decision, review)
    route = direct_route(registered_at=detected_at - 100)
    reporting.register_route(route)
    return incidents, incident, review, reporting, decision, route


def test_initial_deadline_uses_24_hour_cap_when_classification_is_late_but_within_24_hours():
    detected = 1_800_000_000
    incidents, incident, review, reporting, decision, route = setup_major(
        detected_at=detected,
        reviewed_at=detected + 23 * 3600,
    )
    assessment = assess_reporting_workflow(
        reporting,
        decision=decision,
        review=review,
        route=route,
        assessed_at=detected + 23 * 3600 + 60,
    )
    deadline = assessment.deadlines[0]
    assert deadline.basis is DeadlineBasis.INITIAL_AWARENESS_24H
    assert deadline.statutory_due_at == detected + 24 * 3600
    assert assessment.state is ReportingWorkflowState.PENDING


def test_initial_deadline_is_four_hours_from_late_classification_after_24_hours():
    detected = 1_800_000_000
    _, _, review, reporting, decision, route = setup_major(
        detected_at=detected,
        reviewed_at=detected + 25 * 3600,
    )
    assessment = assess_reporting_workflow(
        reporting,
        decision=decision,
        review=review,
        route=route,
        assessed_at=review.reviewed_at + 60,
    )
    deadline = assessment.deadlines[0]
    assert deadline.basis is DeadlineBasis.INITIAL_CLASSIFICATION_4H
    assert deadline.statutory_due_at == review.reviewed_at + 4 * 3600


def test_full_initial_intermediate_final_workflow_completes_and_uses_calendar_month():
    detected = int(datetime(2027, 1, 30, 10, tzinfo=timezone.utc).timestamp())
    _, _, review, reporting, decision, route = setup_major(detected_at=detected)

    initial = package(
        IncidentReportType.INITIAL,
        1,
        review,
        decision,
        route,
        prepared_at=review.reviewed_at + 20,
    )
    reporting.register_package(initial, decision=decision, review=review, route=route)
    initial_receipt = receipt(initial, review.reviewed_at + 1800)
    reporting.register_receipt(initial_receipt)

    intermediate = package(
        IncidentReportType.INTERMEDIATE,
        1,
        review,
        decision,
        route,
        prepared_at=initial_receipt.submitted_at + 100,
    )
    reporting.register_package(intermediate, decision=decision, review=review, route=route)
    intermediate_receipt = receipt(intermediate, initial_receipt.submitted_at + 24 * 3600)
    reporting.register_receipt(intermediate_receipt)

    final = package(
        IncidentReportType.FINAL,
        1,
        review,
        decision,
        route,
        prepared_at=intermediate_receipt.submitted_at + 100,
    )
    reporting.register_package(final, decision=decision, review=review, route=route)
    final_receipt = receipt(final, int(datetime(2027, 2, 27, 10, tzinfo=timezone.utc).timestamp()))
    reporting.register_receipt(final_receipt)

    assessment = assess_reporting_workflow(
        reporting,
        decision=decision,
        review=review,
        route=route,
        assessed_at=final_receipt.submitted_at + 1,
    )
    assert assessment.state is ReportingWorkflowState.COMPLETE
    final_deadline = next(item for item in assessment.deadlines if item.report_type is IncidentReportType.FINAL)
    expected = datetime.fromtimestamp(intermediate_receipt.submitted_at, tz=timezone.utc).replace(month=2)
    assert final_deadline.statutory_due_at == int(expected.timestamp())
    assert assessment.findings == ()


def test_late_report_with_timely_delay_notice_remains_breached():
    _, _, review, reporting, decision, route = setup_major()
    preview = assess_reporting_workflow(
        reporting,
        decision=decision,
        review=review,
        route=route,
        assessed_at=review.reviewed_at + 1,
    )
    due = preview.deadlines[0].effective_due_at
    assert due is not None
    reporting.register_delay_notification(
        DelayNotificationEvidence(
            entity_id="bank-a",
            incident_id="INC-REPORT-1",
            report_type=IncidentReportType.INITIAL,
            sequence=1,
            due_at=due,
            notified_at=due - 60,
            reason_evidence_digest=digest("delay-reason"),
            authority_notification_evidence_digest=digest("delay-authority-notice"),
        )
    )
    initial = package(
        IncidentReportType.INITIAL,
        1,
        review,
        decision,
        route,
        prepared_at=review.reviewed_at + 20,
    )
    reporting.register_package(initial, decision=decision, review=review, route=route)
    reporting.register_receipt(receipt(initial, due + 1))
    assessment = assess_reporting_workflow(
        reporting,
        decision=decision,
        review=review,
        route=route,
        assessed_at=due + 2,
    )
    assert assessment.state is ReportingWorkflowState.BREACHED
    assert any("deadline_breached_with_timely_delay_notice" in item for item in assessment.findings)


def test_weekend_or_bank_holiday_adjustment_changes_effective_not_statutory_deadline():
    _, _, review, reporting, decision, route = setup_major()
    preview = assess_reporting_workflow(
        reporting,
        decision=decision,
        review=review,
        route=route,
        assessed_at=review.reviewed_at + 1,
    )
    original = preview.deadlines[0].statutory_due_at
    assert original is not None
    adjustment = DeadlineAdjustmentEvidence(
        entity_id="bank-a",
        incident_id="INC-REPORT-1",
        report_type=IncidentReportType.INITIAL,
        sequence=1,
        original_due_at=original,
        adjusted_due_at=original + 36 * 3600,
        reason="weekend_or_bank_holiday",
        approved_by_id="reporting-calendar-owner",
        calendar_evidence_digest=digest("bank-holiday-calendar"),
    )
    reporting.register_deadline_adjustment(adjustment)
    assessment = assess_reporting_workflow(
        reporting,
        decision=decision,
        review=review,
        route=route,
        assessed_at=original + 1,
    )
    deadline = assessment.deadlines[0]
    assert deadline.statutory_due_at == original
    assert deadline.effective_due_at == adjustment.adjusted_due_at
    assert deadline.adjustment_digest == adjustment.evidence_digest
    assert assessment.state is ReportingWorkflowState.PENDING


def test_alternative_submission_requires_technical_impossibility_evidence():
    _, _, review, reporting, decision, route = setup_major()
    initial = package(
        IncidentReportType.INITIAL,
        1,
        review,
        decision,
        route,
        prepared_at=review.reviewed_at + 20,
    )
    reporting.register_package(initial, decision=decision, review=review, route=route)
    with pytest.raises(GovernanceError, match="technical-impossibility"):
        receipt(initial, review.reviewed_at + 100, channel=SubmissionChannel.ALTERNATIVE)
    valid = receipt(
        initial,
        review.reviewed_at + 100,
        channel=SubmissionChannel.ALTERNATIVE,
        technical=digest("technical-impossibility"),
    )
    reporting.register_receipt(valid)


def test_aggregated_route_requires_outsourcing_permission_and_scope_evidence():
    with pytest.raises(GovernanceError, match="outsourcing evidence"):
        IncidentReportingRoute(
            entity_id="bank-a",
            route_id="agg",
            version=1,
            competent_authority_id="DE-NCA",
            member_state="DE",
            submission_mode=SubmissionMode.AGGREGATED,
            submitter_id="provider-x",
            contact_evidence_digest=digest("contact"),
            outsourcing_evidence_digest=None,
            authority_permission_evidence_digest=digest("permission"),
            aggregation_scope_evidence_digest=digest("scope"),
            registered_at=100,
        )


def test_report_revisions_are_contiguous_and_bind_exact_previous_package():
    _, _, review, reporting, decision, route = setup_major()
    first = package(
        IncidentReportType.INITIAL,
        1,
        review,
        decision,
        route,
        prepared_at=review.reviewed_at + 20,
    )
    reporting.register_package(first, decision=decision, review=review, route=route)
    with pytest.raises(GovernanceError, match="supersede exact previous"):
        reporting.register_package(
            package(
                IncidentReportType.INITIAL,
                1,
                review,
                decision,
                route,
                prepared_at=review.reviewed_at + 30,
                revision=2,
                supersedes=digest("wrong"),
            ),
            decision=decision,
            review=review,
            route=route,
        )
    second = package(
        IncidentReportType.INITIAL,
        1,
        review,
        decision,
        route,
        prepared_at=review.reviewed_at + 40,
        revision=2,
        supersedes=first.evidence_digest,
    )
    reporting.register_package(second, decision=decision, review=review, route=route)
    assert reporting.package_revisions("bank-a", "INC-REPORT-1", IncidentReportType.INITIAL, 1) == (first, second)


def test_incident_evidence_drift_requires_revalidation():
    incidents, incident, review, reporting, decision, route = setup_major()
    append_event(
        incidents,
        incident,
        sequence=len(incidents.events("bank-a", incident.incident_id)) + 1,
        event_type=IncidentEventType.OTHER,
        at=review.reviewed_at + 100,
    )
    assessment = assess_reporting_workflow(
        reporting,
        decision=decision,
        review=review,
        route=route,
        assessed_at=review.reviewed_at + 200,
    )
    assert assessment.state is ReportingWorkflowState.REVALIDATION_REQUIRED
    assert any("stale" in item for item in assessment.findings)


def test_recovery_after_intermediate_requires_update_without_fabricated_numeric_deadline():
    incidents, incident, review1, reporting, decision1, route = setup_major()
    initial = package(IncidentReportType.INITIAL, 1, review1, decision1, route, prepared_at=review1.reviewed_at + 20)
    reporting.register_package(initial, decision=decision1, review=review1, route=route)
    initial_receipt = receipt(initial, review1.reviewed_at + 100)
    reporting.register_receipt(initial_receipt)
    intermediate = package(
        IncidentReportType.INTERMEDIATE,
        1,
        review1,
        decision1,
        route,
        prepared_at=initial_receipt.submitted_at + 100,
    )
    reporting.register_package(intermediate, decision=decision1, review=review1, route=route)
    intermediate_receipt = receipt(intermediate, initial_receipt.submitted_at + 1000)
    reporting.register_receipt(intermediate_receipt)

    recovered_at = intermediate_receipt.submitted_at + 500
    append_event(
        incidents,
        incident,
        sequence=len(incidents.events("bank-a", incident.incident_id)) + 1,
        event_type=IncidentEventType.RECOVERED,
        at=recovered_at,
    )
    review2 = build_review(
        incidents,
        incident,
        decision=HumanClassificationDecision.MAJOR,
        reviewed_at=recovered_at + 100,
    )
    decision2 = applicability(incidents, review2, version=2)
    reporting.register_applicability(decision2, review2)

    assessment = assess_reporting_workflow(
        reporting,
        decision=decision2,
        review=review2,
        route=route,
        assessed_at=review2.reviewed_at + 1,
    )
    update = next(item for item in assessment.deadlines if item.basis is DeadlineBasis.RECOVERY_UPDATE_WITHOUT_UNDUE_DELAY)
    assert update.sequence == 2
    assert update.statutory_due_at is None
    assert update.effective_due_at is None
    assert assessment.state is ReportingWorkflowState.PENDING


def test_route_drift_fails_closed_and_authority_acknowledgement_never_becomes_supervisory_acceptance():
    _, _, review, reporting, decision, route1 = setup_major()
    initial = package(IncidentReportType.INITIAL, 1, review, decision, route1, prepared_at=review.reviewed_at + 20)
    reporting.register_package(initial, decision=decision, review=review, route=route1)
    submitted = receipt(initial, review.reviewed_at + 100)
    reporting.register_receipt(submitted)
    reporting.register_acknowledgement(
        AuthorityAcknowledgementEvidence(
            entity_id="bank-a",
            incident_id="INC-REPORT-1",
            receipt_digest=submitted.evidence_digest,
            status=AcknowledgementStatus.ACCEPTED,
            acknowledged_at=submitted.submitted_at + 10,
            authority_reference="AUTH-ACK-1",
            acknowledgement_evidence_digest=digest("ack"),
        )
    )
    route2 = direct_route(version=2, registered_at=route1.registered_at + 100)
    reporting.register_route(route2)
    assessment = assess_reporting_workflow(
        reporting,
        decision=decision,
        review=review,
        route=route1,
        assessed_at=submitted.submitted_at + 20,
    )
    assert assessment.state is ReportingWorkflowState.REVALIDATION_REQUIRED
    assert assessment.authority_acceptance_determined is False


def test_non_major_reclassification_after_prior_initial_submission_requires_notification_evidence():
    incidents, incident, review1, reporting, decision1, route = setup_major()
    initial = package(IncidentReportType.INITIAL, 1, review1, decision1, route, prepared_at=review1.reviewed_at + 20)
    reporting.register_package(initial, decision=decision1, review=review1, route=route)
    reporting.register_receipt(receipt(initial, review1.reviewed_at + 100))

    review2 = build_review(
        incidents,
        incident,
        decision=HumanClassificationDecision.NON_MAJOR,
        reviewed_at=review1.reviewed_at + 500,
    )
    decision2 = applicability(incidents, review2, version=2)
    reporting.register_applicability(decision2, review2)
    pending = assess_reporting_workflow(
        reporting,
        decision=decision2,
        review=review2,
        route=route,
        assessed_at=decision2.decided_at + 1,
    )
    assert pending.state is ReportingWorkflowState.PENDING
    assert pending.findings == ("reclassification_notification_pending",)

    reclassification = package(
        IncidentReportType.RECLASSIFICATION,
        1,
        review2,
        decision2,
        route,
        prepared_at=decision2.decided_at + 10,
    )
    reporting.register_package(reclassification, decision=decision2, review=review2, route=route)
    reporting.register_receipt(receipt(reclassification, reclassification.prepared_at + 10))
    complete = assess_reporting_workflow(
        reporting,
        decision=decision2,
        review=review2,
        route=route,
        assessed_at=reclassification.prepared_at + 20,
    )
    assert complete.state is ReportingWorkflowState.COMPLETE


def test_rejected_external_acknowledgement_is_a_reporting_gap_not_a_supervisory_conclusion():
    _, _, review, reporting, decision, route = setup_major()
    initial = package(IncidentReportType.INITIAL, 1, review, decision, route, prepared_at=review.reviewed_at + 20)
    reporting.register_package(initial, decision=decision, review=review, route=route)
    submitted = receipt(initial, review.reviewed_at + 100)
    reporting.register_receipt(submitted)
    reporting.register_acknowledgement(
        AuthorityAcknowledgementEvidence(
            entity_id="bank-a",
            incident_id="INC-REPORT-1",
            receipt_digest=submitted.evidence_digest,
            status=AcknowledgementStatus.REJECTED,
            acknowledged_at=submitted.submitted_at + 10,
            authority_reference="AUTH-REJECT-1",
            acknowledgement_evidence_digest=digest("reject"),
        )
    )
    assessment = assess_reporting_workflow(
        reporting,
        decision=decision,
        review=review,
        route=route,
        assessed_at=submitted.submitted_at + 20,
    )
    assert assessment.state is ReportingWorkflowState.BREACHED
    assert assessment.authority_acceptance_determined is False
    assert any("submission_acknowledgement:rejected" in item for item in assessment.findings)
