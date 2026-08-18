from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path

import jsonschema
import pytest

from doraops import (
    BusinessFunction,
    ClassificationReadinessState,
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
    canonical_json,
    review_incident_classification,
    sha256_digest,
)


def digest(seed: str) -> str:
    return sha256_digest({"seed": seed})


def inventory_fixture():
    registry = InventoryRegistry()
    registry.register_entity(FinancialEntity("bank-a", "Bank A", "DE"))
    function = BusinessFunction(
        "bank-a", "payments", "Payments", FunctionClassification.CRITICAL_OR_IMPORTANT,
        "board-owner", "human classification decision",
    )
    service = ICTService("bank-a", "payment-api", "Payment API", "svc-owner", "application")
    registry.register_node(function)
    registry.register_node(service)
    refs = (
        NodeRef("bank-a", NodeKind.BUSINESS_FUNCTION, "payments"),
        NodeRef("bank-a", NodeKind.ICT_SERVICE, "payment-api"),
    )
    return registry, refs


def incident_fixture():
    inventory, refs = inventory_fixture()
    incident = ICTIncident(
        entity_id="bank-a",
        incident_id="INC-2026-001",
        title="Payment API interruption",
        incident_owner_id="incident-manager",
        occurred_at=100,
        detected_at=110,
        inventory_snapshot_digest=inventory.snapshot_digest("bank-a"),
        affected_nodes=refs,
    )
    registry = IncidentRegistry(inventory)
    registry.register_incident(incident)
    return inventory, registry, incident, refs


def event(incident, sequence, event_type, when, *, related=None):
    return IncidentEvent(
        entity_id=incident.entity_id,
        incident_id=incident.incident_id,
        event_id=f"event-{sequence}",
        sequence=sequence,
        event_type=event_type,
        occurred_at=when,
        recorded_at=when + 1,
        actor_id="operator",
        summary=f"{event_type.value} evidence",
        evidence_digest=digest(f"event-{sequence}"),
        related_reference=related,
    )


def impact(incident, refs, impact_id="impact-1"):
    return IncidentImpactObservation(
        entity_id=incident.entity_id,
        incident_id=incident.incident_id,
        impact_id=impact_id,
        dimension=ImpactDimension.SERVICE_AVAILABILITY,
        severity=ImpactSeverity.SEVERE,
        observed_at=120,
        affected_nodes=(refs[1],),
        summary="Payment API unavailable",
        evidence_digest=digest(impact_id),
    )


def policy():
    return IncidentClassificationPolicy(
        entity_id="bank-a",
        policy_id="incident-policy",
        version="1",
        required_impact_dimensions=(ImpactDimension.SERVICE_AVAILABILITY,),
        require_recovery_event=True,
        require_root_cause_reference=True,
        require_remediation_reference=True,
        require_notification_decision=True,
    )


def test_incident_binds_exact_inventory_and_rejects_stale_or_dangling_scope():
    inventory, refs = inventory_fixture()
    registry = IncidentRegistry(inventory)
    stale = ICTIncident(
        "bank-a", "INC-1", "Incident", "owner", 100, 110, digest("wrong"), refs
    )
    with pytest.raises(GovernanceError, match="stale"):
        registry.register_incident(stale)

    dangling = ICTIncident(
        "bank-a", "INC-2", "Incident", "owner", 100, 110,
        inventory.snapshot_digest("bank-a"),
        (NodeRef("bank-a", NodeKind.ICT_SERVICE, "missing"),),
    )
    with pytest.raises(GovernanceError, match="unknown inventory node"):
        registry.register_incident(dangling)


def test_timeline_is_append_only_and_contiguous():
    _, registry, incident, _ = incident_fixture()
    first = event(incident, 1, IncidentEventType.DETECTED, 110)
    registry.append_event(first)
    assert registry.append_event(first) == first.governance_digest
    with pytest.raises(GovernanceError, match="different content"):
        registry.append_event(replace(first, summary="mutated"))
    with pytest.raises(GovernanceError, match="contiguous"):
        registry.append_event(event(incident, 3, IncidentEventType.CONTAINED, 130))


def test_incomplete_readiness_exposes_exact_missing_inputs():
    _, registry, incident, refs = incident_fixture()
    registry.append_event(event(incident, 1, IncidentEventType.DETECTED, 110))
    registry.register_impact(impact(incident, refs))
    readiness = assess_classification_readiness(registry, "bank-a", incident.incident_id, policy())
    assert readiness.state is ClassificationReadinessState.INCOMPLETE
    assert readiness.missing_inputs == (
        "notification_decision",
        "recovery_event",
        "remediation_reference",
        "root_cause_reference",
    )
    with pytest.raises(GovernanceError, match="incomplete"):
        review_incident_classification(
            registry, readiness, policy(), reviewer_id="reviewer", decision=HumanClassificationDecision.MAJOR,
            rationale="human assessment", reviewed_at=200,
        )


def test_ready_evidence_supports_human_review_without_auto_classification():
    _, registry, incident, refs = incident_fixture()
    registry.append_event(event(incident, 1, IncidentEventType.DETECTED, 110))
    registry.append_event(event(incident, 2, IncidentEventType.RECOVERED, 150))
    registry.append_event(event(incident, 3, IncidentEventType.ROOT_CAUSE_IDENTIFIED, 160, related="RCA-1"))
    registry.append_event(event(incident, 4, IncidentEventType.REMEDIATION_LINKED, 170, related="REM-1"))
    registry.append_event(event(incident, 5, IncidentEventType.NOTIFICATION_DECISION, 175, related="NOTIFY-DEC-1"))
    registry.register_impact(impact(incident, refs))
    readiness = assess_classification_readiness(registry, "bank-a", incident.incident_id, policy())
    assert readiness.state is ClassificationReadinessState.READY_FOR_HUMAN_REVIEW
    assert readiness.missing_inputs == ()
    review = review_incident_classification(
        registry, readiness, policy(), reviewer_id="risk-officer",
        decision=HumanClassificationDecision.UNDETERMINED,
        rationale="Evidence complete; legal classification requires accountable review.", reviewed_at=200,
    )
    assert review.decision is HumanClassificationDecision.UNDETERMINED
    assert review.incident_evidence_snapshot_digest == readiness.incident_evidence_snapshot_digest


def test_review_fails_closed_when_readiness_snapshot_becomes_stale():
    _, registry, incident, refs = incident_fixture()
    registry.append_event(event(incident, 1, IncidentEventType.RECOVERED, 150))
    registry.append_event(event(incident, 2, IncidentEventType.ROOT_CAUSE_IDENTIFIED, 160, related="RCA-1"))
    registry.append_event(event(incident, 3, IncidentEventType.REMEDIATION_LINKED, 170, related="REM-1"))
    registry.append_event(event(incident, 4, IncidentEventType.NOTIFICATION_DECISION, 175, related="NOTIFY-1"))
    registry.register_impact(impact(incident, refs))
    readiness = assess_classification_readiness(registry, "bank-a", incident.incident_id, policy())
    registry.append_event(event(incident, 5, IncidentEventType.OTHER, 180))
    with pytest.raises(GovernanceError, match="stale for current incident evidence"):
        review_incident_classification(
            registry, readiness, policy(), reviewer_id="reviewer",
            decision=HumanClassificationDecision.NON_MAJOR, rationale="human decision", reviewed_at=200,
        )


def test_incident_artifacts_validate_against_release_schemas():
    _, registry, incident, refs = incident_fixture()
    recovered = event(incident, 1, IncidentEventType.RECOVERED, 150)
    root = event(incident, 2, IncidentEventType.ROOT_CAUSE_IDENTIFIED, 160, related="RCA-1")
    remediation = event(incident, 3, IncidentEventType.REMEDIATION_LINKED, 170, related="REM-1")
    notification = event(incident, 4, IncidentEventType.NOTIFICATION_DECISION, 175, related="NOTIFY-1")
    for item in (recovered, root, remediation, notification):
        registry.append_event(item)
    impact_item = impact(incident, refs)
    registry.register_impact(impact_item)
    readiness = assess_classification_readiness(registry, "bank-a", incident.incident_id, policy())
    review = review_incident_classification(
        registry, readiness, policy(), reviewer_id="reviewer",
        decision=HumanClassificationDecision.MAJOR, rationale="human-reviewed classification", reviewed_at=200,
    )

    root_path = Path(__file__).resolve().parents[1]
    cases = (
        ("ict-incident.schema.json", incident),
        ("incident-event.schema.json", recovered),
        ("incident-impact.schema.json", impact_item),
        ("incident-classification-readiness.schema.json", readiness),
        ("incident-classification-review.schema.json", review),
    )
    for schema_name, artifact in cases:
        schema = json.loads((root_path / "schemas" / schema_name).read_text())
        payload = json.loads(canonical_json(artifact))
        jsonschema.Draft202012Validator(schema).validate(payload)
