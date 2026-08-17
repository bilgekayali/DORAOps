import json
from pathlib import Path

import jsonschema

from doraops import (
    BusinessFunction,
    ClientTransactionImpact,
    DataLossImpact,
    FinancialEntity,
    FunctionClassification,
    ICTService,
    IncidentEventType,
    IncidentImpactSnapshot,
    IncidentRecord,
    IncidentTimeline,
    InventoryRegistry,
    NodeKind,
    NodeRef,
    ReputationalImpact,
    append_incident_event,
    canonical_json,
    classify_incident,
)


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "schemas" / "ict-incident.schema.json").read_text(encoding="utf-8"))


def payload(value) -> object:
    return json.loads(canonical_json(value))


def artifacts():
    registry = InventoryRegistry()
    registry.register_entity(FinancialEntity("bank-a", "Bank A", "TR"))
    registry.register_node(
        BusinessFunction(
            "bank-a",
            "payments",
            "Payment Processing",
            FunctionClassification.CRITICAL_OR_IMPORTANT,
            "operational-risk",
            "Material customer impact",
        )
    )
    registry.register_node(
        ICTService("bank-a", "payments-api", "Payments API", "platform-owner", "application_service")
    )
    incident = IncidentRecord(
        "bank-a",
        "INC-001",
        "Payments outage",
        1_000_000,
        (
            NodeRef("bank-a", NodeKind.BUSINESS_FUNCTION, "payments"),
            NodeRef("bank-a", NodeKind.ICT_SERVICE, "payments-api"),
        ),
        occurred_at=999_700,
        apparent_root_cause="network-control-failure",
    )
    timeline = IncidentTimeline("bank-a", "INC-001", ())
    timeline = append_incident_event(
        timeline,
        event_type=IncidentEventType.DETECTED,
        occurred_at=1_000_000,
        recorded_at=1_000_010,
        summary="Monitoring detected payment errors",
        evidence_digest="1" * 64,
    )
    impact = IncidentImpactSnapshot(
        clients_transactions=ClientTransactionImpact(
            affected_clients=11_000,
            total_clients_using_service=100_000,
        ),
        reputation=ReputationalImpact(reflected_in_media=True),
        data_loss=DataLossImpact(),
        duration_minutes=30,
        critical_function_service_downtime_minutes=10,
        impacted_member_states=("DE",),
        economic_costs_and_losses_eur=10_000,
    )
    classification = classify_incident(
        registry,
        incident,
        impact,
        classified_at=1_000_100,
    )
    return incident, timeline.events[0], timeline, impact, classification


def test_real_incident_artifacts_match_strict_schema() -> None:
    jsonschema.Draft202012Validator.check_schema(SCHEMA)
    for artifact in artifacts():
        jsonschema.validate(payload(artifact), SCHEMA)
