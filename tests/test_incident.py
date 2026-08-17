from dataclasses import replace

import pytest

from doraops import (
    BusinessFunction,
    ClientTransactionImpact,
    DataLossImpact,
    FinancialEntity,
    FunctionClassification,
    GovernanceError,
    ICTService,
    IncidentEvent,
    IncidentEventType,
    IncidentImpactSnapshot,
    IncidentRecord,
    IncidentTimeline,
    InventoryRegistry,
    MaterialityThreshold,
    NodeKind,
    NodeRef,
    ReputationalImpact,
    append_incident_event,
    assert_incident_classification_current,
    classify_incident,
)


D1 = "1" * 64
D2 = "2" * 64
D3 = "3" * 64


def registry(*, critical: bool = True) -> InventoryRegistry:
    value = InventoryRegistry()
    value.register_entity(FinancialEntity("bank-a", "Bank A", "TR"))
    value.register_node(
        BusinessFunction(
            "bank-a",
            "payments",
            "Payment Processing",
            (
                FunctionClassification.CRITICAL_OR_IMPORTANT
                if critical
                else FunctionClassification.STANDARD
            ),
            "operational-risk",
            "Material customer impact" if critical else "Standard support function",
        )
    )
    value.register_node(
        ICTService(
            "bank-a",
            "payments-api",
            "Payments API",
            "platform-owner",
            "application_service",
        )
    )
    return value


def incident(*, detected_at: int = 1_000_000) -> IncidentRecord:
    return IncidentRecord(
        entity_id="bank-a",
        incident_id="INC-001",
        title="Payments outage",
        detected_at=detected_at,
        occurred_at=detected_at - 300,
        affected_nodes=(
            NodeRef("bank-a", NodeKind.BUSINESS_FUNCTION, "payments"),
            NodeRef("bank-a", NodeKind.ICT_SERVICE, "payments-api"),
        ),
        apparent_root_cause="network-control-failure",
    )


def impact(
    *,
    clients: ClientTransactionImpact | None = None,
    reputation: ReputationalImpact | None = None,
    data_loss: DataLossImpact | None = None,
    duration_minutes: int = 0,
    downtime_minutes: int = 0,
    states: tuple[str, ...] = (),
    economic_eur: int = 0,
    supervised_service: bool = False,
    malicious_access: bool = False,
) -> IncidentImpactSnapshot:
    return IncidentImpactSnapshot(
        clients_transactions=clients or ClientTransactionImpact(),
        reputation=reputation or ReputationalImpact(),
        data_loss=data_loss or DataLossImpact(),
        duration_minutes=duration_minutes,
        critical_function_service_downtime_minutes=downtime_minutes,
        impacted_member_states=states,
        economic_costs_and_losses_eur=economic_eur,
        authorised_registered_or_supervised_financial_service_affected=supervised_service,
        successful_malicious_unauthorised_access=malicious_access,
    )


def test_incident_timeline_is_append_only_hash_chained() -> None:
    timeline = IncidentTimeline("bank-a", "INC-001", ())
    timeline = append_incident_event(
        timeline,
        event_type=IncidentEventType.DETECTED,
        occurred_at=1_000_000,
        recorded_at=1_000_010,
        summary="Monitoring detected payment errors",
        evidence_digest=D1,
    )
    timeline = append_incident_event(
        timeline,
        event_type=IncidentEventType.CONTAINED,
        occurred_at=1_000_300,
        recorded_at=1_000_320,
        summary="Traffic isolated from failed dependency",
        evidence_digest=D2,
    )
    assert timeline.events[1].previous_event_digest == timeline.events[0].chain_digest
    assert len(timeline.evidence_digest) == 64


def test_broken_timeline_chain_is_rejected() -> None:
    first = IncidentEvent(
        "bank-a",
        "INC-001",
        0,
        IncidentEventType.DETECTED,
        100,
        110,
        "Detected",
        D1,
    )
    second = IncidentEvent(
        "bank-a",
        "INC-001",
        1,
        IncidentEventType.UPDATED,
        120,
        130,
        "Updated",
        D2,
        previous_event_digest=D3,
    )
    with pytest.raises(GovernanceError, match="chain is broken"):
        IncidentTimeline("bank-a", "INC-001", (first, second))


def test_two_materiality_thresholds_plus_critical_function_classifies_major() -> None:
    clients = ClientTransactionImpact(
        affected_clients=11_000,
        total_clients_using_service=100_000,
    )
    classification = classify_incident(
        registry(),
        incident(),
        impact(clients=clients, duration_minutes=24 * 60 + 1),
        classified_at=1_000_100,
    )
    assert classification.critical_services_affected is True
    assert classification.major_incident is True
    assert set(classification.materiality_thresholds) == {
        MaterialityThreshold.CLIENTS_COUNTERPARTIES_TRANSACTIONS,
        MaterialityThreshold.DURATION_OR_DOWNTIME,
    }


def test_client_percentage_threshold_is_strictly_higher_than_ten_percent() -> None:
    clients = ClientTransactionImpact(
        affected_clients=10_000,
        total_clients_using_service=100_000,
    )
    classification = classify_incident(
        registry(),
        incident(),
        impact(clients=clients),
        classified_at=1_000_100,
    )
    assert MaterialityThreshold.CLIENTS_COUNTERPARTIES_TRANSACTIONS not in classification.materiality_thresholds


def test_absolute_client_threshold_is_strictly_higher_than_100000() -> None:
    clients = ClientTransactionImpact(
        affected_clients=100_001,
        total_clients_using_service=2_000_000,
    )
    classification = classify_incident(
        registry(),
        incident(),
        impact(clients=clients),
        classified_at=1_000_100,
    )
    assert MaterialityThreshold.CLIENTS_COUNTERPARTIES_TRANSACTIONS in classification.materiality_thresholds


def test_critical_function_downtime_threshold_is_strictly_over_two_hours() -> None:
    at_two_hours = classify_incident(
        registry(),
        incident(),
        impact(downtime_minutes=120),
        classified_at=1_000_100,
    )
    over_two_hours = classify_incident(
        registry(),
        incident(),
        impact(downtime_minutes=121),
        classified_at=1_000_100,
    )
    assert MaterialityThreshold.DURATION_OR_DOWNTIME not in at_two_hours.materiality_thresholds
    assert MaterialityThreshold.DURATION_OR_DOWNTIME in over_two_hours.materiality_thresholds


def test_two_hour_service_downtime_does_not_apply_without_critical_function() -> None:
    classification = classify_incident(
        registry(critical=False),
        incident(),
        impact(downtime_minutes=500),
        classified_at=1_000_100,
    )
    assert MaterialityThreshold.DURATION_OR_DOWNTIME not in classification.materiality_thresholds


def test_two_member_states_meets_geographical_threshold() -> None:
    classification = classify_incident(
        registry(),
        incident(),
        impact(states=("DE", "FR")),
        classified_at=1_000_100,
    )
    assert MaterialityThreshold.GEOGRAPHICAL_SPREAD in classification.materiality_thresholds


def test_economic_threshold_is_strictly_above_100000_eur() -> None:
    exact = classify_incident(
        registry(),
        incident(),
        impact(economic_eur=100_000),
        classified_at=1_000_100,
    )
    above = classify_incident(
        registry(),
        incident(),
        impact(economic_eur=100_001),
        classified_at=1_000_100,
    )
    assert MaterialityThreshold.ECONOMIC_IMPACT not in exact.materiality_thresholds
    assert MaterialityThreshold.ECONOMIC_IMPACT in above.materiality_thresholds


def test_successful_malicious_access_with_potential_data_loss_is_direct_major_trigger() -> None:
    classification = classify_incident(
        registry(critical=False),
        incident(),
        impact(
            malicious_access=True,
            data_loss=DataLossImpact(
                confidentiality_impacted=True,
                successful_malicious_unauthorised_access_with_potential_data_loss=True,
            ),
        ),
        classified_at=1_000_100,
    )
    assert classification.critical_services_affected is True
    assert classification.direct_malicious_access_trigger is True
    assert classification.major_incident is True
    assert classification.materiality_thresholds == (MaterialityThreshold.DATA_LOSS,)


def test_malicious_access_without_potential_data_loss_is_not_direct_trigger() -> None:
    classification = classify_incident(
        registry(critical=False),
        incident(),
        impact(malicious_access=True),
        classified_at=1_000_100,
    )
    assert classification.critical_services_affected is True
    assert classification.direct_malicious_access_trigger is False
    assert classification.major_incident is False


def test_potential_data_loss_flag_requires_successful_malicious_access() -> None:
    with pytest.raises(GovernanceError, match="requires successful_malicious"):
        impact(
            data_loss=DataLossImpact(
                successful_malicious_unauthorised_access_with_potential_data_loss=True,
            ),
            malicious_access=False,
        )


def test_reputational_threshold_uses_any_rts_indicator() -> None:
    classification = classify_incident(
        registry(),
        incident(),
        impact(reputation=ReputationalImpact(reflected_in_media=True)),
        classified_at=1_000_100,
    )
    assert MaterialityThreshold.REPUTATIONAL_IMPACT in classification.materiality_thresholds


def test_initial_notification_deadline_is_four_hours_after_classification_with_24_hour_cap() -> None:
    detected = 1_000_000
    major_impact = impact(
        reputation=ReputationalImpact(reflected_in_media=True),
        duration_minutes=24 * 60 + 1,
    )
    early = classify_incident(
        registry(),
        incident(detected_at=detected),
        major_impact,
        classified_at=detected + 2 * 3600,
    )
    near_cap = classify_incident(
        registry(),
        incident(detected_at=detected),
        major_impact,
        classified_at=detected + 23 * 3600,
    )
    late = classify_incident(
        registry(),
        incident(detected_at=detected),
        major_impact,
        classified_at=detected + 30 * 3600,
    )
    assert early.initial_notification_due_at == detected + 6 * 3600
    assert near_cap.initial_notification_due_at == detected + 24 * 3600
    assert late.initial_notification_due_at == detected + 34 * 3600


def test_inventory_change_invalidates_existing_incident_classification() -> None:
    inventory = registry()
    current_incident = incident()
    current_impact = impact(
        reputation=ReputationalImpact(reflected_in_media=True),
        duration_minutes=24 * 60 + 1,
    )
    classification = classify_incident(
        inventory,
        current_incident,
        current_impact,
        classified_at=1_000_100,
    )
    assert_incident_classification_current(
        classification,
        inventory,
        current_incident,
        current_impact,
    )
    inventory.register_node(
        ICTService(
            "bank-a",
            "new-dependency",
            "New Dependency",
            "platform-owner",
            "infrastructure_service",
        )
    )
    with pytest.raises(GovernanceError, match="stale for current inventory"):
        assert_incident_classification_current(
            classification,
            inventory,
            current_incident,
            current_impact,
        )


def test_impact_change_invalidates_existing_incident_classification() -> None:
    inventory = registry()
    current_incident = incident()
    current_impact = impact(duration_minutes=10)
    classification = classify_incident(
        inventory,
        current_incident,
        current_impact,
        classified_at=1_000_100,
    )
    changed = replace(current_impact, duration_minutes=20)
    with pytest.raises(GovernanceError, match="stale for current impact"):
        assert_incident_classification_current(
            classification,
            inventory,
            current_incident,
            changed,
        )
