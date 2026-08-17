from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .canonical import sha256_digest
from .inventory import (
    BusinessFunction,
    FunctionClassification,
    GovernanceError,
    InventoryRegistry,
    NodeKind,
    NodeRef,
)


SECONDS_PER_HOUR = 3600


class IncidentEventType(str, Enum):
    OCCURRED = "occurred"
    DETECTED = "detected"
    UPDATED = "updated"
    CONTAINED = "contained"
    RECOVERED = "recovered"
    ROOT_CAUSE_IDENTIFIED = "root_cause_identified"
    RESOLVED = "resolved"


class MaterialityThreshold(str, Enum):
    CLIENTS_COUNTERPARTIES_TRANSACTIONS = "clients_counterparties_transactions"
    REPUTATIONAL_IMPACT = "reputational_impact"
    DURATION_OR_DOWNTIME = "duration_or_downtime"
    GEOGRAPHICAL_SPREAD = "geographical_spread"
    DATA_LOSS = "data_loss"
    ECONOMIC_IMPACT = "economic_impact"


def _text(name: str, value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise GovernanceError(f"{name} must be a non-empty string")
    return value.strip()


def _digest(name: str, value: str) -> str:
    if len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
        raise GovernanceError(f"{name} must be a lowercase SHA-256 digest")
    return value


def _nonnegative(name: str, value: int) -> int:
    if not isinstance(value, int) or value < 0:
        raise GovernanceError(f"{name} must be a non-negative integer")
    return value


@dataclass(frozen=True, slots=True)
class IncidentRecord:
    entity_id: str
    incident_id: str
    title: str
    detected_at: int
    affected_nodes: tuple[NodeRef, ...]
    occurred_at: int | None = None
    apparent_root_cause: str | None = None

    def __post_init__(self) -> None:
        for name in ("entity_id", "incident_id", "title"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        _nonnegative("detected_at", self.detected_at)
        if self.occurred_at is not None:
            _nonnegative("occurred_at", self.occurred_at)
            if self.occurred_at > self.detected_at:
                raise GovernanceError("incident occurred_at cannot be after detected_at")
        if not self.affected_nodes:
            raise GovernanceError("incident must reference at least one affected inventory node")
        if len(self.affected_nodes) != len(set(self.affected_nodes)):
            raise GovernanceError("incident affected_nodes must be unique")
        if any(ref.entity_id != self.entity_id for ref in self.affected_nodes):
            raise GovernanceError("incident affected nodes must remain in the same entity scope")
        if self.apparent_root_cause is not None:
            object.__setattr__(
                self,
                "apparent_root_cause",
                _text("apparent_root_cause", self.apparent_root_cause),
            )

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class IncidentEvent:
    entity_id: str
    incident_id: str
    sequence: int
    event_type: IncidentEventType
    occurred_at: int
    recorded_at: int
    summary: str
    evidence_digest: str
    previous_event_digest: str | None = None

    def __post_init__(self) -> None:
        for name in ("entity_id", "incident_id", "summary"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        _nonnegative("sequence", self.sequence)
        _nonnegative("event occurred_at", self.occurred_at)
        _nonnegative("event recorded_at", self.recorded_at)
        if self.recorded_at < self.occurred_at:
            raise GovernanceError("event recorded_at cannot be before occurred_at")
        _digest("event evidence_digest", self.evidence_digest)
        if self.previous_event_digest is not None:
            _digest("previous_event_digest", self.previous_event_digest)

    @property
    def chain_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class IncidentTimeline:
    entity_id: str
    incident_id: str
    events: tuple[IncidentEvent, ...]

    def __post_init__(self) -> None:
        for name in ("entity_id", "incident_id"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        previous: IncidentEvent | None = None
        for index, event in enumerate(self.events):
            if event.entity_id != self.entity_id or event.incident_id != self.incident_id:
                raise GovernanceError("timeline event identity does not match timeline")
            if event.sequence != index:
                raise GovernanceError("timeline event sequence must be contiguous from zero")
            if previous is None:
                if event.previous_event_digest is not None:
                    raise GovernanceError("first timeline event cannot reference a previous event")
            else:
                if event.recorded_at < previous.recorded_at:
                    raise GovernanceError("timeline recorded_at must be append-only and non-decreasing")
                if event.previous_event_digest != previous.chain_digest:
                    raise GovernanceError("timeline event chain is broken")
            previous = event

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


def append_incident_event(
    timeline: IncidentTimeline,
    *,
    event_type: IncidentEventType,
    occurred_at: int,
    recorded_at: int,
    summary: str,
    evidence_digest: str,
) -> IncidentTimeline:
    previous = timeline.events[-1] if timeline.events else None
    event = IncidentEvent(
        entity_id=timeline.entity_id,
        incident_id=timeline.incident_id,
        sequence=len(timeline.events),
        event_type=event_type,
        occurred_at=occurred_at,
        recorded_at=recorded_at,
        summary=summary,
        evidence_digest=evidence_digest,
        previous_event_digest=previous.chain_digest if previous is not None else None,
    )
    return IncidentTimeline(timeline.entity_id, timeline.incident_id, timeline.events + (event,))


@dataclass(frozen=True, slots=True)
class ClientTransactionImpact:
    affected_clients: int = 0
    total_clients_using_service: int = 0
    affected_financial_counterparties: int = 0
    total_financial_counterparties: int = 0
    affected_transactions: int = 0
    daily_average_transactions: int = 0
    affected_transaction_value_eur: int = 0
    daily_average_transaction_value_eur: int = 0
    relevant_client_or_counterparty_affected: bool = False
    estimated: bool = False

    def __post_init__(self) -> None:
        for name in (
            "affected_clients",
            "total_clients_using_service",
            "affected_financial_counterparties",
            "total_financial_counterparties",
            "affected_transactions",
            "daily_average_transactions",
            "affected_transaction_value_eur",
            "daily_average_transaction_value_eur",
        ):
            _nonnegative(name, getattr(self, name))
        if self.affected_clients > self.total_clients_using_service and self.total_clients_using_service > 0:
            raise GovernanceError("affected_clients cannot exceed total_clients_using_service")
        if (
            self.affected_financial_counterparties > self.total_financial_counterparties
            and self.total_financial_counterparties > 0
        ):
            raise GovernanceError("affected counterparties cannot exceed total counterparties")


@dataclass(frozen=True, slots=True)
class ReputationalImpact:
    reflected_in_media: bool = False
    repetitive_client_or_counterparty_complaints: bool = False
    regulatory_requirements_at_risk: bool = False
    material_client_or_counterparty_loss_likely: bool = False

    @property
    def threshold_met(self) -> bool:
        return any(
            (
                self.reflected_in_media,
                self.repetitive_client_or_counterparty_complaints,
                self.regulatory_requirements_at_risk,
                self.material_client_or_counterparty_loss_likely,
            )
        )


@dataclass(frozen=True, slots=True)
class DataLossImpact:
    availability_impacted: bool = False
    authenticity_impacted: bool = False
    integrity_impacted: bool = False
    confidentiality_impacted: bool = False
    adverse_business_or_regulatory_impact: bool = False
    successful_malicious_unauthorised_access_with_potential_data_loss: bool = False

    @property
    def any_data_dimension_impacted(self) -> bool:
        return any(
            (
                self.availability_impacted,
                self.authenticity_impacted,
                self.integrity_impacted,
                self.confidentiality_impacted,
            )
        )

    @property
    def threshold_met(self) -> bool:
        adverse_data_loss = self.any_data_dimension_impacted and self.adverse_business_or_regulatory_impact
        return adverse_data_loss or self.successful_malicious_unauthorised_access_with_potential_data_loss


@dataclass(frozen=True, slots=True)
class IncidentImpactSnapshot:
    clients_transactions: ClientTransactionImpact
    reputation: ReputationalImpact
    data_loss: DataLossImpact
    duration_minutes: int
    critical_function_service_downtime_minutes: int
    impacted_member_states: tuple[str, ...]
    economic_costs_and_losses_eur: int
    authorised_registered_or_supervised_financial_service_affected: bool = False
    successful_malicious_unauthorised_access: bool = False

    def __post_init__(self) -> None:
        _nonnegative("duration_minutes", self.duration_minutes)
        _nonnegative(
            "critical_function_service_downtime_minutes",
            self.critical_function_service_downtime_minutes,
        )
        _nonnegative("economic_costs_and_losses_eur", self.economic_costs_and_losses_eur)
        states = tuple(state.strip().upper() for state in self.impacted_member_states)
        if any(len(state) != 2 or not state.isalpha() for state in states):
            raise GovernanceError("impacted_member_states must contain alpha-2 codes")
        if len(states) != len(set(states)):
            raise GovernanceError("impacted_member_states must be unique")
        object.__setattr__(self, "impacted_member_states", tuple(sorted(states)))
        if (
            self.data_loss.successful_malicious_unauthorised_access_with_potential_data_loss
            and not self.successful_malicious_unauthorised_access
        ):
            raise GovernanceError(
                "potential-data-loss malicious access requires successful_malicious_unauthorised_access"
            )

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class IncidentClassification:
    entity_id: str
    incident_id: str
    inventory_snapshot_digest: str
    incident_digest: str
    impact_snapshot_digest: str
    classified_at: int
    critical_services_affected: bool
    materiality_thresholds: tuple[MaterialityThreshold, ...]
    direct_malicious_access_trigger: bool
    major_incident: bool
    initial_notification_due_at: int | None

    def __post_init__(self) -> None:
        for name in ("entity_id", "incident_id"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        for name in ("inventory_snapshot_digest", "incident_digest", "impact_snapshot_digest"):
            _digest(name, getattr(self, name))
        _nonnegative("classified_at", self.classified_at)
        if len(self.materiality_thresholds) != len(set(self.materiality_thresholds)):
            raise GovernanceError("materiality_thresholds must be unique")
        if self.major_incident and self.initial_notification_due_at is None:
            raise GovernanceError("major incident requires an initial notification deadline")
        if not self.major_incident and self.initial_notification_due_at is not None:
            raise GovernanceError("non-major incident cannot carry a major-incident notification deadline")

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


def _ratio_exceeds(numerator: int, denominator: int, percentage: int) -> bool:
    if denominator <= 0:
        return False
    return numerator * 100 > denominator * percentage


def _clients_transactions_threshold(value: ClientTransactionImpact) -> bool:
    return any(
        (
            _ratio_exceeds(value.affected_clients, value.total_clients_using_service, 10),
            value.affected_clients > 100_000,
            _ratio_exceeds(
                value.affected_financial_counterparties,
                value.total_financial_counterparties,
                30,
            ),
            _ratio_exceeds(value.affected_transactions, value.daily_average_transactions, 10),
            _ratio_exceeds(
                value.affected_transaction_value_eur,
                value.daily_average_transaction_value_eur,
                10,
            ),
            value.relevant_client_or_counterparty_affected,
        )
    )


def _critical_function_affected(registry: InventoryRegistry, incident: IncidentRecord) -> bool:
    for ref in incident.affected_nodes:
        node = registry.node(ref)
        if (
            ref.kind is NodeKind.BUSINESS_FUNCTION
            and isinstance(node, BusinessFunction)
            and node.classification is FunctionClassification.CRITICAL_OR_IMPORTANT
        ):
            return True
    return False


def classify_incident(
    registry: InventoryRegistry,
    incident: IncidentRecord,
    impact: IncidentImpactSnapshot,
    *,
    classified_at: int,
) -> IncidentClassification:
    _nonnegative("classified_at", classified_at)
    if classified_at < incident.detected_at:
        raise GovernanceError("classified_at cannot be before incident detection")
    for ref in incident.affected_nodes:
        registry.node(ref)

    critical_function_affected = _critical_function_affected(registry, incident)
    critical_services_affected = any(
        (
            critical_function_affected,
            impact.authorised_registered_or_supervised_financial_service_affected,
            impact.successful_malicious_unauthorised_access,
        )
    )

    thresholds: list[MaterialityThreshold] = []
    if _clients_transactions_threshold(impact.clients_transactions):
        thresholds.append(MaterialityThreshold.CLIENTS_COUNTERPARTIES_TRANSACTIONS)
    if impact.reputation.threshold_met:
        thresholds.append(MaterialityThreshold.REPUTATIONAL_IMPACT)
    if impact.duration_minutes > 24 * 60 or (
        critical_function_affected
        and impact.critical_function_service_downtime_minutes > 2 * 60
    ):
        thresholds.append(MaterialityThreshold.DURATION_OR_DOWNTIME)
    if len(impact.impacted_member_states) >= 2:
        thresholds.append(MaterialityThreshold.GEOGRAPHICAL_SPREAD)
    if impact.data_loss.threshold_met:
        thresholds.append(MaterialityThreshold.DATA_LOSS)
    if impact.economic_costs_and_losses_eur > 100_000:
        thresholds.append(MaterialityThreshold.ECONOMIC_IMPACT)

    direct_trigger = impact.data_loss.successful_malicious_unauthorised_access_with_potential_data_loss
    major = critical_services_affected and (direct_trigger or len(thresholds) >= 2)

    initial_due: int | None = None
    if major:
        four_hours_after_classification = classified_at + 4 * SECONDS_PER_HOUR
        if classified_at <= incident.detected_at + 24 * SECONDS_PER_HOUR:
            initial_due = min(
                four_hours_after_classification,
                incident.detected_at + 24 * SECONDS_PER_HOUR,
            )
        else:
            initial_due = four_hours_after_classification

    return IncidentClassification(
        entity_id=incident.entity_id,
        incident_id=incident.incident_id,
        inventory_snapshot_digest=registry.snapshot_digest(incident.entity_id),
        incident_digest=incident.evidence_digest,
        impact_snapshot_digest=impact.evidence_digest,
        classified_at=classified_at,
        critical_services_affected=critical_services_affected,
        materiality_thresholds=tuple(sorted(thresholds, key=lambda item: item.value)),
        direct_malicious_access_trigger=direct_trigger,
        major_incident=major,
        initial_notification_due_at=initial_due,
    )


def assert_incident_classification_current(
    classification: IncidentClassification,
    registry: InventoryRegistry,
    incident: IncidentRecord,
    impact: IncidentImpactSnapshot,
) -> None:
    if classification.entity_id != incident.entity_id or classification.incident_id != incident.incident_id:
        raise GovernanceError("incident classification identity does not match incident")
    if classification.inventory_snapshot_digest != registry.snapshot_digest(incident.entity_id):
        raise GovernanceError("incident classification is stale for current inventory snapshot")
    if classification.incident_digest != incident.evidence_digest:
        raise GovernanceError("incident classification is stale for current incident record")
    if classification.impact_snapshot_digest != impact.evidence_digest:
        raise GovernanceError("incident classification is stale for current impact snapshot")
