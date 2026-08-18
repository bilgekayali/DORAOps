from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, IntEnum
from typing import Iterable

from .canonical import sha256_digest
from .inventory import GovernanceError, InventoryRegistry, NodeRef, ThirdPartyService


class IncidentEventType(str, Enum):
    DETECTED = "detected"
    ESCALATED = "escalated"
    CONTAINED = "contained"
    RECOVERED = "recovered"
    ROOT_CAUSE_IDENTIFIED = "root_cause_identified"
    REMEDIATION_LINKED = "remediation_linked"
    NOTIFICATION_DECISION = "notification_decision"
    OTHER = "other"


class ImpactDimension(str, Enum):
    SERVICE_AVAILABILITY = "service_availability"
    DATA_CONFIDENTIALITY = "data_confidentiality"
    DATA_INTEGRITY = "data_integrity"
    DATA_AVAILABILITY = "data_availability"
    CLIENT_IMPACT = "client_impact"
    FINANCIAL_IMPACT = "financial_impact"
    GEOGRAPHIC_SPREAD = "geographic_spread"
    REPUTATIONAL_IMPACT = "reputational_impact"
    OTHER = "other"


class ImpactSeverity(IntEnum):
    LIMITED = 1
    MATERIAL = 2
    SEVERE = 3
    CRITICAL = 4


class ClassificationReadinessState(str, Enum):
    INCOMPLETE = "incomplete"
    READY_FOR_HUMAN_REVIEW = "ready_for_human_review"


class HumanClassificationDecision(str, Enum):
    MAJOR = "major"
    NON_MAJOR = "non_major"
    UNDETERMINED = "undetermined"


def _text(name: str, value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise GovernanceError(f"{name} must be a non-empty string")
    return value.strip()


def _digest(name: str, value: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
        raise GovernanceError(f"{name} must be a lowercase SHA-256 digest")
    return value


def _timestamp(name: str, value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise GovernanceError(f"{name} must be a non-negative integer timestamp")
    return value


@dataclass(frozen=True, slots=True)
class ICTIncident:
    entity_id: str
    incident_id: str
    title: str
    incident_owner_id: str
    occurred_at: int
    detected_at: int
    inventory_snapshot_digest: str
    affected_nodes: tuple[NodeRef, ...]

    def __post_init__(self) -> None:
        for name in ("entity_id", "incident_id", "title", "incident_owner_id"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        _timestamp("occurred_at", self.occurred_at)
        _timestamp("detected_at", self.detected_at)
        if self.detected_at < self.occurred_at:
            raise GovernanceError("detected_at cannot precede occurred_at")
        _digest("inventory_snapshot_digest", self.inventory_snapshot_digest)
        if not self.affected_nodes:
            raise GovernanceError("incident must reference at least one affected inventory node")
        if len(self.affected_nodes) != len(set(self.affected_nodes)):
            raise GovernanceError("incident affected_nodes must be unique")
        if any(ref.entity_id != self.entity_id for ref in self.affected_nodes):
            raise GovernanceError("incident affected nodes must remain in the same entity scope")

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class IncidentEvent:
    entity_id: str
    incident_id: str
    event_id: str
    sequence: int
    event_type: IncidentEventType
    occurred_at: int
    recorded_at: int
    actor_id: str
    summary: str
    evidence_digest: str
    related_reference: str | None = None

    def __post_init__(self) -> None:
        for name in ("entity_id", "incident_id", "event_id", "actor_id", "summary"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        if isinstance(self.sequence, bool) or not isinstance(self.sequence, int) or self.sequence < 1:
            raise GovernanceError("incident event sequence must be a positive integer")
        _timestamp("event occurred_at", self.occurred_at)
        _timestamp("event recorded_at", self.recorded_at)
        if self.recorded_at < self.occurred_at:
            raise GovernanceError("event recorded_at cannot precede occurred_at")
        _digest("event evidence_digest", self.evidence_digest)
        if self.related_reference is not None:
            object.__setattr__(self, "related_reference", _text("related_reference", self.related_reference))
        if self.event_type in {
            IncidentEventType.ROOT_CAUSE_IDENTIFIED,
            IncidentEventType.REMEDIATION_LINKED,
            IncidentEventType.NOTIFICATION_DECISION,
        } and self.related_reference is None:
            raise GovernanceError(f"{self.event_type.value} event requires related_reference")

    @property
    def governance_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class IncidentImpactObservation:
    entity_id: str
    incident_id: str
    impact_id: str
    dimension: ImpactDimension
    severity: ImpactSeverity
    observed_at: int
    affected_nodes: tuple[NodeRef, ...]
    summary: str
    evidence_digest: str

    def __post_init__(self) -> None:
        for name in ("entity_id", "incident_id", "impact_id", "summary"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        _timestamp("impact observed_at", self.observed_at)
        _digest("impact evidence_digest", self.evidence_digest)
        if not self.affected_nodes:
            raise GovernanceError("impact observation must reference at least one affected node")
        if len(self.affected_nodes) != len(set(self.affected_nodes)):
            raise GovernanceError("impact affected_nodes must be unique")
        if any(ref.entity_id != self.entity_id for ref in self.affected_nodes):
            raise GovernanceError("impact affected nodes must remain in the same entity scope")

    @property
    def governance_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class IncidentClassificationPolicy:
    entity_id: str
    policy_id: str
    version: str
    required_impact_dimensions: tuple[ImpactDimension, ...]
    require_recovery_event: bool = True
    require_root_cause_reference: bool = False
    require_remediation_reference: bool = False
    require_notification_decision: bool = True

    def __post_init__(self) -> None:
        for name in ("entity_id", "policy_id", "version"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        if not self.required_impact_dimensions:
            raise GovernanceError("classification policy requires at least one impact dimension")
        if len(self.required_impact_dimensions) != len(set(self.required_impact_dimensions)):
            raise GovernanceError("required impact dimensions must be unique")

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class IncidentClassificationReadiness:
    entity_id: str
    incident_id: str
    incident_digest: str
    incident_evidence_snapshot_digest: str
    policy_digest: str
    state: ClassificationReadinessState
    missing_inputs: tuple[str, ...]
    observed_impact_dimensions: tuple[ImpactDimension, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "entity_id", _text("entity_id", self.entity_id))
        object.__setattr__(self, "incident_id", _text("incident_id", self.incident_id))
        for name in ("incident_digest", "incident_evidence_snapshot_digest", "policy_digest"):
            _digest(name, getattr(self, name))
        if len(self.missing_inputs) != len(set(self.missing_inputs)):
            raise GovernanceError("missing_inputs must be unique")
        if len(self.observed_impact_dimensions) != len(set(self.observed_impact_dimensions)):
            raise GovernanceError("observed impact dimensions must be unique")
        expected = (
            ClassificationReadinessState.INCOMPLETE
            if self.missing_inputs
            else ClassificationReadinessState.READY_FOR_HUMAN_REVIEW
        )
        if self.state is not expected:
            raise GovernanceError("classification readiness state is inconsistent with missing inputs")

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class IncidentClassificationReview:
    entity_id: str
    incident_id: str
    readiness_digest: str
    incident_evidence_snapshot_digest: str
    reviewer_id: str
    decision: HumanClassificationDecision
    rationale: str
    reviewed_at: int

    def __post_init__(self) -> None:
        for name in ("entity_id", "incident_id", "reviewer_id", "rationale"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        _digest("readiness_digest", self.readiness_digest)
        _digest("incident_evidence_snapshot_digest", self.incident_evidence_snapshot_digest)
        _timestamp("reviewed_at", self.reviewed_at)

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


class IncidentRegistry:
    """Append-only reference registry for deterministic ICT incident evidence."""

    def __init__(self, inventory: InventoryRegistry) -> None:
        self._inventory = inventory
        self._incidents: dict[tuple[str, str], ICTIncident] = {}
        self._events: dict[tuple[str, str], list[IncidentEvent]] = {}
        self._impacts: dict[tuple[str, str], dict[str, IncidentImpactObservation]] = {}

    def register_incident(self, incident: ICTIncident) -> str:
        if incident.inventory_snapshot_digest != self._inventory.snapshot_digest(incident.entity_id):
            raise GovernanceError("incident inventory_snapshot_digest is stale for current inventory")
        for ref in incident.affected_nodes:
            self._inventory.node(ref)
        key = (incident.entity_id, incident.incident_id)
        existing = self._incidents.get(key)
        if existing is not None and existing.evidence_digest != incident.evidence_digest:
            raise GovernanceError("incident_id is already registered with different content")
        self._incidents.setdefault(key, incident)
        self._events.setdefault(key, [])
        self._impacts.setdefault(key, {})
        return incident.evidence_digest

    def append_event(self, event: IncidentEvent) -> str:
        key = (event.entity_id, event.incident_id)
        incident = self._require_incident(*key)
        events = self._events[key]
        if any(existing.event_id == event.event_id for existing in events):
            existing = next(existing for existing in events if existing.event_id == event.event_id)
            if existing.governance_digest != event.governance_digest:
                raise GovernanceError("event_id is already registered with different content")
            return existing.governance_digest
        expected_sequence = len(events) + 1
        if event.sequence != expected_sequence:
            raise GovernanceError("incident events must be appended with contiguous sequence numbers")
        if event.occurred_at < incident.occurred_at:
            raise GovernanceError("incident event cannot predate incident occurred_at")
        events.append(event)
        return event.governance_digest

    def register_impact(self, impact: IncidentImpactObservation) -> str:
        key = (impact.entity_id, impact.incident_id)
        incident = self._require_incident(*key)
        incident_nodes = set(incident.affected_nodes)
        for ref in impact.affected_nodes:
            self._inventory.node(ref)
            if ref not in incident_nodes:
                raise GovernanceError("impact observation references a node outside incident scope")
        impacts = self._impacts[key]
        existing = impacts.get(impact.impact_id)
        if existing is not None and existing.governance_digest != impact.governance_digest:
            raise GovernanceError("impact_id is already registered with different content")
        impacts.setdefault(impact.impact_id, impact)
        return impact.governance_digest

    def incident(self, entity_id: str, incident_id: str) -> ICTIncident:
        return self._require_incident(entity_id, incident_id)

    def events(self, entity_id: str, incident_id: str) -> tuple[IncidentEvent, ...]:
        self._require_incident(entity_id, incident_id)
        return tuple(self._events[(entity_id, incident_id)])

    def impacts(self, entity_id: str, incident_id: str) -> tuple[IncidentImpactObservation, ...]:
        self._require_incident(entity_id, incident_id)
        return tuple(sorted(self._impacts[(entity_id, incident_id)].values(), key=lambda item: item.impact_id))

    def evidence_snapshot_digest(self, entity_id: str, incident_id: str) -> str:
        incident = self._require_incident(entity_id, incident_id)
        return sha256_digest(
            {
                "incident": incident.evidence_digest,
                "events": [item.governance_digest for item in self.events(entity_id, incident_id)],
                "impacts": [item.governance_digest for item in self.impacts(entity_id, incident_id)],
            }
        )

    def affected_provider_ids(self, entity_id: str, incident_id: str) -> tuple[str, ...]:
        incident = self._require_incident(entity_id, incident_id)
        provider_ids = {
            node.provider_id
            for ref in incident.affected_nodes
            for node in (self._inventory.node(ref),)
            if isinstance(node, ThirdPartyService)
        }
        return tuple(sorted(provider_ids))

    def _require_incident(self, entity_id: str, incident_id: str) -> ICTIncident:
        try:
            return self._incidents[(entity_id, incident_id)]
        except KeyError as exc:
            raise GovernanceError("unknown ICT incident") from exc


def assess_classification_readiness(
    registry: IncidentRegistry,
    entity_id: str,
    incident_id: str,
    policy: IncidentClassificationPolicy,
) -> IncidentClassificationReadiness:
    incident = registry.incident(entity_id, incident_id)
    if policy.entity_id != entity_id:
        raise GovernanceError("incident classification policy is outside entity scope")

    events = registry.events(entity_id, incident_id)
    impacts = registry.impacts(entity_id, incident_id)
    event_types = {event.event_type for event in events}
    observed_dimensions = tuple(sorted({impact.dimension for impact in impacts}, key=lambda item: item.value))
    missing: list[str] = []

    if not impacts:
        missing.append("impact_observation")
    for dimension in policy.required_impact_dimensions:
        if dimension not in set(observed_dimensions):
            missing.append(f"impact_dimension:{dimension.value}")
    if policy.require_recovery_event and IncidentEventType.RECOVERED not in event_types:
        missing.append("recovery_event")
    if policy.require_root_cause_reference and IncidentEventType.ROOT_CAUSE_IDENTIFIED not in event_types:
        missing.append("root_cause_reference")
    if policy.require_remediation_reference and IncidentEventType.REMEDIATION_LINKED not in event_types:
        missing.append("remediation_reference")
    if policy.require_notification_decision and IncidentEventType.NOTIFICATION_DECISION not in event_types:
        missing.append("notification_decision")

    missing_inputs = tuple(sorted(set(missing)))
    state = (
        ClassificationReadinessState.INCOMPLETE
        if missing_inputs
        else ClassificationReadinessState.READY_FOR_HUMAN_REVIEW
    )
    return IncidentClassificationReadiness(
        entity_id=entity_id,
        incident_id=incident_id,
        incident_digest=incident.evidence_digest,
        incident_evidence_snapshot_digest=registry.evidence_snapshot_digest(entity_id, incident_id),
        policy_digest=policy.evidence_digest,
        state=state,
        missing_inputs=missing_inputs,
        observed_impact_dimensions=observed_dimensions,
    )


def review_incident_classification(
    registry: IncidentRegistry,
    readiness: IncidentClassificationReadiness,
    policy: IncidentClassificationPolicy,
    *,
    reviewer_id: str,
    decision: HumanClassificationDecision,
    rationale: str,
    reviewed_at: int,
) -> IncidentClassificationReview:
    if readiness.state is not ClassificationReadinessState.READY_FOR_HUMAN_REVIEW:
        raise GovernanceError("incomplete incident evidence cannot receive a final human classification review")
    if readiness.policy_digest != policy.evidence_digest:
        raise GovernanceError("classification readiness is stale for current policy")
    current_snapshot = registry.evidence_snapshot_digest(readiness.entity_id, readiness.incident_id)
    if readiness.incident_evidence_snapshot_digest != current_snapshot:
        raise GovernanceError("classification readiness is stale for current incident evidence")
    return IncidentClassificationReview(
        entity_id=readiness.entity_id,
        incident_id=readiness.incident_id,
        readiness_digest=readiness.evidence_digest,
        incident_evidence_snapshot_digest=current_snapshot,
        reviewer_id=reviewer_id,
        decision=decision,
        rationale=rationale,
        reviewed_at=reviewed_at,
    )
