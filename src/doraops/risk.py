from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, IntEnum
from typing import Iterable

from .canonical import sha256_digest
from .inventory import GovernanceError, InventoryRegistry, NodeRef


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Likelihood(IntEnum):
    RARE = 1
    POSSIBLE = 2
    LIKELY = 3
    ALMOST_CERTAIN = 4


class Impact(IntEnum):
    LIMITED = 1
    MATERIAL = 2
    SEVERE = 3
    CRITICAL = 4


class ControlEffectiveness(IntEnum):
    INEFFECTIVE = 0
    LIMITED = 1
    ADEQUATE = 2
    STRONG = 3


class TreatmentType(str, Enum):
    MITIGATE = "mitigate"
    ACCEPT = "accept"
    AVOID = "avoid"
    TRANSFER = "transfer"


def _text(name: str, value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise GovernanceError(f"{name} must be a non-empty string")
    return value.strip()


def _digest(name: str, value: str) -> str:
    if len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
        raise GovernanceError(f"{name} must be a lowercase SHA-256 digest")
    return value


@dataclass(frozen=True, slots=True)
class ICTRiskScenario:
    entity_id: str
    scenario_id: str
    title: str
    threat: str
    vulnerability: str
    risk_owner_id: str
    affected_nodes: tuple[NodeRef, ...]
    likelihood: Likelihood
    impact: Impact

    def __post_init__(self) -> None:
        for name in ("entity_id", "scenario_id", "title", "threat", "vulnerability", "risk_owner_id"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        if not self.affected_nodes:
            raise GovernanceError("risk scenario must reference at least one affected inventory node")
        if len(self.affected_nodes) != len(set(self.affected_nodes)):
            raise GovernanceError("risk scenario affected_nodes must be unique")
        if any(ref.entity_id != self.entity_id for ref in self.affected_nodes):
            raise GovernanceError("risk scenario affected nodes must remain in the same entity scope")

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class ICTControlObservation:
    entity_id: str
    control_id: str
    name: str
    control_type: str
    effectiveness: ControlEffectiveness
    evidence_digest: str

    def __post_init__(self) -> None:
        for name in ("entity_id", "control_id", "name", "control_type"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        object.__setattr__(self, "evidence_digest", _digest("control evidence_digest", self.evidence_digest))

    @property
    def governance_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class ICTRiskPolicy:
    entity_id: str
    policy_id: str
    version: str
    medium_threshold: int = 5
    high_threshold: int = 9
    critical_threshold: int = 13
    max_control_credit: int = 4

    def __post_init__(self) -> None:
        for name in ("entity_id", "policy_id", "version"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        if not (1 < self.medium_threshold < self.high_threshold < self.critical_threshold <= 16):
            raise GovernanceError("ICT risk thresholds must be strictly increasing within the 1..16 score range")
        if self.max_control_credit < 0 or self.max_control_credit > 8:
            raise GovernanceError("max_control_credit must be between 0 and 8")

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class RiskTreatmentPlan:
    treatment: TreatmentType
    treatment_owner_id: str
    rationale: str
    target_timestamp: int | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "treatment_owner_id", _text("treatment_owner_id", self.treatment_owner_id))
        object.__setattr__(self, "rationale", _text("treatment rationale", self.rationale))
        if self.target_timestamp is not None and self.target_timestamp < 0:
            raise GovernanceError("target_timestamp must be non-negative")
        if self.treatment is TreatmentType.MITIGATE and self.target_timestamp is None:
            raise GovernanceError("mitigation treatment requires target_timestamp")


@dataclass(frozen=True, slots=True)
class ICTRiskDecision:
    entity_id: str
    scenario_id: str
    inventory_snapshot_digest: str
    scenario_digest: str
    policy_digest: str
    control_digests: tuple[str, ...]
    inherent_score: int
    inherent_level: RiskLevel
    control_credit: int
    residual_score: int
    residual_level: RiskLevel
    treatment: RiskTreatmentPlan
    risk_acceptance_required: bool
    remediation_required: bool

    def __post_init__(self) -> None:
        for name in ("entity_id", "scenario_id"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        for name in ("inventory_snapshot_digest", "scenario_digest", "policy_digest"):
            _digest(name, getattr(self, name))
        for value in self.control_digests:
            _digest("control digest", value)
        if len(self.control_digests) != len(set(self.control_digests)):
            raise GovernanceError("control_digests must be unique")

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


def _level(score: int, policy: ICTRiskPolicy) -> RiskLevel:
    if score >= policy.critical_threshold:
        return RiskLevel.CRITICAL
    if score >= policy.high_threshold:
        return RiskLevel.HIGH
    if score >= policy.medium_threshold:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


def _normalize_controls(
    controls: Iterable[ICTControlObservation],
    entity_id: str,
) -> tuple[ICTControlObservation, ...]:
    control_list = tuple(sorted(controls, key=lambda item: item.control_id))
    if any(control.entity_id != entity_id for control in control_list):
        raise GovernanceError("ICT control observation is outside the scenario entity scope")
    control_ids = tuple(control.control_id for control in control_list)
    if len(control_ids) != len(set(control_ids)):
        raise GovernanceError("ICT control observations must not repeat control_id")
    return control_list


def assess_ict_risk(
    registry: InventoryRegistry,
    scenario: ICTRiskScenario,
    controls: Iterable[ICTControlObservation],
    policy: ICTRiskPolicy,
    treatment: RiskTreatmentPlan,
) -> ICTRiskDecision:
    if policy.entity_id != scenario.entity_id:
        raise GovernanceError("ICT risk policy is not scoped to the scenario entity")

    for ref in scenario.affected_nodes:
        registry.node(ref)

    inventory_digest = registry.snapshot_digest(scenario.entity_id)
    control_list = _normalize_controls(controls, scenario.entity_id)

    inherent_score = int(scenario.likelihood) * int(scenario.impact)
    inherent_level = _level(inherent_score, policy)
    raw_credit = sum(int(control.effectiveness) for control in control_list)
    control_credit = min(policy.max_control_credit, raw_credit)
    residual_score = max(1, inherent_score - control_credit)
    residual_level = _level(residual_score, policy)

    risk_acceptance_required = treatment.treatment is TreatmentType.ACCEPT and residual_level in {
        RiskLevel.HIGH,
        RiskLevel.CRITICAL,
    }
    remediation_required = residual_level in {RiskLevel.HIGH, RiskLevel.CRITICAL} and treatment.treatment is not TreatmentType.ACCEPT

    return ICTRiskDecision(
        entity_id=scenario.entity_id,
        scenario_id=scenario.scenario_id,
        inventory_snapshot_digest=inventory_digest,
        scenario_digest=scenario.evidence_digest,
        policy_digest=policy.evidence_digest,
        control_digests=tuple(control.governance_digest for control in control_list),
        inherent_score=inherent_score,
        inherent_level=inherent_level,
        control_credit=control_credit,
        residual_score=residual_score,
        residual_level=residual_level,
        treatment=treatment,
        risk_acceptance_required=risk_acceptance_required,
        remediation_required=remediation_required,
    )


def assert_risk_decision_current(
    decision: ICTRiskDecision,
    registry: InventoryRegistry,
    scenario: ICTRiskScenario,
    controls: Iterable[ICTControlObservation],
    policy: ICTRiskPolicy,
) -> None:
    if decision.entity_id != scenario.entity_id or decision.scenario_id != scenario.scenario_id:
        raise GovernanceError("ICT risk decision identity does not match scenario")
    if decision.inventory_snapshot_digest != registry.snapshot_digest(scenario.entity_id):
        raise GovernanceError("ICT risk decision is stale for current inventory snapshot")
    if decision.scenario_digest != scenario.evidence_digest:
        raise GovernanceError("ICT risk decision is stale for current scenario")
    if decision.policy_digest != policy.evidence_digest:
        raise GovernanceError("ICT risk decision is stale for current risk policy")
    control_list = _normalize_controls(controls, scenario.entity_id)
    current_control_digests = tuple(control.governance_digest for control in control_list)
    if decision.control_digests != current_control_digests:
        raise GovernanceError("ICT risk decision is stale for current control evidence")
