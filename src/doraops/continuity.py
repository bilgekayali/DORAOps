from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable

from .canonical import sha256_digest
from .inventory import GovernanceError, InventoryRegistry, NodeKind, NodeRef
from .resilience import FindingSeverity, RetestOutcome


class RecoveryMetric(str, Enum):
    MAXIMUM_TOLERABLE_DISRUPTION = "maximum_tolerable_disruption"
    RECOVERY_TIME_OBJECTIVE = "recovery_time_objective"
    RECOVERY_POINT_OBJECTIVE = "recovery_point_objective"
    MINIMUM_SERVICE_LEVEL = "minimum_service_level"


class RecoveryMetricState(str, Enum):
    MET = "met"
    BREACHED = "breached"
    INCOMPLETE = "incomplete"


class RecoveryAssessmentState(str, Enum):
    MET = "met"
    BREACHED = "breached"
    INCOMPLETE = "incomplete"


class ContinuityFindingStatus(str, Enum):
    OPEN = "open"
    REMEDIATION_SUBMITTED = "remediation_submitted"
    RETEST_FAILED = "retest_failed"
    CLOSED = "closed"


class ContinuityResolutionState(str, Enum):
    SUCCESSFUL = "successful"
    SUCCESSFUL_WITH_FINDINGS = "successful_with_findings"
    BLOCKED = "blocked"
    INCOMPLETE = "incomplete"


class DependencyTraversalDirection(str, Enum):
    OUTBOUND = "outbound"
    INBOUND = "inbound"
    BOTH = "both"


_RECOVERY_TARGET_KINDS = {
    NodeKind.BUSINESS_FUNCTION,
    NodeKind.BUSINESS_PROCESS,
    NodeKind.ICT_SERVICE,
}


def _text(name: str, value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise GovernanceError(f"{name} must be a non-empty string")
    return value.strip()


def _digest(name: str, value: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(ch not in "0123456789abcdef" for ch in value)
    ):
        raise GovernanceError(f"{name} must be a lowercase SHA-256 digest")
    return value


def _timestamp(name: str, value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise GovernanceError(f"{name} must be a non-negative integer timestamp")
    return value


def _positive_int(name: str, value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise GovernanceError(f"{name} must be a positive integer")
    return value


def _non_negative_int(name: str, value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise GovernanceError(f"{name} must be a non-negative integer")
    return value


def _basis_points(name: str, value: int, *, allow_zero: bool = True) -> int:
    minimum = 0 if allow_zero else 1
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= 10_000:
        raise GovernanceError(f"{name} must be an integer between {minimum} and 10000 basis points")
    return value


def _node_key(ref: NodeRef) -> tuple[str, str]:
    if not isinstance(ref, NodeRef) or not isinstance(ref.kind, NodeKind):
        raise GovernanceError("continuity node references must use governed NodeRef/NodeKind values")
    return ref.kind.value, ref.node_id


def _validate_ref(ref: NodeRef, entity_id: str, *, recovery_target: bool = False) -> NodeRef:
    _node_key(ref)
    if ref.entity_id != entity_id:
        raise GovernanceError("continuity node reference is outside entity scope")
    if recovery_target and ref.kind not in _RECOVERY_TARGET_KINDS:
        raise GovernanceError("recovery objective target must be a business function, process or ICT service")
    return ref


def _unique_texts(name: str, values: Iterable[str], *, allow_empty: bool = False) -> tuple[str, ...]:
    cleaned = tuple(_text(name, value) for value in values)
    if not allow_empty and not cleaned:
        raise GovernanceError(f"{name} must contain at least one value")
    if len(cleaned) != len(set(cleaned)):
        raise GovernanceError(f"{name} must contain unique values")
    return tuple(sorted(cleaned))


def _unique_digests(name: str, values: Iterable[str]) -> tuple[str, ...]:
    cleaned = tuple(_digest(name, value) for value in values)
    if not cleaned:
        raise GovernanceError(f"{name}s must contain at least one digest")
    if len(cleaned) != len(set(cleaned)):
        raise GovernanceError(f"{name}s must be unique")
    return tuple(sorted(cleaned))


@dataclass(frozen=True, slots=True)
class RecoveryObjectiveProfile:
    entity_id: str
    objective_id: str
    target: NodeRef
    inventory_snapshot_digest: str
    owner_id: str
    maximum_tolerable_disruption_seconds: int
    recovery_time_objective_seconds: int
    recovery_point_objective_seconds: int
    minimum_service_level_basis_points: int
    rationale: str
    registered_at: int

    def __post_init__(self) -> None:
        for name in ("entity_id", "objective_id", "owner_id", "rationale"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        _validate_ref(self.target, self.entity_id, recovery_target=True)
        _digest("inventory_snapshot_digest", self.inventory_snapshot_digest)
        _positive_int("maximum_tolerable_disruption_seconds", self.maximum_tolerable_disruption_seconds)
        _positive_int("recovery_time_objective_seconds", self.recovery_time_objective_seconds)
        _non_negative_int("recovery_point_objective_seconds", self.recovery_point_objective_seconds)
        _basis_points("minimum_service_level_basis_points", self.minimum_service_level_basis_points, allow_zero=False)
        if self.recovery_time_objective_seconds > self.maximum_tolerable_disruption_seconds:
            raise GovernanceError("recovery_time_objective_seconds cannot exceed maximum tolerable disruption")
        _timestamp("registered_at", self.registered_at)

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class ContinuityExercisePlan:
    entity_id: str
    exercise_id: str
    title: str
    objective_digest: str
    objective_target: NodeRef
    inventory_snapshot_digest: str
    owner_id: str
    independent_reviewer_id: str | None
    scenario: str
    activation_assumptions: tuple[str, ...]
    scope_nodes: tuple[NodeRef, ...]
    planned_at: int

    def __post_init__(self) -> None:
        for name in ("entity_id", "exercise_id", "title", "owner_id", "scenario"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        _digest("objective_digest", self.objective_digest)
        _digest("inventory_snapshot_digest", self.inventory_snapshot_digest)
        _validate_ref(self.objective_target, self.entity_id, recovery_target=True)
        if self.independent_reviewer_id is not None:
            reviewer = _text("independent_reviewer_id", self.independent_reviewer_id)
            if reviewer == self.owner_id:
                raise GovernanceError("independent reviewer must differ from continuity exercise owner")
            object.__setattr__(self, "independent_reviewer_id", reviewer)
        object.__setattr__(
            self,
            "activation_assumptions",
            _unique_texts("activation_assumption", self.activation_assumptions),
        )
        scope = tuple(self.scope_nodes)
        if not scope:
            raise GovernanceError("continuity exercise scope must contain at least one node")
        if len(scope) != len(set(scope)):
            raise GovernanceError("continuity exercise scope_nodes must be unique")
        for ref in scope:
            _validate_ref(ref, self.entity_id)
        if self.objective_target not in scope:
            raise GovernanceError("continuity exercise scope must include the recovery-objective target")
        object.__setattr__(self, "scope_nodes", tuple(sorted(scope, key=_node_key)))
        _timestamp("planned_at", self.planned_at)

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class ContinuityExerciseExecution:
    plan_digest: str
    execution_id: str
    started_at: int
    completed_at: int
    executor_id: str
    evidence_digests: tuple[str, ...]
    notes: str

    def __post_init__(self) -> None:
        _digest("plan_digest", self.plan_digest)
        for name in ("execution_id", "executor_id", "notes"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        _timestamp("started_at", self.started_at)
        _timestamp("completed_at", self.completed_at)
        if self.completed_at < self.started_at:
            raise GovernanceError("continuity exercise cannot complete before it starts")
        object.__setattr__(self, "evidence_digests", _unique_digests("execution evidence_digest", self.evidence_digests))

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class RecoveryObservation:
    plan_digest: str
    execution_digest: str
    observation_id: str
    observed_at: int
    observer_id: str
    restoration_time_seconds: int | None
    recovery_point_loss_seconds: int | None
    achieved_service_level_basis_points: int | None
    evidence_digests: tuple[str, ...]

    def __post_init__(self) -> None:
        _digest("plan_digest", self.plan_digest)
        _digest("execution_digest", self.execution_digest)
        for name in ("observation_id", "observer_id"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        _timestamp("observed_at", self.observed_at)
        if self.restoration_time_seconds is not None:
            _non_negative_int("restoration_time_seconds", self.restoration_time_seconds)
        if self.recovery_point_loss_seconds is not None:
            _non_negative_int("recovery_point_loss_seconds", self.recovery_point_loss_seconds)
        if self.achieved_service_level_basis_points is not None:
            _basis_points("achieved_service_level_basis_points", self.achieved_service_level_basis_points)
        object.__setattr__(self, "evidence_digests", _unique_digests("observation evidence_digest", self.evidence_digests))

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class RecoveryMetricAssessment:
    metric: RecoveryMetric
    state: RecoveryMetricState
    observed_value: int | None
    threshold_value: int
    reason: str

    def __post_init__(self) -> None:
        if not isinstance(self.metric, RecoveryMetric):
            raise GovernanceError("recovery metric must use RecoveryMetric")
        if not isinstance(self.state, RecoveryMetricState):
            raise GovernanceError("recovery metric state must use RecoveryMetricState")
        if self.observed_value is not None:
            _non_negative_int("observed_value", self.observed_value)
        _non_negative_int("threshold_value", self.threshold_value)
        object.__setattr__(self, "reason", _text("reason", self.reason))
        if self.state is RecoveryMetricState.INCOMPLETE and self.observed_value is not None:
            raise GovernanceError("incomplete recovery metric cannot carry an observed value")
        if self.state is not RecoveryMetricState.INCOMPLETE and self.observed_value is None:
            raise GovernanceError("met/breached recovery metric requires an observed value")

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class ContinuityAssessment:
    entity_id: str
    plan_digest: str
    execution_digest: str
    objective_digest: str
    observation_digest: str | None
    assessed_at: int
    state: RecoveryAssessmentState
    metric_assessments: tuple[RecoveryMetricAssessment, ...]
    gaps: tuple[str, ...]
    operational_resilience_determined: bool = False
    regulatory_compliance_determined: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "entity_id", _text("entity_id", self.entity_id))
        for name in ("plan_digest", "execution_digest", "objective_digest"):
            _digest(name, getattr(self, name))
        if self.observation_digest is not None:
            _digest("observation_digest", self.observation_digest)
        _timestamp("assessed_at", self.assessed_at)
        if not isinstance(self.state, RecoveryAssessmentState):
            raise GovernanceError("continuity assessment state must use RecoveryAssessmentState")
        metrics = tuple(self.metric_assessments)
        if {item.metric for item in metrics} != set(RecoveryMetric):
            raise GovernanceError("continuity assessment must cover every governed recovery metric exactly once")
        if len(metrics) != len(set(item.metric for item in metrics)):
            raise GovernanceError("continuity assessment recovery metrics must be unique")
        object.__setattr__(self, "metric_assessments", tuple(sorted(metrics, key=lambda item: item.metric.value)))
        gaps = tuple(self.gaps)
        if gaps != tuple(sorted(set(gaps))):
            raise GovernanceError("continuity assessment gaps must be sorted and unique")
        if self.operational_resilience_determined or self.regulatory_compliance_determined:
            raise GovernanceError("continuity assessment does not determine resilience or regulatory compliance")
        states = {item.state for item in metrics}
        expected = RecoveryAssessmentState.MET
        if RecoveryMetricState.INCOMPLETE in states:
            expected = RecoveryAssessmentState.INCOMPLETE
        elif RecoveryMetricState.BREACHED in states:
            expected = RecoveryAssessmentState.BREACHED
        if self.state is not expected:
            raise GovernanceError("continuity assessment state is inconsistent with metric assessments")
        if self.state is RecoveryAssessmentState.MET and gaps:
            raise GovernanceError("met continuity assessment cannot carry gaps")
        if self.state is RecoveryAssessmentState.INCOMPLETE and not gaps:
            raise GovernanceError("incomplete continuity assessment must explain missing evidence")

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class ContinuityFinding:
    entity_id: str
    finding_id: str
    assessment_digest: str
    severity: FindingSeverity
    title: str
    owner_id: str
    identified_at: int
    evidence_digest: str

    def __post_init__(self) -> None:
        for name in ("entity_id", "finding_id", "title", "owner_id"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        _digest("assessment_digest", self.assessment_digest)
        if not isinstance(self.severity, FindingSeverity):
            raise GovernanceError("continuity finding severity must use FindingSeverity")
        _timestamp("identified_at", self.identified_at)
        object.__setattr__(self, "evidence_digest", _digest("finding evidence_digest", self.evidence_digest))

    @property
    def governance_digest(self) -> str:
        return sha256_digest(self)

    @property
    def blocking(self) -> bool:
        return self.severity in {FindingSeverity.HIGH, FindingSeverity.CRITICAL}


@dataclass(frozen=True, slots=True)
class ContinuityRemediationEvidence:
    finding_digest: str
    remediation_id: str
    owner_id: str
    completed_at: int
    summary: str
    evidence_digest: str

    def __post_init__(self) -> None:
        _digest("finding_digest", self.finding_digest)
        for name in ("remediation_id", "owner_id", "summary"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        _timestamp("completed_at", self.completed_at)
        object.__setattr__(self, "evidence_digest", _digest("remediation evidence_digest", self.evidence_digest))

    @property
    def governance_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class ContinuityRetestEvidence:
    finding_digest: str
    remediation_digest: str
    retest_id: str
    reviewer_id: str
    tested_at: int
    outcome: RetestOutcome
    notes: str
    evidence_digest: str

    def __post_init__(self) -> None:
        _digest("finding_digest", self.finding_digest)
        _digest("remediation_digest", self.remediation_digest)
        for name in ("retest_id", "reviewer_id", "notes"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        _timestamp("tested_at", self.tested_at)
        if not isinstance(self.outcome, RetestOutcome):
            raise GovernanceError("continuity retest outcome must use RetestOutcome")
        object.__setattr__(self, "evidence_digest", _digest("retest evidence_digest", self.evidence_digest))

    @property
    def governance_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class ContinuityFindingResolution:
    finding_digest: str
    status: ContinuityFindingStatus
    blocking: bool
    remediation_digest: str | None
    retest_digest: str | None

    def __post_init__(self) -> None:
        _digest("finding_digest", self.finding_digest)
        if not isinstance(self.status, ContinuityFindingStatus):
            raise GovernanceError("continuity finding status must use ContinuityFindingStatus")
        if type(self.blocking) is not bool:
            raise GovernanceError("continuity finding blocking must be a boolean")
        if self.remediation_digest is not None:
            _digest("remediation_digest", self.remediation_digest)
        if self.retest_digest is not None:
            _digest("retest_digest", self.retest_digest)


@dataclass(frozen=True, slots=True)
class ContinuityResolution:
    plan_digest: str
    assessment_digest: str
    state: ContinuityResolutionState
    finding_resolutions: tuple[ContinuityFindingResolution, ...]
    unresolved_finding_digests: tuple[str, ...]
    evidence_history_digests: tuple[str, ...]

    def __post_init__(self) -> None:
        _digest("plan_digest", self.plan_digest)
        _digest("assessment_digest", self.assessment_digest)
        if not isinstance(self.state, ContinuityResolutionState):
            raise GovernanceError("continuity resolution state must use ContinuityResolutionState")
        for name, values in (
            ("unresolved_finding_digest", self.unresolved_finding_digests),
            ("evidence_history_digest", self.evidence_history_digests),
        ):
            for value in values:
                _digest(name, value)
            if tuple(values) != tuple(sorted(set(values))):
                raise GovernanceError(f"{name}s must be sorted and unique")

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class DependencyImpactSnapshot:
    entity_id: str
    inventory_snapshot_digest: str
    origin_nodes: tuple[NodeRef, ...]
    direction: DependencyTraversalDirection
    maximum_depth: int
    impacted_nodes: tuple[NodeRef, ...]
    traversed_edge_digests: tuple[str, ...]
    generated_at: int
    runtime_impact_determined: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "entity_id", _text("entity_id", self.entity_id))
        _digest("inventory_snapshot_digest", self.inventory_snapshot_digest)
        if not isinstance(self.direction, DependencyTraversalDirection):
            raise GovernanceError("dependency traversal direction must use DependencyTraversalDirection")
        _positive_int("maximum_depth", self.maximum_depth)
        origins = tuple(self.origin_nodes)
        impacts = tuple(self.impacted_nodes)
        if not origins:
            raise GovernanceError("dependency impact snapshot requires origin_nodes")
        if len(origins) != len(set(origins)) or len(impacts) != len(set(impacts)):
            raise GovernanceError("dependency impact node references must be unique")
        for ref in (*origins, *impacts):
            _validate_ref(ref, self.entity_id)
        if set(origins) & set(impacts):
            raise GovernanceError("dependency impact origins cannot also be impacted nodes")
        object.__setattr__(self, "origin_nodes", tuple(sorted(origins, key=_node_key)))
        object.__setattr__(self, "impacted_nodes", tuple(sorted(impacts, key=_node_key)))
        edge_digests = tuple(self.traversed_edge_digests)
        for value in edge_digests:
            _digest("traversed_edge_digest", value)
        if edge_digests != tuple(sorted(set(edge_digests))):
            raise GovernanceError("traversed_edge_digests must be sorted and unique")
        _timestamp("generated_at", self.generated_at)
        if self.runtime_impact_determined:
            raise GovernanceError("dependency topology traversal does not determine runtime impact")

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


def build_recovery_objective(
    registry: InventoryRegistry,
    *,
    entity_id: str,
    objective_id: str,
    target: NodeRef,
    owner_id: str,
    maximum_tolerable_disruption_seconds: int,
    recovery_time_objective_seconds: int,
    recovery_point_objective_seconds: int,
    minimum_service_level_basis_points: int,
    rationale: str,
    registered_at: int,
) -> RecoveryObjectiveProfile:
    _validate_ref(target, entity_id, recovery_target=True)
    registry.node(target)
    return RecoveryObjectiveProfile(
        entity_id=entity_id,
        objective_id=objective_id,
        target=target,
        inventory_snapshot_digest=registry.snapshot_digest(entity_id),
        owner_id=owner_id,
        maximum_tolerable_disruption_seconds=maximum_tolerable_disruption_seconds,
        recovery_time_objective_seconds=recovery_time_objective_seconds,
        recovery_point_objective_seconds=recovery_point_objective_seconds,
        minimum_service_level_basis_points=minimum_service_level_basis_points,
        rationale=rationale,
        registered_at=registered_at,
    )


def assert_recovery_objective_current(
    objective: RecoveryObjectiveProfile,
    registry: InventoryRegistry,
) -> None:
    registry.node(objective.target)
    if registry.snapshot_digest(objective.entity_id) != objective.inventory_snapshot_digest:
        raise GovernanceError("recovery objective is stale for current inventory/dependency topology")


def build_continuity_exercise_plan(
    registry: InventoryRegistry,
    objective: RecoveryObjectiveProfile,
    *,
    exercise_id: str,
    title: str,
    owner_id: str,
    independent_reviewer_id: str | None,
    scenario: str,
    activation_assumptions: Iterable[str],
    scope_nodes: Iterable[NodeRef],
    planned_at: int,
) -> ContinuityExercisePlan:
    assert_recovery_objective_current(objective, registry)
    scope = tuple(scope_nodes)
    for ref in scope:
        _validate_ref(ref, objective.entity_id)
        registry.node(ref)
    return ContinuityExercisePlan(
        entity_id=objective.entity_id,
        exercise_id=exercise_id,
        title=title,
        objective_digest=objective.evidence_digest,
        objective_target=objective.target,
        inventory_snapshot_digest=objective.inventory_snapshot_digest,
        owner_id=owner_id,
        independent_reviewer_id=independent_reviewer_id,
        scenario=scenario,
        activation_assumptions=tuple(activation_assumptions),
        scope_nodes=scope,
        planned_at=planned_at,
    )


def assert_continuity_plan_current(
    plan: ContinuityExercisePlan,
    objective: RecoveryObjectiveProfile,
    registry: InventoryRegistry,
) -> None:
    if plan.entity_id != objective.entity_id:
        raise GovernanceError("continuity plan and recovery objective are outside the same entity scope")
    if plan.objective_digest != objective.evidence_digest or plan.objective_target != objective.target:
        raise GovernanceError("continuity plan is stale for current recovery objective")
    assert_recovery_objective_current(objective, registry)
    current_inventory = registry.snapshot_digest(plan.entity_id)
    if plan.inventory_snapshot_digest != current_inventory:
        raise GovernanceError("continuity plan is stale for current inventory/dependency topology")
    for ref in plan.scope_nodes:
        registry.node(ref)


def record_continuity_execution(
    plan: ContinuityExercisePlan,
    objective: RecoveryObjectiveProfile,
    registry: InventoryRegistry,
    *,
    execution_id: str,
    started_at: int,
    completed_at: int,
    executor_id: str,
    evidence_digests: Iterable[str],
    notes: str,
) -> ContinuityExerciseExecution:
    assert_continuity_plan_current(plan, objective, registry)
    if started_at < plan.planned_at:
        raise GovernanceError("continuity exercise execution cannot predate its plan")
    return ContinuityExerciseExecution(
        plan_digest=plan.evidence_digest,
        execution_id=execution_id,
        started_at=started_at,
        completed_at=completed_at,
        executor_id=executor_id,
        evidence_digests=tuple(evidence_digests),
        notes=notes,
    )


def record_recovery_observation(
    plan: ContinuityExercisePlan,
    execution: ContinuityExerciseExecution,
    *,
    observation_id: str,
    observed_at: int,
    observer_id: str,
    restoration_time_seconds: int | None,
    recovery_point_loss_seconds: int | None,
    achieved_service_level_basis_points: int | None,
    evidence_digests: Iterable[str],
) -> RecoveryObservation:
    if execution.plan_digest != plan.evidence_digest:
        raise GovernanceError("continuity execution is bound to a different plan")
    if observed_at < execution.started_at:
        raise GovernanceError("recovery observation cannot predate exercise execution")
    return RecoveryObservation(
        plan_digest=plan.evidence_digest,
        execution_digest=execution.evidence_digest,
        observation_id=observation_id,
        observed_at=observed_at,
        observer_id=observer_id,
        restoration_time_seconds=restoration_time_seconds,
        recovery_point_loss_seconds=recovery_point_loss_seconds,
        achieved_service_level_basis_points=achieved_service_level_basis_points,
        evidence_digests=tuple(evidence_digests),
    )


def _metric(
    metric: RecoveryMetric,
    observed: int | None,
    threshold: int,
    *,
    lower_or_equal_is_met: bool,
) -> RecoveryMetricAssessment:
    if observed is None:
        return RecoveryMetricAssessment(
            metric=metric,
            state=RecoveryMetricState.INCOMPLETE,
            observed_value=None,
            threshold_value=threshold,
            reason="required recovery observation is missing",
        )
    met = observed <= threshold if lower_or_equal_is_met else observed >= threshold
    return RecoveryMetricAssessment(
        metric=metric,
        state=RecoveryMetricState.MET if met else RecoveryMetricState.BREACHED,
        observed_value=observed,
        threshold_value=threshold,
        reason="configured recovery objective satisfied" if met else "configured recovery objective breached",
    )


def assess_continuity_recovery(
    plan: ContinuityExercisePlan,
    objective: RecoveryObjectiveProfile,
    execution: ContinuityExerciseExecution,
    observations: Iterable[RecoveryObservation],
    registry: InventoryRegistry,
    *,
    assessed_at: int,
) -> ContinuityAssessment:
    assert_continuity_plan_current(plan, objective, registry)
    if execution.plan_digest != plan.evidence_digest:
        raise GovernanceError("continuity execution is bound to a different plan")
    assessed_at = _timestamp("assessed_at", assessed_at)
    if assessed_at < execution.completed_at:
        raise GovernanceError("continuity assessment cannot predate exercise completion")

    supplied = tuple(observations)
    for item in supplied:
        if item.plan_digest != plan.evidence_digest or item.execution_digest != execution.evidence_digest:
            raise GovernanceError("recovery observation is bound to a different plan/execution")
        if item.observed_at < execution.started_at:
            raise GovernanceError("recovery observation cannot predate exercise execution")
        if item.observed_at > assessed_at:
            raise GovernanceError("recovery observation cannot be from the future")

    observation: RecoveryObservation | None = None
    if supplied:
        latest_at = max(item.observed_at for item in supplied)
        latest = tuple(item for item in supplied if item.observed_at == latest_at)
        if len({item.evidence_digest for item in latest}) > 1:
            raise GovernanceError("conflicting latest recovery observations fail closed")
        observation = latest[0]

    restoration = observation.restoration_time_seconds if observation is not None else None
    recovery_point = observation.recovery_point_loss_seconds if observation is not None else None
    service_level = observation.achieved_service_level_basis_points if observation is not None else None
    metrics = (
        _metric(
            RecoveryMetric.MAXIMUM_TOLERABLE_DISRUPTION,
            restoration,
            objective.maximum_tolerable_disruption_seconds,
            lower_or_equal_is_met=True,
        ),
        _metric(
            RecoveryMetric.RECOVERY_TIME_OBJECTIVE,
            restoration,
            objective.recovery_time_objective_seconds,
            lower_or_equal_is_met=True,
        ),
        _metric(
            RecoveryMetric.RECOVERY_POINT_OBJECTIVE,
            recovery_point,
            objective.recovery_point_objective_seconds,
            lower_or_equal_is_met=True,
        ),
        _metric(
            RecoveryMetric.MINIMUM_SERVICE_LEVEL,
            service_level,
            objective.minimum_service_level_basis_points,
            lower_or_equal_is_met=False,
        ),
    )
    states = {item.state for item in metrics}
    gaps: list[str] = []
    for item in metrics:
        if item.state is RecoveryMetricState.INCOMPLETE:
            gaps.append(f"missing_metric:{item.metric.value}")
    if RecoveryMetricState.INCOMPLETE in states:
        state = RecoveryAssessmentState.INCOMPLETE
    elif RecoveryMetricState.BREACHED in states:
        state = RecoveryAssessmentState.BREACHED
    else:
        state = RecoveryAssessmentState.MET
    return ContinuityAssessment(
        entity_id=plan.entity_id,
        plan_digest=plan.evidence_digest,
        execution_digest=execution.evidence_digest,
        objective_digest=objective.evidence_digest,
        observation_digest=observation.evidence_digest if observation is not None else None,
        assessed_at=assessed_at,
        state=state,
        metric_assessments=metrics,
        gaps=tuple(sorted(gaps)),
    )


def create_continuity_finding(
    assessment: ContinuityAssessment,
    *,
    finding_id: str,
    severity: FindingSeverity,
    title: str,
    owner_id: str,
    identified_at: int,
    evidence_digest: str,
) -> ContinuityFinding:
    if assessment.state is RecoveryAssessmentState.MET:
        raise GovernanceError("met continuity assessment does not require a recovery finding")
    if identified_at < assessment.assessed_at:
        raise GovernanceError("continuity finding cannot predate recovery assessment")
    return ContinuityFinding(
        entity_id=assessment.entity_id,
        finding_id=finding_id,
        assessment_digest=assessment.evidence_digest,
        severity=severity,
        title=title,
        owner_id=owner_id,
        identified_at=identified_at,
        evidence_digest=evidence_digest,
    )


def create_continuity_remediation(
    finding: ContinuityFinding,
    *,
    remediation_id: str,
    owner_id: str,
    completed_at: int,
    summary: str,
    evidence_digest: str,
) -> ContinuityRemediationEvidence:
    if completed_at < finding.identified_at:
        raise GovernanceError("continuity remediation cannot complete before finding identification")
    return ContinuityRemediationEvidence(
        finding_digest=finding.governance_digest,
        remediation_id=remediation_id,
        owner_id=owner_id,
        completed_at=completed_at,
        summary=summary,
        evidence_digest=evidence_digest,
    )


def create_continuity_retest(
    plan: ContinuityExercisePlan,
    finding: ContinuityFinding,
    remediation: ContinuityRemediationEvidence,
    *,
    retest_id: str,
    reviewer_id: str,
    tested_at: int,
    outcome: RetestOutcome,
    notes: str,
    evidence_digest: str,
) -> ContinuityRetestEvidence:
    if remediation.finding_digest != finding.governance_digest:
        raise GovernanceError("continuity remediation is bound to a different finding")
    if tested_at < remediation.completed_at:
        raise GovernanceError("continuity retest cannot predate remediation completion")
    if outcome is RetestOutcome.PASSED:
        if plan.independent_reviewer_id is not None and reviewer_id != plan.independent_reviewer_id:
            raise GovernanceError("continuity finding closure requires configured independent reviewer")
        if finding.blocking and reviewer_id == remediation.owner_id:
            raise GovernanceError("blocking continuity finding requires independent remediation retest")
    return ContinuityRetestEvidence(
        finding_digest=finding.governance_digest,
        remediation_digest=remediation.governance_digest,
        retest_id=retest_id,
        reviewer_id=reviewer_id,
        tested_at=tested_at,
        outcome=outcome,
        notes=notes,
        evidence_digest=evidence_digest,
    )


def _latest_unique(items: tuple[object, ...], timestamp_attr: str, identity: str) -> object | None:
    if not items:
        return None
    latest_at = max(getattr(item, timestamp_attr) for item in items)
    candidates = tuple(item for item in items if getattr(item, timestamp_attr) == latest_at)
    if len({sha256_digest(item) for item in candidates}) > 1:
        raise GovernanceError(f"conflicting latest {identity} evidence fails closed")
    return candidates[0]


def resolve_continuity(
    plan: ContinuityExercisePlan,
    assessment: ContinuityAssessment,
    findings: Iterable[ContinuityFinding] = (),
    remediations: Iterable[ContinuityRemediationEvidence] = (),
    retests: Iterable[ContinuityRetestEvidence] = (),
) -> ContinuityResolution:
    if assessment.plan_digest != plan.evidence_digest:
        raise GovernanceError("continuity assessment is bound to a different plan")
    finding_list = tuple(sorted(findings, key=lambda item: item.finding_id))
    finding_ids = tuple(item.finding_id for item in finding_list)
    if len(finding_ids) != len(set(finding_ids)):
        raise GovernanceError("continuity findings must have unique finding_id values")
    if any(item.entity_id != plan.entity_id or item.assessment_digest != assessment.evidence_digest for item in finding_list):
        raise GovernanceError("continuity finding is bound to different assessment/entity evidence")
    if assessment.state is not RecoveryAssessmentState.MET and not finding_list:
        state = (
            ContinuityResolutionState.INCOMPLETE
            if assessment.state is RecoveryAssessmentState.INCOMPLETE
            else ContinuityResolutionState.BLOCKED
        )
        return ContinuityResolution(
            plan_digest=plan.evidence_digest,
            assessment_digest=assessment.evidence_digest,
            state=state,
            finding_resolutions=(),
            unresolved_finding_digests=(),
            evidence_history_digests=(),
        )

    finding_by_digest = {item.governance_digest: item for item in finding_list}
    remediation_list = tuple(remediations)
    retest_list = tuple(retests)
    for item in remediation_list:
        if item.finding_digest not in finding_by_digest:
            raise GovernanceError("continuity remediation references unknown finding")
    remediation_by_digest = {item.governance_digest: item for item in remediation_list}
    for item in retest_list:
        finding = finding_by_digest.get(item.finding_digest)
        remediation = remediation_by_digest.get(item.remediation_digest)
        if finding is None or remediation is None or remediation.finding_digest != item.finding_digest:
            raise GovernanceError("continuity retest references unknown or mismatched lifecycle evidence")

    resolutions: list[ContinuityFindingResolution] = []
    unresolved: list[str] = []
    for finding in finding_list:
        finding_digest = finding.governance_digest
        related_remediations = tuple(item for item in remediation_list if item.finding_digest == finding_digest)
        remediation = _latest_unique(related_remediations, "completed_at", "continuity remediation")
        if remediation is None:
            status = ContinuityFindingStatus.OPEN
            remediation_digest = None
            retest_digest = None
        else:
            remediation_digest = remediation.governance_digest
            related_retests = tuple(
                item
                for item in retest_list
                if item.finding_digest == finding_digest and item.remediation_digest == remediation_digest
            )
            retest = _latest_unique(related_retests, "tested_at", "continuity retest")
            if retest is None:
                status = ContinuityFindingStatus.REMEDIATION_SUBMITTED
                retest_digest = None
            else:
                retest_digest = retest.governance_digest
                if retest.outcome is RetestOutcome.PASSED:
                    if plan.independent_reviewer_id is not None and retest.reviewer_id != plan.independent_reviewer_id:
                        raise GovernanceError("continuity finding closure requires configured independent reviewer")
                    if finding.blocking and retest.reviewer_id == remediation.owner_id:
                        raise GovernanceError("blocking continuity finding requires independent remediation retest")
                    status = ContinuityFindingStatus.CLOSED
                else:
                    status = ContinuityFindingStatus.RETEST_FAILED
        if status is not ContinuityFindingStatus.CLOSED:
            unresolved.append(finding_digest)
        resolutions.append(
            ContinuityFindingResolution(
                finding_digest=finding_digest,
                status=status,
                blocking=finding.blocking,
                remediation_digest=remediation_digest,
                retest_digest=retest_digest,
            )
        )

    if unresolved:
        if assessment.state is RecoveryAssessmentState.INCOMPLETE:
            state = ContinuityResolutionState.INCOMPLETE
        else:
            state = ContinuityResolutionState.BLOCKED
    elif finding_list:
        state = ContinuityResolutionState.SUCCESSFUL_WITH_FINDINGS
    else:
        state = ContinuityResolutionState.SUCCESSFUL
    history = tuple(
        sorted(
            {item.governance_digest for item in finding_list}
            | {item.governance_digest for item in remediation_list}
            | {item.governance_digest for item in retest_list}
        )
    )
    return ContinuityResolution(
        plan_digest=plan.evidence_digest,
        assessment_digest=assessment.evidence_digest,
        state=state,
        finding_resolutions=tuple(resolutions),
        unresolved_finding_digests=tuple(sorted(unresolved)),
        evidence_history_digests=history,
    )


def build_dependency_impact_snapshot(
    registry: InventoryRegistry,
    *,
    entity_id: str,
    origin_nodes: Iterable[NodeRef],
    direction: DependencyTraversalDirection,
    maximum_depth: int,
    generated_at: int,
) -> DependencyImpactSnapshot:
    if not isinstance(direction, DependencyTraversalDirection):
        raise GovernanceError("dependency traversal direction must use DependencyTraversalDirection")
    maximum_depth = _positive_int("maximum_depth", maximum_depth)
    origins = tuple(origin_nodes)
    if not origins or len(origins) != len(set(origins)):
        raise GovernanceError("dependency impact origin_nodes must be non-empty and unique")
    for ref in origins:
        _validate_ref(ref, entity_id)
        registry.node(ref)

    edges = registry.edges(entity_id)
    seen = set(origins)
    frontier = set(origins)
    traversed: set[str] = set()
    for _ in range(maximum_depth):
        next_frontier: set[NodeRef] = set()
        for edge in edges:
            candidates: list[NodeRef] = []
            if direction in {DependencyTraversalDirection.OUTBOUND, DependencyTraversalDirection.BOTH} and edge.source in frontier:
                candidates.append(edge.target)
            if direction in {DependencyTraversalDirection.INBOUND, DependencyTraversalDirection.BOTH} and edge.target in frontier:
                candidates.append(edge.source)
            if candidates:
                traversed.add(edge.evidence_digest)
            for candidate in candidates:
                if candidate not in seen:
                    seen.add(candidate)
                    next_frontier.add(candidate)
        if not next_frontier:
            break
        frontier = next_frontier

    impacted = tuple(sorted(seen - set(origins), key=_node_key))
    return DependencyImpactSnapshot(
        entity_id=entity_id,
        inventory_snapshot_digest=registry.snapshot_digest(entity_id),
        origin_nodes=tuple(origins),
        direction=direction,
        maximum_depth=maximum_depth,
        impacted_nodes=impacted,
        traversed_edge_digests=tuple(sorted(traversed)),
        generated_at=generated_at,
    )


def assert_dependency_impact_current(
    snapshot: DependencyImpactSnapshot,
    registry: InventoryRegistry,
) -> None:
    expected = build_dependency_impact_snapshot(
        registry,
        entity_id=snapshot.entity_id,
        origin_nodes=snapshot.origin_nodes,
        direction=snapshot.direction,
        maximum_depth=snapshot.maximum_depth,
        generated_at=snapshot.generated_at,
    )
    if expected.evidence_digest != snapshot.evidence_digest:
        raise GovernanceError("dependency impact snapshot is stale for current topology")
