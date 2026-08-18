from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable

from .canonical import sha256_digest
from .inventory import GovernanceError, InventoryRegistry, NodeRef
from .risk import ICTRiskDecision


class ResilienceTestType(str, Enum):
    SCENARIO_BASED = "scenario_based"
    VULNERABILITY_ASSESSMENT = "vulnerability_assessment"
    NETWORK_SECURITY_ASSESSMENT = "network_security_assessment"
    PENETRATION_TEST = "penetration_test"
    SOURCE_CODE_REVIEW = "source_code_review"
    PHYSICAL_SECURITY_REVIEW = "physical_security_review"
    PERFORMANCE_TEST = "performance_test"
    END_TO_END_TEST = "end_to_end_test"
    THREAT_LED_PENETRATION_TEST = "threat_led_penetration_test"
    OTHER = "other"


class TestExecutionOutcome(str, Enum):
    PASSED = "passed"
    PASSED_WITH_FINDINGS = "passed_with_findings"
    FAILED = "failed"
    INCOMPLETE = "incomplete"


class FindingSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingStatus(str, Enum):
    OPEN = "open"
    REMEDIATION_SUBMITTED = "remediation_submitted"
    RETEST_FAILED = "retest_failed"
    CLOSED = "closed"


class RetestOutcome(str, Enum):
    PASSED = "passed"
    FAILED = "failed"


class TestResolutionState(str, Enum):
    SUCCESSFUL = "successful"
    SUCCESSFUL_WITH_FINDINGS = "successful_with_findings"
    BLOCKED = "blocked"
    INCOMPLETE = "incomplete"


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


@dataclass(frozen=True, slots=True)
class ResilienceTestPlan:
    entity_id: str
    test_id: str
    title: str
    test_type: ResilienceTestType
    objective: str
    test_owner_id: str
    independent_reviewer_id: str | None
    inventory_snapshot_digest: str
    risk_decision_digests: tuple[str, ...]
    scope_nodes: tuple[NodeRef, ...]
    scenario: str
    planned_at: int
    tlpt_qualification_evidence_digest: str | None = None

    def __post_init__(self) -> None:
        for name in ("entity_id", "test_id", "title", "objective", "test_owner_id", "scenario"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        if self.independent_reviewer_id is not None:
            object.__setattr__(
                self,
                "independent_reviewer_id",
                _text("independent_reviewer_id", self.independent_reviewer_id),
            )
            if self.independent_reviewer_id == self.test_owner_id:
                raise GovernanceError("independent reviewer must differ from test owner")
        _digest("inventory_snapshot_digest", self.inventory_snapshot_digest)
        if not self.risk_decision_digests:
            raise GovernanceError("resilience test plan must bind at least one ICT risk decision")
        for value in self.risk_decision_digests:
            _digest("risk_decision_digest", value)
        if len(self.risk_decision_digests) != len(set(self.risk_decision_digests)):
            raise GovernanceError("risk_decision_digests must be unique")
        if not self.scope_nodes:
            raise GovernanceError("resilience test plan must define at least one scope node")
        if len(self.scope_nodes) != len(set(self.scope_nodes)):
            raise GovernanceError("resilience test scope_nodes must be unique")
        if any(ref.entity_id != self.entity_id for ref in self.scope_nodes):
            raise GovernanceError("resilience test scope must remain in the same entity")
        _timestamp("planned_at", self.planned_at)
        if self.test_type is ResilienceTestType.THREAT_LED_PENETRATION_TEST:
            if self.tlpt_qualification_evidence_digest is None:
                raise GovernanceError("TLPT representation requires qualification evidence")
            _digest(
                "tlpt_qualification_evidence_digest",
                self.tlpt_qualification_evidence_digest,
            )
        elif self.tlpt_qualification_evidence_digest is not None:
            raise GovernanceError("TLPT qualification evidence is only valid for TLPT test type")

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class ResilienceTestExecution:
    plan_digest: str
    execution_id: str
    executed_at: int
    executor_id: str
    outcome: TestExecutionOutcome
    evidence_digests: tuple[str, ...]
    notes: str

    def __post_init__(self) -> None:
        _digest("plan_digest", self.plan_digest)
        object.__setattr__(self, "execution_id", _text("execution_id", self.execution_id))
        object.__setattr__(self, "executor_id", _text("executor_id", self.executor_id))
        object.__setattr__(self, "notes", _text("notes", self.notes))
        _timestamp("executed_at", self.executed_at)
        if not self.evidence_digests:
            raise GovernanceError("test execution requires at least one evidence digest")
        for value in self.evidence_digests:
            _digest("execution evidence_digest", value)
        if len(self.evidence_digests) != len(set(self.evidence_digests)):
            raise GovernanceError("execution evidence_digests must be unique")

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class ResilienceFinding:
    plan_digest: str
    execution_digest: str
    finding_id: str
    severity: FindingSeverity
    title: str
    owner_id: str
    identified_at: int
    evidence_digest: str

    def __post_init__(self) -> None:
        _digest("plan_digest", self.plan_digest)
        _digest("execution_digest", self.execution_digest)
        for name in ("finding_id", "title", "owner_id"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        _timestamp("identified_at", self.identified_at)
        object.__setattr__(self, "evidence_digest", _digest("finding evidence_digest", self.evidence_digest))

    @property
    def governance_digest(self) -> str:
        return sha256_digest(self)

    @property
    def blocking(self) -> bool:
        return self.severity in {FindingSeverity.HIGH, FindingSeverity.CRITICAL}


@dataclass(frozen=True, slots=True)
class RemediationEvidence:
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
class RetestEvidence:
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
        object.__setattr__(self, "evidence_digest", _digest("retest evidence_digest", self.evidence_digest))

    @property
    def governance_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class FindingResolution:
    finding_digest: str
    status: FindingStatus
    blocking: bool
    remediation_digest: str | None
    retest_digest: str | None

    def __post_init__(self) -> None:
        _digest("finding_digest", self.finding_digest)
        if self.remediation_digest is not None:
            _digest("remediation_digest", self.remediation_digest)
        if self.retest_digest is not None:
            _digest("retest_digest", self.retest_digest)


@dataclass(frozen=True, slots=True)
class ResilienceTestResolution:
    plan_digest: str
    execution_digest: str
    state: TestResolutionState
    finding_resolutions: tuple[FindingResolution, ...]
    unresolved_finding_digests: tuple[str, ...]
    evidence_history_digests: tuple[str, ...]

    def __post_init__(self) -> None:
        _digest("plan_digest", self.plan_digest)
        _digest("execution_digest", self.execution_digest)
        for name, values in (
            ("unresolved_finding_digest", self.unresolved_finding_digests),
            ("evidence_history_digest", self.evidence_history_digests),
        ):
            for value in values:
                _digest(name, value)
            if len(values) != len(set(values)):
                raise GovernanceError(f"{name}s must be unique")

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


def _normalize_risks(
    risk_decisions: Iterable[ICTRiskDecision],
    entity_id: str,
    inventory_snapshot_digest: str,
) -> tuple[ICTRiskDecision, ...]:
    risks = tuple(sorted(risk_decisions, key=lambda item: (item.scenario_id, item.evidence_digest)))
    if not risks:
        raise GovernanceError("resilience testing requires at least one current ICT risk decision")
    if any(item.entity_id != entity_id for item in risks):
        raise GovernanceError("ICT risk decision is outside the resilience-test entity scope")
    if any(item.inventory_snapshot_digest != inventory_snapshot_digest for item in risks):
        raise GovernanceError("ICT risk decision is stale for current inventory snapshot")
    digests = tuple(item.evidence_digest for item in risks)
    if len(digests) != len(set(digests)):
        raise GovernanceError("ICT risk decisions must be unique")
    return risks


def build_resilience_test_plan(
    registry: InventoryRegistry,
    risk_decisions: Iterable[ICTRiskDecision],
    *,
    entity_id: str,
    test_id: str,
    title: str,
    test_type: ResilienceTestType,
    objective: str,
    test_owner_id: str,
    independent_reviewer_id: str | None,
    scope_nodes: Iterable[NodeRef],
    scenario: str,
    planned_at: int,
    tlpt_qualification_evidence_digest: str | None = None,
) -> ResilienceTestPlan:
    inventory_digest = registry.snapshot_digest(entity_id)
    risks = _normalize_risks(risk_decisions, entity_id, inventory_digest)
    scope = tuple(sorted(scope_nodes, key=lambda ref: (ref.kind.value, ref.node_id)))
    for ref in scope:
        registry.node(ref)
    return ResilienceTestPlan(
        entity_id=entity_id,
        test_id=test_id,
        title=title,
        test_type=test_type,
        objective=objective,
        test_owner_id=test_owner_id,
        independent_reviewer_id=independent_reviewer_id,
        inventory_snapshot_digest=inventory_digest,
        risk_decision_digests=tuple(item.evidence_digest for item in risks),
        scope_nodes=scope,
        scenario=scenario,
        planned_at=planned_at,
        tlpt_qualification_evidence_digest=tlpt_qualification_evidence_digest,
    )


def assert_test_plan_current(
    plan: ResilienceTestPlan,
    registry: InventoryRegistry,
    risk_decisions: Iterable[ICTRiskDecision],
) -> None:
    current_inventory = registry.snapshot_digest(plan.entity_id)
    if plan.inventory_snapshot_digest != current_inventory:
        raise GovernanceError("resilience test plan is stale for current inventory snapshot")
    risks = _normalize_risks(risk_decisions, plan.entity_id, current_inventory)
    if plan.risk_decision_digests != tuple(item.evidence_digest for item in risks):
        raise GovernanceError("resilience test plan is stale for current ICT risk decisions")
    for ref in plan.scope_nodes:
        registry.node(ref)


def record_test_execution(
    plan: ResilienceTestPlan,
    registry: InventoryRegistry,
    risk_decisions: Iterable[ICTRiskDecision],
    *,
    execution_id: str,
    executed_at: int,
    executor_id: str,
    outcome: TestExecutionOutcome,
    evidence_digests: Iterable[str],
    notes: str,
) -> ResilienceTestExecution:
    assert_test_plan_current(plan, registry, risk_decisions)
    executed_at = _timestamp("executed_at", executed_at)
    if executed_at < plan.planned_at:
        raise GovernanceError("test execution cannot precede the planned test timestamp")
    return ResilienceTestExecution(
        plan_digest=plan.evidence_digest,
        execution_id=execution_id,
        executed_at=executed_at,
        executor_id=executor_id,
        outcome=outcome,
        evidence_digests=tuple(sorted(evidence_digests)),
        notes=notes,
    )


def create_finding(
    plan: ResilienceTestPlan,
    execution: ResilienceTestExecution,
    *,
    finding_id: str,
    severity: FindingSeverity,
    title: str,
    owner_id: str,
    identified_at: int,
    evidence_digest: str,
) -> ResilienceFinding:
    if execution.plan_digest != plan.evidence_digest:
        raise GovernanceError("test execution is bound to a different plan")
    identified_at = _timestamp("identified_at", identified_at)
    if identified_at < execution.executed_at:
        raise GovernanceError("finding cannot precede the bound test execution")
    return ResilienceFinding(
        plan_digest=plan.evidence_digest,
        execution_digest=execution.evidence_digest,
        finding_id=finding_id,
        severity=severity,
        title=title,
        owner_id=owner_id,
        identified_at=identified_at,
        evidence_digest=evidence_digest,
    )


def create_remediation(
    finding: ResilienceFinding,
    *,
    remediation_id: str,
    owner_id: str,
    completed_at: int,
    summary: str,
    evidence_digest: str,
) -> RemediationEvidence:
    if completed_at < finding.identified_at:
        raise GovernanceError("remediation cannot complete before finding identification")
    return RemediationEvidence(
        finding_digest=finding.governance_digest,
        remediation_id=remediation_id,
        owner_id=owner_id,
        completed_at=completed_at,
        summary=summary,
        evidence_digest=evidence_digest,
    )


def create_retest(
    plan: ResilienceTestPlan,
    finding: ResilienceFinding,
    remediation: RemediationEvidence,
    *,
    retest_id: str,
    reviewer_id: str,
    tested_at: int,
    outcome: RetestOutcome,
    notes: str,
    evidence_digest: str,
) -> RetestEvidence:
    if remediation.finding_digest != finding.governance_digest:
        raise GovernanceError("remediation is bound to a different finding")
    if tested_at < remediation.completed_at:
        raise GovernanceError("retest cannot precede remediation completion")
    if (
        outcome is RetestOutcome.PASSED
        and plan.independent_reviewer_id is not None
        and reviewer_id != plan.independent_reviewer_id
    ):
        raise GovernanceError("finding closure requires the configured independent reviewer")
    return RetestEvidence(
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
    digests = {sha256_digest(item) for item in candidates}
    if len(digests) > 1:
        raise GovernanceError(f"conflicting latest {identity} evidence fails closed")
    return candidates[0]


def resolve_test(
    plan: ResilienceTestPlan,
    execution: ResilienceTestExecution,
    findings: Iterable[ResilienceFinding],
    remediations: Iterable[RemediationEvidence] = (),
    retests: Iterable[RetestEvidence] = (),
) -> ResilienceTestResolution:
    if execution.plan_digest != plan.evidence_digest:
        raise GovernanceError("test execution is bound to a different plan")

    finding_list = tuple(sorted(findings, key=lambda item: item.finding_id))
    if execution.outcome is TestExecutionOutcome.PASSED_WITH_FINDINGS and not finding_list:
        raise GovernanceError("passed_with_findings execution requires finding evidence")
    finding_ids = tuple(item.finding_id for item in finding_list)
    if len(finding_ids) != len(set(finding_ids)):
        raise GovernanceError("resilience findings must have unique finding_id values")
    if any(
        item.plan_digest != plan.evidence_digest
        or item.execution_digest != execution.evidence_digest
        for item in finding_list
    ):
        raise GovernanceError("finding is bound to a different plan or execution")

    finding_by_digest = {item.governance_digest: item for item in finding_list}
    remediation_list = tuple(remediations)
    retest_list = tuple(retests)
    for item in remediation_list:
        if item.finding_digest not in finding_by_digest:
            raise GovernanceError("remediation references an unknown finding")
    remediation_by_digest = {item.governance_digest: item for item in remediation_list}
    for item in retest_list:
        if item.finding_digest not in finding_by_digest:
            raise GovernanceError("retest references an unknown finding")
        remediation = remediation_by_digest.get(item.remediation_digest)
        if remediation is None or remediation.finding_digest != item.finding_digest:
            raise GovernanceError("retest references unknown or mismatched remediation evidence")

    resolutions: list[FindingResolution] = []
    unresolved: list[str] = []
    for finding in finding_list:
        finding_digest = finding.governance_digest
        related_remediations = tuple(
            item for item in remediation_list if item.finding_digest == finding_digest
        )
        remediation = _latest_unique(
            related_remediations,
            "completed_at",
            "remediation",
        )
        if remediation is None:
            status = FindingStatus.OPEN
            remediation_digest = None
            retest_digest = None
        else:
            remediation_digest = remediation.governance_digest
            related_retests = tuple(
                item
                for item in retest_list
                if item.finding_digest == finding_digest
                and item.remediation_digest == remediation_digest
            )
            retest = _latest_unique(related_retests, "tested_at", "retest")
            if retest is None:
                status = FindingStatus.REMEDIATION_SUBMITTED
                retest_digest = None
            else:
                retest_digest = retest.governance_digest
                if retest.outcome is RetestOutcome.PASSED:
                    if (
                        plan.independent_reviewer_id is not None
                        and retest.reviewer_id != plan.independent_reviewer_id
                    ):
                        raise GovernanceError(
                            "finding closure requires the configured independent reviewer"
                        )
                    status = FindingStatus.CLOSED
                else:
                    status = FindingStatus.RETEST_FAILED
        if status is not FindingStatus.CLOSED:
            unresolved.append(finding_digest)
        resolutions.append(
            FindingResolution(
                finding_digest=finding_digest,
                status=status,
                blocking=finding.blocking,
                remediation_digest=remediation_digest,
                retest_digest=retest_digest,
            )
        )

    blocking_unresolved = any(
        item.blocking and item.status is not FindingStatus.CLOSED for item in resolutions
    )
    if execution.outcome is TestExecutionOutcome.INCOMPLETE:
        state = TestResolutionState.INCOMPLETE
    elif execution.outcome is TestExecutionOutcome.FAILED or blocking_unresolved:
        state = TestResolutionState.BLOCKED
    elif finding_list:
        state = TestResolutionState.SUCCESSFUL_WITH_FINDINGS
    else:
        state = TestResolutionState.SUCCESSFUL

    history = tuple(
        sorted(
            {item.governance_digest for item in finding_list}
            | {item.governance_digest for item in remediation_list}
            | {item.governance_digest for item in retest_list}
        )
    )
    return ResilienceTestResolution(
        plan_digest=plan.evidence_digest,
        execution_digest=execution.evidence_digest,
        state=state,
        finding_resolutions=tuple(resolutions),
        unresolved_finding_digests=tuple(sorted(unresolved)),
        evidence_history_digests=history,
    )
