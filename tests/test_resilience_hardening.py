from __future__ import annotations

import pytest

from doraops import (
    BusinessFunction,
    FinancialEntity,
    FindingSeverity,
    FunctionClassification,
    GovernanceError,
    ICTRiskPolicy,
    ICTRiskScenario,
    ICTService,
    Impact,
    InventoryRegistry,
    Likelihood,
    NodeKind,
    NodeRef,
    ResilienceTestType,
    RiskTreatmentPlan,
    TestExecutionOutcome,
    TreatmentType,
    assess_ict_risk,
    build_resilience_test_plan,
    create_finding,
    record_test_execution,
    resolve_test,
    sha256_digest,
)


def digest(seed: str) -> str:
    return sha256_digest({"seed": seed})


def fixture():
    registry = InventoryRegistry()
    registry.register_entity(FinancialEntity("bank-a", "Bank A", "DE"))
    function = BusinessFunction(
        "bank-a",
        "payments",
        "Payments",
        FunctionClassification.CRITICAL_OR_IMPORTANT,
        "board-owner",
        "human decision",
    )
    service = ICTService("bank-a", "api", "Payment API", "svc-owner", "application")
    registry.register_node(function)
    registry.register_node(service)
    refs = (
        NodeRef("bank-a", NodeKind.BUSINESS_FUNCTION, "payments"),
        NodeRef("bank-a", NodeKind.ICT_SERVICE, "api"),
    )
    scenario = ICTRiskScenario(
        entity_id="bank-a",
        scenario_id="risk-1",
        title="Outage",
        threat="disruption",
        vulnerability="single path",
        risk_owner_id="risk-owner",
        affected_nodes=refs,
        likelihood=Likelihood.LIKELY,
        impact=Impact.SEVERE,
    )
    risk = assess_ict_risk(
        registry,
        scenario,
        (),
        ICTRiskPolicy("bank-a", "policy", "1"),
        RiskTreatmentPlan(
            TreatmentType.MITIGATE,
            "owner",
            "mitigate",
            target_timestamp=500,
        ),
    )
    plan = build_resilience_test_plan(
        registry,
        (risk,),
        entity_id="bank-a",
        test_id="test-1",
        title="Resilience test",
        test_type=ResilienceTestType.SCENARIO_BASED,
        objective="exercise controls",
        test_owner_id="test-owner",
        independent_reviewer_id=None,
        scope_nodes=refs,
        scenario="loss of primary path",
        planned_at=200,
    )
    return registry, risk, plan


def test_execution_and_finding_timestamps_fail_closed():
    registry, risk, plan = fixture()
    with pytest.raises(GovernanceError, match="cannot precede the planned"):
        record_test_execution(
            plan,
            registry,
            (risk,),
            execution_id="early",
            executed_at=199,
            executor_id="operator",
            outcome=TestExecutionOutcome.PASSED,
            evidence_digests=(digest("early"),),
            notes="too early",
        )

    execution = record_test_execution(
        plan,
        registry,
        (risk,),
        execution_id="exec",
        executed_at=300,
        executor_id="operator",
        outcome=TestExecutionOutcome.PASSED,
        evidence_digests=(digest("exec"),),
        notes="completed",
    )
    with pytest.raises(GovernanceError, match="cannot precede the bound test execution"):
        create_finding(
            plan,
            execution,
            finding_id="F-early",
            severity=FindingSeverity.HIGH,
            title="Impossible early finding",
            owner_id="owner",
            identified_at=299,
            evidence_digest=digest("finding"),
        )


def test_passed_with_findings_requires_actual_finding_evidence():
    registry, risk, plan = fixture()
    execution = record_test_execution(
        plan,
        registry,
        (risk,),
        execution_id="exec-findings",
        executed_at=300,
        executor_id="operator",
        outcome=TestExecutionOutcome.PASSED_WITH_FINDINGS,
        evidence_digests=(digest("exec-findings"),),
        notes="declared findings",
    )
    with pytest.raises(GovernanceError, match="requires finding evidence"):
        resolve_test(plan, execution, ())
