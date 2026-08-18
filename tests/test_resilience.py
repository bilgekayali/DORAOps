from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path

import jsonschema
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
    RetestOutcome,
    RiskTreatmentPlan,
    TestExecutionOutcome,
    TestResolutionState,
    TreatmentType,
    assess_ict_risk,
    build_resilience_test_plan,
    canonical_json,
    create_finding,
    create_remediation,
    create_retest,
    record_test_execution,
    resolve_test,
    sha256_digest,
)


def digest(seed: str) -> str:
    return sha256_digest({"seed": seed})


def governed_fixture():
    registry = InventoryRegistry()
    registry.register_entity(FinancialEntity("bank-a", "Bank A", "DE"))
    function = BusinessFunction(
        "bank-a",
        "payments",
        "Payments",
        FunctionClassification.CRITICAL_OR_IMPORTANT,
        "board-owner",
        "human classification",
    )
    service = ICTService("bank-a", "payment-api", "Payment API", "svc-owner", "application")
    registry.register_node(function)
    registry.register_node(service)
    refs = (
        NodeRef("bank-a", NodeKind.BUSINESS_FUNCTION, "payments"),
        NodeRef("bank-a", NodeKind.ICT_SERVICE, "payment-api"),
    )
    scenario = ICTRiskScenario(
        entity_id="bank-a",
        scenario_id="risk-1",
        title="Payment API outage",
        threat="service disruption",
        vulnerability="single processing path",
        risk_owner_id="risk-owner",
        affected_nodes=refs,
        likelihood=Likelihood.LIKELY,
        impact=Impact.SEVERE,
    )
    policy = ICTRiskPolicy("bank-a", "risk-policy", "1")
    treatment = RiskTreatmentPlan(
        TreatmentType.MITIGATE,
        "treatment-owner",
        "reduce outage exposure",
        target_timestamp=500,
    )
    risk = assess_ict_risk(registry, scenario, (), policy, treatment)
    return registry, refs, risk


def plan_fixture(*, reviewer: str | None = "independent-reviewer"):
    registry, refs, risk = governed_fixture()
    plan = build_resilience_test_plan(
        registry,
        (risk,),
        entity_id="bank-a",
        test_id="test-1",
        title="Payment resilience scenario",
        test_type=ResilienceTestType.SCENARIO_BASED,
        objective="Exercise payment service recovery controls",
        test_owner_id="test-owner",
        independent_reviewer_id=reviewer,
        scope_nodes=refs,
        scenario="Loss of the primary payment API path",
        planned_at=200,
    )
    return registry, refs, risk, plan


def execution_fixture():
    registry, refs, risk, plan = plan_fixture()
    execution = record_test_execution(
        plan,
        registry,
        (risk,),
        execution_id="exec-1",
        executed_at=300,
        executor_id="operator",
        outcome=TestExecutionOutcome.PASSED,
        evidence_digests=(digest("execution-log"),),
        notes="Scenario completed; findings are resolved separately.",
    )
    return registry, refs, risk, plan, execution


def test_plan_binds_exact_inventory_risk_and_scope_and_rejects_replay():
    registry, _, risk, plan = plan_fixture()
    assert plan.inventory_snapshot_digest == registry.snapshot_digest("bank-a")
    assert plan.risk_decision_digests == (risk.evidence_digest,)

    registry.register_node(ICTService("bank-a", "new-service", "New Service", "owner", "application"))
    with pytest.raises(GovernanceError, match="stale for current inventory"):
        record_test_execution(
            plan,
            registry,
            (risk,),
            execution_id="exec-stale",
            executed_at=301,
            executor_id="operator",
            outcome=TestExecutionOutcome.PASSED,
            evidence_digests=(digest("stale"),),
            notes="must fail closed",
        )


def test_plan_rejects_changed_risk_decision_and_dangling_scope():
    registry, refs, risk, _ = plan_fixture()
    changed_risk = replace(risk, residual_score=risk.residual_score + 1)
    with pytest.raises(GovernanceError, match="stale for current ICT risk decisions"):
        plan = build_resilience_test_plan(
            registry,
            (risk,),
            entity_id="bank-a",
            test_id="test-risk",
            title="Risk-bound test",
            test_type=ResilienceTestType.SCENARIO_BASED,
            objective="test",
            test_owner_id="owner",
            independent_reviewer_id=None,
            scope_nodes=refs,
            scenario="scenario",
            planned_at=200,
        )
        record_test_execution(
            plan,
            registry,
            (changed_risk,),
            execution_id="exec",
            executed_at=300,
            executor_id="operator",
            outcome=TestExecutionOutcome.PASSED,
            evidence_digests=(digest("exec"),),
            notes="changed risk must fail",
        )

    with pytest.raises(GovernanceError, match="unknown inventory node"):
        build_resilience_test_plan(
            registry,
            (risk,),
            entity_id="bank-a",
            test_id="test-dangling",
            title="Dangling",
            test_type=ResilienceTestType.SCENARIO_BASED,
            objective="test",
            test_owner_id="owner",
            independent_reviewer_id=None,
            scope_nodes=(NodeRef("bank-a", NodeKind.ICT_SERVICE, "missing"),),
            scenario="scenario",
            planned_at=200,
        )


def test_tlpt_representation_requires_explicit_qualification_evidence():
    registry, refs, risk = governed_fixture()
    with pytest.raises(GovernanceError, match="TLPT representation requires"):
        build_resilience_test_plan(
            registry,
            (risk,),
            entity_id="bank-a",
            test_id="tlpt-1",
            title="TLPT",
            test_type=ResilienceTestType.THREAT_LED_PENETRATION_TEST,
            objective="qualified workflow only",
            test_owner_id="owner",
            independent_reviewer_id="reviewer",
            scope_nodes=refs,
            scenario="threat-led scenario",
            planned_at=200,
        )


def test_blocking_finding_prevents_unconditional_success_until_retested():
    _, _, _, plan, execution = execution_fixture()
    finding = create_finding(
        plan,
        execution,
        finding_id="F-1",
        severity=FindingSeverity.CRITICAL,
        title="Recovery path failed",
        owner_id="remediation-owner",
        identified_at=310,
        evidence_digest=digest("finding"),
    )
    blocked = resolve_test(plan, execution, (finding,))
    assert blocked.state is TestResolutionState.BLOCKED
    assert blocked.unresolved_finding_digests == (finding.governance_digest,)

    remediation = create_remediation(
        finding,
        remediation_id="R-1",
        owner_id="remediation-owner",
        completed_at=350,
        summary="Recovery path corrected",
        evidence_digest=digest("remediation"),
    )
    with pytest.raises(GovernanceError, match="independent reviewer"):
        create_retest(
            plan,
            finding,
            remediation,
            retest_id="RT-wrong",
            reviewer_id="test-owner",
            tested_at=360,
            outcome=RetestOutcome.PASSED,
            notes="wrong reviewer",
            evidence_digest=digest("wrong-retest"),
        )

    failed_retest = create_retest(
        plan,
        finding,
        remediation,
        retest_id="RT-1",
        reviewer_id="independent-reviewer",
        tested_at=360,
        outcome=RetestOutcome.FAILED,
        notes="first retest still fails",
        evidence_digest=digest("failed-retest"),
    )
    still_blocked = resolve_test(plan, execution, (finding,), (remediation,), (failed_retest,))
    assert still_blocked.state is TestResolutionState.BLOCKED

    passed_retest = create_retest(
        plan,
        finding,
        remediation,
        retest_id="RT-2",
        reviewer_id="independent-reviewer",
        tested_at=370,
        outcome=RetestOutcome.PASSED,
        notes="independent retest passed",
        evidence_digest=digest("passed-retest"),
    )
    resolved = resolve_test(
        plan,
        execution,
        (finding,),
        (remediation,),
        (failed_retest, passed_retest),
    )
    assert resolved.state is TestResolutionState.SUCCESSFUL_WITH_FINDINGS
    assert resolved.unresolved_finding_digests == ()
    assert failed_retest.governance_digest in resolved.evidence_history_digests
    assert passed_retest.governance_digest in resolved.evidence_history_digests


def test_incomplete_execution_cannot_resolve_successfully():
    registry, _, risk, plan = plan_fixture()
    execution = record_test_execution(
        plan,
        registry,
        (risk,),
        execution_id="exec-incomplete",
        executed_at=300,
        executor_id="operator",
        outcome=TestExecutionOutcome.INCOMPLETE,
        evidence_digests=(digest("partial"),),
        notes="test interrupted",
    )
    assert resolve_test(plan, execution, ()).state is TestResolutionState.INCOMPLETE


def test_resilience_artifacts_validate_against_release_schemas():
    _, _, _, plan, execution = execution_fixture()
    finding = create_finding(
        plan,
        execution,
        finding_id="F-1",
        severity=FindingSeverity.HIGH,
        title="Recovery evidence gap",
        owner_id="owner",
        identified_at=310,
        evidence_digest=digest("finding-schema"),
    )
    remediation = create_remediation(
        finding,
        remediation_id="R-1",
        owner_id="owner",
        completed_at=350,
        summary="Gap remediated",
        evidence_digest=digest("remediation-schema"),
    )
    retest = create_retest(
        plan,
        finding,
        remediation,
        retest_id="RT-1",
        reviewer_id="independent-reviewer",
        tested_at=360,
        outcome=RetestOutcome.PASSED,
        notes="validated",
        evidence_digest=digest("retest-schema"),
    )
    resolution = resolve_test(plan, execution, (finding,), (remediation,), (retest,))

    root = Path(__file__).resolve().parents[1]
    cases = (
        ("resilience-test-plan.schema.json", plan),
        ("resilience-test-execution.schema.json", execution),
        ("resilience-finding.schema.json", finding),
        ("resilience-remediation.schema.json", remediation),
        ("resilience-retest.schema.json", retest),
        ("resilience-test-resolution.schema.json", resolution),
    )
    for schema_name, artifact in cases:
        schema = json.loads((root / "schemas" / schema_name).read_text())
        payload = json.loads(canonical_json(artifact))
        jsonschema.Draft202012Validator(schema).validate(payload)
