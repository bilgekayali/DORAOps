from dataclasses import replace

import pytest

from doraops import (
    BusinessFunction,
    ControlEffectiveness,
    FinancialEntity,
    FunctionClassification,
    GovernanceError,
    ICTControlObservation,
    ICTRiskPolicy,
    ICTRiskScenario,
    ICTService,
    Impact,
    InventoryRegistry,
    Likelihood,
    NodeKind,
    NodeRef,
    RiskLevel,
    RiskTreatmentPlan,
    TreatmentType,
    assess_ict_risk,
    assert_risk_decision_current,
)


D1 = "1" * 64
D2 = "2" * 64
D3 = "3" * 64


def registry() -> InventoryRegistry:
    value = InventoryRegistry()
    value.register_entity(FinancialEntity("bank-a", "Bank A", "TR"))
    value.register_node(
        BusinessFunction(
            "bank-a",
            "payments",
            "Payment Processing",
            FunctionClassification.CRITICAL_OR_IMPORTANT,
            "operational-risk",
            "Material customer and settlement impact if disrupted",
        )
    )
    value.register_node(
        ICTService(
            "bank-a",
            "payments-api",
            "Payments API",
            "payments-platform",
            "application_service",
        )
    )
    return value


def scenario(
    *,
    likelihood: Likelihood = Likelihood.ALMOST_CERTAIN,
    impact: Impact = Impact.CRITICAL,
) -> ICTRiskScenario:
    return ICTRiskScenario(
        entity_id="bank-a",
        scenario_id="payments-outage",
        title="Payment processing outage",
        threat="Critical platform outage",
        vulnerability="Insufficient failover capacity",
        risk_owner_id="operational-risk",
        affected_nodes=(
            NodeRef("bank-a", NodeKind.BUSINESS_FUNCTION, "payments"),
            NodeRef("bank-a", NodeKind.ICT_SERVICE, "payments-api"),
        ),
        likelihood=likelihood,
        impact=impact,
    )


def controls() -> tuple[ICTControlObservation, ...]:
    return (
        ICTControlObservation(
            "bank-a",
            "active-active",
            "Active-active deployment",
            "availability",
            ControlEffectiveness.ADEQUATE,
            D1,
        ),
        ICTControlObservation(
            "bank-a",
            "failover-test",
            "Periodic failover testing",
            "resilience_testing",
            ControlEffectiveness.LIMITED,
            D2,
        ),
    )


def mitigation() -> RiskTreatmentPlan:
    return RiskTreatmentPlan(
        TreatmentType.MITIGATE,
        "technology-risk-owner",
        "Increase failover capacity and test recovery",
        target_timestamp=1_800_000_000,
    )


def test_identical_inputs_produce_identical_decision_independent_of_control_order() -> None:
    inventory = registry()
    policy = ICTRiskPolicy("bank-a", "ict-risk", "1")
    first = assess_ict_risk(inventory, scenario(), controls(), policy, mitigation())
    second = assess_ict_risk(inventory, scenario(), reversed(controls()), policy, mitigation())
    assert first == second
    assert first.evidence_digest == second.evidence_digest


def test_critical_inherent_risk_and_bounded_control_credit() -> None:
    decision = assess_ict_risk(
        registry(),
        scenario(),
        controls(),
        ICTRiskPolicy("bank-a", "ict-risk", "1", max_control_credit=2),
        mitigation(),
    )
    assert decision.inherent_score == 16
    assert decision.inherent_level is RiskLevel.CRITICAL
    assert decision.control_credit == 2
    assert decision.residual_score == 14
    assert decision.residual_level is RiskLevel.CRITICAL
    assert decision.remediation_required is True


def test_high_residual_risk_acceptance_is_explicitly_flagged() -> None:
    treatment = RiskTreatmentPlan(
        TreatmentType.ACCEPT,
        "operational-risk",
        "Temporary accountable risk acceptance pending strategic remediation",
    )
    decision = assess_ict_risk(
        registry(),
        scenario(likelihood=Likelihood.LIKELY, impact=Impact.CRITICAL),
        (),
        ICTRiskPolicy("bank-a", "ict-risk", "1"),
        treatment,
    )
    assert decision.residual_level is RiskLevel.HIGH
    assert decision.risk_acceptance_required is True
    assert decision.remediation_required is False


def test_mitigation_requires_target_timestamp() -> None:
    with pytest.raises(GovernanceError, match="requires target_timestamp"):
        RiskTreatmentPlan(
            TreatmentType.MITIGATE,
            "technology-risk-owner",
            "Mitigate material risk",
        )


def test_missing_inventory_node_fails_closed() -> None:
    missing = ICTRiskScenario(
        entity_id="bank-a",
        scenario_id="missing-node",
        title="Unknown dependency risk",
        threat="Outage",
        vulnerability="Unknown dependency",
        risk_owner_id="risk-owner",
        affected_nodes=(NodeRef("bank-a", NodeKind.ICT_SERVICE, "unknown"),),
        likelihood=Likelihood.POSSIBLE,
        impact=Impact.MATERIAL,
    )
    with pytest.raises(GovernanceError, match="unknown inventory node"):
        assess_ict_risk(
            registry(),
            missing,
            (),
            ICTRiskPolicy("bank-a", "ict-risk", "1"),
            RiskTreatmentPlan(TreatmentType.ACCEPT, "risk-owner", "Low exposure acceptance"),
        )


def test_cross_entity_control_is_rejected() -> None:
    bad_control = ICTControlObservation(
        "bank-b",
        "foreign-control",
        "Foreign Control",
        "preventive",
        ControlEffectiveness.STRONG,
        D3,
    )
    with pytest.raises(GovernanceError, match="outside the scenario entity"):
        assess_ict_risk(
            registry(),
            scenario(),
            (bad_control,),
            ICTRiskPolicy("bank-a", "ict-risk", "1"),
            mitigation(),
        )


def test_inventory_change_invalidates_existing_risk_decision() -> None:
    inventory = registry()
    current_scenario = scenario()
    current_controls = controls()
    policy = ICTRiskPolicy("bank-a", "ict-risk", "1")
    decision = assess_ict_risk(inventory, current_scenario, current_controls, policy, mitigation())
    assert_risk_decision_current(decision, inventory, current_scenario, current_controls, policy)

    inventory.register_node(
        ICTService(
            "bank-a",
            "new-critical-dependency",
            "New Critical Dependency",
            "platform-owner",
            "infrastructure_service",
        )
    )
    with pytest.raises(GovernanceError, match="stale for current inventory"):
        assert_risk_decision_current(decision, inventory, current_scenario, current_controls, policy)


def test_control_evidence_change_invalidates_existing_risk_decision() -> None:
    inventory = registry()
    current_scenario = scenario()
    current_controls = controls()
    policy = ICTRiskPolicy("bank-a", "ict-risk", "1")
    decision = assess_ict_risk(inventory, current_scenario, current_controls, policy, mitigation())
    changed_controls = (
        replace(current_controls[0], evidence_digest="a" * 64),
        current_controls[1],
    )
    with pytest.raises(GovernanceError, match="stale for current control evidence"):
        assert_risk_decision_current(decision, inventory, current_scenario, changed_controls, policy)


def test_policy_change_invalidates_existing_risk_decision() -> None:
    inventory = registry()
    current_scenario = scenario()
    current_controls = controls()
    policy = ICTRiskPolicy("bank-a", "ict-risk", "1")
    decision = assess_ict_risk(inventory, current_scenario, current_controls, policy, mitigation())
    changed_policy = ICTRiskPolicy("bank-a", "ict-risk", "2")
    with pytest.raises(GovernanceError, match="stale for current risk policy"):
        assert_risk_decision_current(
            decision,
            inventory,
            current_scenario,
            current_controls,
            changed_policy,
        )
