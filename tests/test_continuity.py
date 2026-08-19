from __future__ import annotations

from dataclasses import replace

import pytest

from doraops import (
    ContinuityResolutionState,
    DependencyEdge,
    DependencyRelationship,
    DependencyTraversalDirection,
    FindingSeverity,
    GovernanceError,
    ICTAsset,
    NodeKind,
    NodeRef,
    RecoveryAssessmentState,
    RetestOutcome,
    assert_continuity_plan_current,
    assert_dependency_impact_current,
    assert_recovery_objective_current,
    assess_continuity_recovery,
    build_continuity_exercise_plan,
    build_dependency_impact_snapshot,
    build_recovery_objective,
    create_continuity_finding,
    create_continuity_remediation,
    create_continuity_retest,
    record_continuity_execution,
    record_recovery_observation,
    resolve_continuity,
)
from tests.test_inventory import build_registry


D1 = "1" * 64
D2 = "2" * 64
D3 = "3" * 64
D4 = "4" * 64
D5 = "5" * 64


def continuity_registry():
    registry = build_registry()
    function = NodeRef("bank-a", NodeKind.BUSINESS_FUNCTION, "payments")
    process = NodeRef("bank-a", NodeKind.BUSINESS_PROCESS, "payment-processing")
    service = NodeRef("bank-a", NodeKind.ICT_SERVICE, "payments-api")
    asset = NodeRef("bank-a", NodeKind.ICT_ASSET, "payments-cluster")
    registry.register_edge(
        DependencyEdge(
            "bank-a",
            "function-process",
            function,
            process,
            DependencyRelationship.SUPPORTED_BY,
            "Payments function uses the payment-processing process",
        )
    )
    registry.register_edge(
        DependencyEdge(
            "bank-a",
            "process-service",
            process,
            service,
            DependencyRelationship.SUPPORTED_BY,
            "Payment processing uses the Payments API",
        )
    )
    registry.register_edge(
        DependencyEdge(
            "bank-a",
            "service-asset",
            service,
            asset,
            DependencyRelationship.HOSTED_ON,
            "Payments API is hosted on the payments cluster",
        )
    )
    return registry, function, process, service, asset


def continuity_fixture(*, independent_reviewer_id: str | None = "continuity-reviewer"):
    registry, function, process, service, asset = continuity_registry()
    objective = build_recovery_objective(
        registry,
        entity_id="bank-a",
        objective_id="payments-recovery",
        target=function,
        owner_id="payments-owner",
        maximum_tolerable_disruption_seconds=600,
        recovery_time_objective_seconds=300,
        recovery_point_objective_seconds=60,
        minimum_service_level_basis_points=8000,
        rationale="Institution-owned recovery objectives for payment processing",
        registered_at=100,
    )
    plan = build_continuity_exercise_plan(
        registry,
        objective,
        exercise_id="continuity-1",
        title="Payments regional outage recovery exercise",
        owner_id="continuity-owner",
        independent_reviewer_id=independent_reviewer_id,
        scenario="Primary processing region becomes unavailable",
        activation_assumptions=("secondary region available", "backup copy accessible"),
        scope_nodes=(function, process, service, asset),
        planned_at=120,
    )
    execution = record_continuity_execution(
        plan,
        objective,
        registry,
        execution_id="execution-1",
        started_at=150,
        completed_at=220,
        executor_id="dr-operator",
        evidence_digests=(D1, D2),
        notes="Recovery exercise completed and recovery evidence collected",
    )
    return registry, function, process, service, asset, objective, plan, execution


def observation(plan, execution, *, observation_id="obs-1", observed_at=225, restoration=240, rpo=30, service=9000, evidence=D3):
    return record_recovery_observation(
        plan,
        execution,
        observation_id=observation_id,
        observed_at=observed_at,
        observer_id="recovery-observer",
        restoration_time_seconds=restoration,
        recovery_point_loss_seconds=rpo,
        achieved_service_level_basis_points=service,
        evidence_digests=(evidence,),
    )


def test_recovery_assessment_met_breached_incomplete_and_conflicting_latest() -> None:
    registry, *_, objective, plan, execution = continuity_fixture()
    healthy_observation = observation(plan, execution)
    healthy = assess_continuity_recovery(
        plan,
        objective,
        execution,
        (healthy_observation,),
        registry,
        assessed_at=230,
    )
    assert healthy.state is RecoveryAssessmentState.MET
    assert healthy.operational_resilience_determined is False
    assert healthy.regulatory_compliance_determined is False

    breached_observation = observation(
        plan,
        execution,
        observation_id="obs-breach",
        restoration=420,
        rpo=90,
        service=7000,
        evidence=D4,
    )
    breached = assess_continuity_recovery(
        plan,
        objective,
        execution,
        (breached_observation,),
        registry,
        assessed_at=230,
    )
    assert breached.state is RecoveryAssessmentState.BREACHED

    incomplete_observation = observation(
        plan,
        execution,
        observation_id="obs-incomplete",
        rpo=None,
        evidence=D5,
    )
    incomplete = assess_continuity_recovery(
        plan,
        objective,
        execution,
        (incomplete_observation,),
        registry,
        assessed_at=230,
    )
    assert incomplete.state is RecoveryAssessmentState.INCOMPLETE
    assert "missing_metric:recovery_point_objective" in incomplete.gaps

    conflicting = replace(
        healthy_observation,
        observation_id="obs-conflict",
        restoration_time_seconds=500,
        evidence_digests=(D5,),
    )
    with pytest.raises(GovernanceError, match="conflicting latest recovery observations"):
        assess_continuity_recovery(
            plan,
            objective,
            execution,
            (healthy_observation, conflicting),
            registry,
            assessed_at=230,
        )


def test_recovery_objective_rejects_incoherent_or_non_service_targets_and_bool_numbers() -> None:
    registry, function, *_ = continuity_registry()
    with pytest.raises(GovernanceError, match="cannot exceed maximum tolerable disruption"):
        build_recovery_objective(
            registry,
            entity_id="bank-a",
            objective_id="bad-rto",
            target=function,
            owner_id="owner",
            maximum_tolerable_disruption_seconds=300,
            recovery_time_objective_seconds=600,
            recovery_point_objective_seconds=60,
            minimum_service_level_basis_points=8000,
            rationale="invalid objective ordering",
            registered_at=1,
        )
    with pytest.raises(GovernanceError, match="business function, process or ICT service"):
        build_recovery_objective(
            registry,
            entity_id="bank-a",
            objective_id="bad-target",
            target=NodeRef("bank-a", NodeKind.INFORMATION_ASSET, "payment-ledger-data"),
            owner_id="owner",
            maximum_tolerable_disruption_seconds=600,
            recovery_time_objective_seconds=300,
            recovery_point_objective_seconds=60,
            minimum_service_level_basis_points=8000,
            rationale="invalid recovery target",
            registered_at=1,
        )
    with pytest.raises(GovernanceError, match="positive integer"):
        build_recovery_objective(
            registry,
            entity_id="bank-a",
            objective_id="bad-bool",
            target=function,
            owner_id="owner",
            maximum_tolerable_disruption_seconds=True,
            recovery_time_objective_seconds=1,
            recovery_point_objective_seconds=0,
            minimum_service_level_basis_points=8000,
            rationale="bool must not pass as integer",
            registered_at=1,
        )


def test_objective_and_plan_fail_closed_after_topology_change() -> None:
    registry, *_, objective, plan, _ = continuity_fixture()
    registry.register_node(
        ICTAsset(
            entity_id="bank-a",
            asset_id="new-recovery-component",
            name="New Recovery Component",
            owner_id="platform-owner",
            asset_type="compute",
        )
    )
    with pytest.raises(GovernanceError, match="stale for current inventory/dependency topology"):
        assert_recovery_objective_current(objective, registry)
    with pytest.raises(GovernanceError, match="stale"):
        assert_continuity_plan_current(plan, objective, registry)


def test_dependency_impact_snapshot_walks_modeled_topology_and_becomes_stale() -> None:
    registry, function, process, service, asset, *_ = continuity_fixture()
    snapshot = build_dependency_impact_snapshot(
        registry,
        entity_id="bank-a",
        origin_nodes=(function,),
        direction=DependencyTraversalDirection.OUTBOUND,
        maximum_depth=3,
        generated_at=250,
    )
    expected = tuple(sorted((process, service, asset), key=lambda ref: (ref.kind.value, ref.node_id)))
    assert snapshot.impacted_nodes == expected
    assert snapshot.runtime_impact_determined is False
    assert_dependency_impact_current(snapshot, registry)

    new_asset = ICTAsset(
        entity_id="bank-a",
        asset_id="downstream-recovery-node",
        name="Downstream Recovery Node",
        owner_id="platform-owner",
        asset_type="compute",
    )
    registry.register_node(new_asset)
    registry.register_edge(
        DependencyEdge(
            "bank-a",
            "asset-new-asset",
            asset,
            NodeRef("bank-a", NodeKind.ICT_ASSET, "downstream-recovery-node"),
            DependencyRelationship.DEPENDS_ON,
            "New modeled dependency",
        )
    )
    with pytest.raises(GovernanceError, match="stale for current topology"):
        assert_dependency_impact_current(snapshot, registry)


def test_blocking_recovery_finding_requires_independent_retest_for_closure() -> None:
    registry, *_, objective, plan, execution = continuity_fixture()
    breached = assess_continuity_recovery(
        plan,
        objective,
        execution,
        (observation(plan, execution, restoration=450, rpo=90, service=7000),),
        registry,
        assessed_at=230,
    )
    finding = create_continuity_finding(
        breached,
        finding_id="finding-1",
        severity=FindingSeverity.HIGH,
        title="Recovery objectives were not achieved",
        owner_id="continuity-owner",
        identified_at=240,
        evidence_digest=D4,
    )
    remediation = create_continuity_remediation(
        finding,
        remediation_id="remediation-1",
        owner_id="remediation-owner",
        completed_at=300,
        summary="Recovery orchestration and replication controls were remediated",
        evidence_digest=D5,
    )
    with pytest.raises(GovernanceError, match="configured independent reviewer"):
        create_continuity_retest(
            plan,
            finding,
            remediation,
            retest_id="retest-wrong",
            reviewer_id="developer",
            tested_at=320,
            outcome=RetestOutcome.PASSED,
            notes="wrong reviewer",
            evidence_digest=D1,
        )
    retest = create_continuity_retest(
        plan,
        finding,
        remediation,
        retest_id="retest-1",
        reviewer_id="continuity-reviewer",
        tested_at=320,
        outcome=RetestOutcome.PASSED,
        notes="independent retest passed for represented recovery evidence",
        evidence_digest=D2,
    )
    resolution = resolve_continuity(plan, breached, (finding,), (remediation,), (retest,))
    assert resolution.state is ContinuityResolutionState.SUCCESSFUL_WITH_FINDINGS
    assert not resolution.unresolved_finding_digests


def test_raw_string_node_kind_does_not_bypass_recovery_target_contract() -> None:
    registry, function, *_ = continuity_registry()
    bad_ref = NodeRef("bank-a", "business_function", function.node_id)  # type: ignore[arg-type]
    with pytest.raises(GovernanceError, match="NodeRef/NodeKind"):
        build_recovery_objective(
            registry,
            entity_id="bank-a",
            objective_id="bad",
            target=bad_ref,
            owner_id="owner",
            maximum_tolerable_disruption_seconds=600,
            recovery_time_objective_seconds=300,
            recovery_point_objective_seconds=60,
            minimum_service_level_basis_points=8000,
            rationale="invalid raw enum",
            registered_at=1,
        )


def test_observation_and_assessment_timestamps_fail_closed() -> None:
    registry, *_, objective, plan, execution = continuity_fixture()
    with pytest.raises(GovernanceError, match="cannot predate exercise execution"):
        observation(plan, execution, observed_at=140)
    obs = observation(plan, execution)
    with pytest.raises(GovernanceError, match="cannot predate exercise completion"):
        assess_continuity_recovery(plan, objective, execution, (obs,), registry, assessed_at=200)
