from __future__ import annotations

from copy import deepcopy

import pytest

from doraops import (
    DependencyTraversalDirection,
    DossierState,
    GovernanceDossierBuilder,
    GovernanceError,
    ICTAsset,
    RecoveryAssessmentState,
    assess_continuity_recovery,
    build_dependency_impact_snapshot,
    dossier_document,
    sha256_digest,
    verify_dossier_document,
)
from tests.test_continuity import continuity_fixture, observation


def build_continuity_dossier(*, breached: bool = False):
    registry, function, *_middle, objective, plan, execution = continuity_fixture()
    obs = observation(
        plan,
        execution,
        restoration=450 if breached else 240,
        rpo=90 if breached else 30,
        service=7000 if breached else 9000,
    )
    assessment = assess_continuity_recovery(
        plan,
        objective,
        execution,
        (obs,),
        registry,
        assessed_at=230,
    )
    impact = build_dependency_impact_snapshot(
        registry,
        entity_id="bank-a",
        origin_nodes=(function,),
        direction=DependencyTraversalDirection.OUTBOUND,
        maximum_depth=3,
        generated_at=240,
    )
    builder = GovernanceDossierBuilder(
        registry,
        entity_id="bank-a",
        generated_at=300,
        source_revision="v0.2-release-candidate",
    )
    builder.add_continuity_recovery(
        objective,
        plan,
        execution,
        assessment,
        observations=(obs,),
        impact_snapshot=impact,
    )
    return registry, objective, plan, execution, obs, assessment, impact, builder.build()


def test_current_continuity_evidence_is_packaged_and_verified_offline() -> None:
    *_, assessment, impact, dossier = build_continuity_dossier()
    assert assessment.state is RecoveryAssessmentState.MET
    assert impact.runtime_impact_determined is False
    assert dossier.release_version == "0.2.0"
    assert dossier.state is DossierState.CURRENT
    assert dossier.coverage["continuity"] >= 5
    document = dossier_document(dossier)
    assert verify_dossier_document(document) == document["dossier_digest"]


def test_breached_recovery_objective_is_explicit_dossier_gap() -> None:
    *_, assessment, _impact, dossier = build_continuity_dossier(breached=True)
    assert assessment.state is RecoveryAssessmentState.BREACHED
    assert dossier.state is DossierState.WITH_GAPS
    assert any("recovery_objectives_breached" in finding for finding in dossier.findings)


def test_topology_change_marks_preexisting_continuity_evidence_for_revalidation() -> None:
    registry, _function, *_middle, objective, plan, execution = continuity_fixture()
    obs = observation(plan, execution)
    assessment = assess_continuity_recovery(plan, objective, execution, (obs,), registry, assessed_at=230)
    registry.register_node(
        ICTAsset(
            entity_id="bank-a",
            asset_id="topology-change",
            name="Topology Change",
            owner_id="owner",
            asset_type="compute",
        )
    )
    builder = GovernanceDossierBuilder(
        registry,
        entity_id="bank-a",
        generated_at=300,
        source_revision="changed-topology",
    )
    builder.add_continuity_recovery(objective, plan, execution, assessment, observations=(obs,))
    dossier = builder.build()
    assert dossier.state is DossierState.REVALIDATION_REQUIRED
    assert any("stale for current inventory/dependency topology" in finding for finding in dossier.findings)


def test_continuity_cross_binding_tamper_fails_even_after_rehashing_artifact_and_outer_dossier() -> None:
    *_, dossier = build_continuity_dossier()
    document = deepcopy(dossier_document(dossier))
    assessment = next(
        item
        for item in document["dossier"]["artifacts"]
        if item["domain"] == "continuity" and item["artifact_type"] == "recovery_assessment"
    )
    assessment["payload"]["objective_digest"] = "f" * 64
    assessment["digest"] = sha256_digest(assessment["payload"])
    document["dossier_digest"] = sha256_digest(document["dossier"])
    with pytest.raises(GovernanceError, match="objective_digest does not resolve"):
        verify_dossier_document(document)
