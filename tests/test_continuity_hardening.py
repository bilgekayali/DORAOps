from __future__ import annotations

from copy import deepcopy

import pytest

from doraops import (
    ContinuityFinding,
    FindingSeverity,
    GovernanceDossierBuilder,
    GovernanceError,
    RetestOutcome,
    assess_continuity_recovery,
    create_continuity_finding,
    create_continuity_remediation,
    create_continuity_retest,
    dossier_document,
    resolve_continuity,
    sha256_digest,
    verify_dossier_document,
)
from tests.test_continuity import D1, D2, D3, D4, continuity_fixture, observation


def test_met_assessment_cannot_accept_manually_constructed_finding() -> None:
    registry, *_, objective, plan, execution = continuity_fixture()
    met = assess_continuity_recovery(
        plan,
        objective,
        execution,
        (observation(plan, execution),),
        registry,
        assessed_at=230,
    )
    forged = ContinuityFinding(
        entity_id="bank-a",
        finding_id="forged-on-met",
        assessment_digest=met.evidence_digest,
        severity=FindingSeverity.LOW,
        title="Finding cannot be attached to a met assessment",
        owner_id="owner",
        identified_at=240,
        evidence_digest=D1,
    )
    with pytest.raises(GovernanceError, match="met continuity assessment cannot carry"):
        resolve_continuity(plan, met, (forged,))


def lifecycle_dossier_document():
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
        finding_id="finding-hardening",
        severity=FindingSeverity.HIGH,
        title="Recovery objectives breached",
        owner_id="continuity-owner",
        identified_at=240,
        evidence_digest=D1,
    )
    remediation = create_continuity_remediation(
        finding,
        remediation_id="remediation-hardening",
        owner_id="remediation-owner",
        completed_at=300,
        summary="Recovery controls remediated",
        evidence_digest=D2,
    )
    retest = create_continuity_retest(
        plan,
        finding,
        remediation,
        retest_id="retest-hardening",
        reviewer_id="continuity-reviewer",
        tested_at=320,
        outcome=RetestOutcome.PASSED,
        notes="Independent represented retest passed",
        evidence_digest=D3,
    )
    resolution = resolve_continuity(plan, breached, (finding,), (remediation,), (retest,))
    obs = observation(plan, execution, restoration=450, rpo=90, service=7000)
    builder = GovernanceDossierBuilder(
        registry,
        entity_id="bank-a",
        generated_at=400,
        source_revision="continuity-hardening",
    )
    builder.add_continuity_recovery(
        objective,
        plan,
        execution,
        breached,
        observations=(obs,),
        findings=(finding,),
        remediations=(remediation,),
        retests=(retest,),
        resolution=resolution,
    )
    document = dossier_document(builder.build())
    verify_dossier_document(document)
    return document


def test_offline_verifier_rejects_rehashed_continuity_resolution_state_tamper() -> None:
    document = deepcopy(lifecycle_dossier_document())
    resolution = next(
        item
        for item in document["dossier"]["artifacts"]
        if item["domain"] == "continuity" and item["artifact_type"] == "continuity_resolution"
    )
    resolution["payload"]["state"] = "successful"
    resolution["digest"] = sha256_digest(resolution["payload"])
    document["dossier_digest"] = sha256_digest(document["dossier"])
    with pytest.raises(GovernanceError, match="resolution state is inconsistent"):
        verify_dossier_document(document)


def test_offline_verifier_rejects_rehashed_metric_threshold_tamper() -> None:
    registry, *_, objective, plan, execution = continuity_fixture()
    obs = observation(plan, execution)
    assessment = assess_continuity_recovery(plan, objective, execution, (obs,), registry, assessed_at=230)
    builder = GovernanceDossierBuilder(
        registry,
        entity_id="bank-a",
        generated_at=400,
        source_revision="assessment-hardening",
    )
    builder.add_continuity_recovery(objective, plan, execution, assessment, observations=(obs,))
    document = deepcopy(dossier_document(builder.build()))
    artifact = next(
        item
        for item in document["dossier"]["artifacts"]
        if item["domain"] == "continuity" and item["artifact_type"] == "recovery_assessment"
    )
    artifact["payload"]["metric_assessments"][0]["threshold_value"] += 1
    artifact["digest"] = sha256_digest(artifact["payload"])
    document["dossier_digest"] = sha256_digest(document["dossier"])
    with pytest.raises(GovernanceError, match="threshold differs"):
        verify_dossier_document(document)
