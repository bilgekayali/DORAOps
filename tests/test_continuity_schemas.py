from __future__ import annotations

import json
from pathlib import Path

import jsonschema

import doraops
from doraops import (
    DependencyTraversalDirection,
    FindingSeverity,
    RetestOutcome,
    assess_continuity_recovery,
    build_dependency_impact_snapshot,
    canonical_json,
    create_continuity_finding,
    create_continuity_remediation,
    create_continuity_retest,
    dossier_document,
    resolve_continuity,
)
from tests.test_continuity import D1, D2, D3, continuity_fixture, observation


ROOT = Path(__file__).resolve().parents[1]


def contract(name: str) -> dict:
    result = json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(result)
    return result


def payload(value):
    return json.loads(canonical_json(value))


def version_tuple(value: str) -> tuple[int, int, int]:
    major, minor, patch = value.split(".")[:3]
    return int(major), int(minor), int(patch)


def test_v02_release_versions_are_aligned() -> None:
    assert version_tuple(doraops.__version__) >= (0, 2, 0)
    assert doraops.RELEASE_VERSION == doraops.__version__


def test_continuity_runtime_artifacts_validate_against_strict_schemas() -> None:
    registry, function, *_middle, objective, plan, execution = continuity_fixture()
    obs = observation(plan, execution)
    assessment = assess_continuity_recovery(plan, objective, execution, (obs,), registry, assessed_at=230)
    impact = build_dependency_impact_snapshot(
        registry,
        entity_id="bank-a",
        origin_nodes=(function,),
        direction=DependencyTraversalDirection.OUTBOUND,
        maximum_depth=3,
        generated_at=250,
    )

    jsonschema.Draft202012Validator(contract("recovery-objective.schema.json")).validate(payload(objective))
    exercise_contract = jsonschema.Draft202012Validator(contract("continuity-exercise.schema.json"))
    for item in (plan, execution, obs):
        exercise_contract.validate(payload(item))
    jsonschema.Draft202012Validator(contract("continuity-assessment.schema.json")).validate(payload(assessment))
    jsonschema.Draft202012Validator(contract("dependency-impact.schema.json")).validate(payload(impact))


def test_continuity_lifecycle_schema_accepts_real_failure_remediation_retest_resolution() -> None:
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
        finding_id="finding-schema",
        severity=FindingSeverity.HIGH,
        title="Recovery objective breach",
        owner_id="owner",
        identified_at=240,
        evidence_digest=D1,
    )
    remediation = create_continuity_remediation(
        finding,
        remediation_id="rem-schema",
        owner_id="rem-owner",
        completed_at=300,
        summary="remediated",
        evidence_digest=D2,
    )
    retest = create_continuity_retest(
        plan,
        finding,
        remediation,
        retest_id="retest-schema",
        reviewer_id="continuity-reviewer",
        tested_at=320,
        outcome=RetestOutcome.PASSED,
        notes="independent retest passed",
        evidence_digest=D3,
    )
    resolution = resolve_continuity(plan, breached, (finding,), (remediation,), (retest,))
    validator = jsonschema.Draft202012Validator(contract("continuity-lifecycle.schema.json"))
    for item in (finding, remediation, retest, resolution):
        validator.validate(payload(item))


def test_continuity_non_claim_fields_are_locked_in_schema() -> None:
    assessment = contract("continuity-assessment.schema.json")
    assert assessment["properties"]["operational_resilience_determined"]["const"] is False
    assert assessment["properties"]["regulatory_compliance_determined"]["const"] is False
    impact = contract("dependency-impact.schema.json")
    assert impact["properties"]["runtime_impact_determined"]["const"] is False


def test_governance_dossier_schema_retains_v02_envelope_under_current_release() -> None:
    schema = contract("governance-dossier.schema.json")
    release = schema["properties"]["dossier"]["properties"]["release_version"]["const"]
    assert release == doraops.RELEASE_VERSION
    assert version_tuple(release) >= (0, 2, 0)
