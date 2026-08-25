from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from doraops.canonical import canonical_json, sha256_digest
from doraops.control_matrix import (
    ControlCoverageState,
    EvidenceBinding,
    assess_control_evidence,
    matrix_from_dict,
    verify_matrix_payload,
)
from doraops.inventory import GovernanceError

ROOT = Path(__file__).resolve().parents[1]
MATRIX_PATH = ROOT / "configs" / "dora-control-evidence-matrix.json"


def matrix_payload():
    return json.loads(MATRIX_PATH.read_text(encoding="utf-8"))


def complete_bindings(matrix, *, observed_at: int = 100):
    result = []
    for mapping in matrix.mappings:
        for evidence_type in mapping.expected_evidence_types:
            result.append(
                EvidenceBinding(
                    control_id=mapping.control_id,
                    evidence_type=evidence_type,
                    artifact_digest=sha256_digest({"control": mapping.control_id, "type": evidence_type}),
                    accountable_role=mapping.responsible_role,
                    verifier_id=f"verifier:{mapping.control_id}",
                    observed_at=observed_at,
                )
            )
    return tuple(result)


def test_reference_matrix_is_schema_valid_and_semantically_verifiable():
    payload = matrix_payload()
    schema = json.loads((ROOT / "schemas" / "control-evidence-matrix.schema.json").read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.Draft202012Validator(schema).validate(payload)

    matrix = matrix_from_dict(payload)
    assert verify_matrix_payload(payload) == matrix.evidence_digest
    assert matrix.regulation == "Regulation (EU) 2022/2554"
    assert len(matrix.mappings) == 13
    assert tuple(item.control_id for item in matrix.mappings) == tuple(sorted(item.control_id for item in matrix.mappings))
    assert matrix.complete_legal_mapping_claimed is False
    assert matrix.dora_compliance_determined is False
    assert matrix.legal_applicability_determined is False
    assert matrix.supervisory_acceptance_determined is False
    assert matrix.requires_human_review is True


def test_complete_evidence_representation_is_not_a_compliance_conclusion():
    matrix = matrix_from_dict(matrix_payload())
    assessment = assess_control_evidence(matrix, complete_bindings(matrix), assessed_at=200)
    assert assessment.represented_control_count == len(matrix.mappings)
    assert assessment.gap_control_count == 0
    assert all(item.state is ControlCoverageState.REPRESENTED for item in assessment.controls)
    assert assessment.dora_compliance_determined is False
    assert assessment.legal_applicability_determined is False
    assert assessment.supervisory_acceptance_determined is False
    assert assessment.requires_human_review is True
    assert not hasattr(assessment, "compliance_score")
    assert not hasattr(assessment, "compliance_percentage")


def test_missing_evidence_is_reported_as_gap_not_noncompliance():
    matrix = matrix_from_dict(matrix_payload())
    bindings = list(complete_bindings(matrix))
    target = matrix.mapping("governance_accountability")
    missing_type = target.expected_evidence_types[0]
    bindings = [
        item for item in bindings
        if not (item.control_id == target.control_id and item.evidence_type == missing_type)
    ]
    assessment = assess_control_evidence(matrix, bindings, assessed_at=200)
    coverage = next(item for item in assessment.controls if item.control_id == target.control_id)
    assert coverage.state is ControlCoverageState.GAP
    assert coverage.missing_evidence_types == (missing_type,)
    assert assessment.gap_control_count == 1
    assert assessment.dora_compliance_determined is False


def test_unexpected_evidence_type_fails_closed():
    matrix = matrix_from_dict(matrix_payload())
    mapping = matrix.mappings[0]
    binding = EvidenceBinding(
        control_id=mapping.control_id,
        evidence_type="invented_evidence",
        artifact_digest="a" * 64,
        accountable_role=mapping.responsible_role,
        verifier_id="validator",
        observed_at=1,
    )
    with pytest.raises(GovernanceError, match="not expected"):
        assess_control_evidence(matrix, (binding,), assessed_at=2)


def test_wrong_accountable_role_fails_closed():
    matrix = matrix_from_dict(matrix_payload())
    mapping = matrix.mappings[0]
    binding = EvidenceBinding(
        control_id=mapping.control_id,
        evidence_type=mapping.expected_evidence_types[0],
        artifact_digest="b" * 64,
        accountable_role="wrong-role",
        verifier_id="validator",
        observed_at=1,
    )
    with pytest.raises(GovernanceError, match="differs from control responsibility"):
        assess_control_evidence(matrix, (binding,), assessed_at=2)


def test_future_evidence_binding_fails_closed():
    matrix = matrix_from_dict(matrix_payload())
    mapping = matrix.mappings[0]
    binding = EvidenceBinding(
        control_id=mapping.control_id,
        evidence_type=mapping.expected_evidence_types[0],
        artifact_digest="c" * 64,
        accountable_role=mapping.responsible_role,
        verifier_id="validator",
        observed_at=11,
    )
    with pytest.raises(GovernanceError, match="after assessment time"):
        assess_control_evidence(matrix, (binding,), assessed_at=10)


def test_matrix_nonclaims_fail_closed():
    payload = matrix_payload()
    payload["dora_compliance_determined"] = True
    with pytest.raises(GovernanceError, match="cannot determine DORA compliance"):
        matrix_from_dict(payload)


def test_assessment_schema_validates_runtime_output():
    matrix = matrix_from_dict(matrix_payload())
    assessment = assess_control_evidence(matrix, complete_bindings(matrix), assessed_at=200)
    payload = json.loads(canonical_json(assessment))
    schema = json.loads((ROOT / "schemas" / "control-evidence-assessment.schema.json").read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.Draft202012Validator(schema).validate(payload)


def test_machine_contract_contains_no_compliance_percentage_or_maturity_score():
    source = (ROOT / "src" / "doraops" / "control_matrix.py").read_text(encoding="utf-8")
    config = MATRIX_PATH.read_text(encoding="utf-8")
    for forbidden in ("compliance_percentage", "maturity_score"):
        assert forbidden not in source
        assert forbidden not in config
