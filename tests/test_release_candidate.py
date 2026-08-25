from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

import doraops
from doraops.inventory import GovernanceError
from doraops.release_candidate import (
    git_blob_sha1,
    verify_release_candidate,
    verify_repository_governance_policy,
    verify_stable_api_contract,
    verify_stable_schema_contract,
)

ROOT = Path(__file__).resolve().parents[1]
CONFIGS = ROOT / "configs"


def load(name: str):
    return json.loads((CONFIGS / name).read_text(encoding="utf-8"))


def test_release_candidate_state_matches_package_boundary():
    status = verify_release_candidate(ROOT)
    expected_eligible = doraops.__version__ == "1.0.0"
    assert status["package_version"] == doraops.__version__
    assert status["required_release_version"] == "1.0.0"
    assert status["formal_stable_reference_release_eligible"] is expected_eligible
    assert status["production_readiness_determined"] is False
    assert status["dora_compliance_determined"] is False
    assert status["supervisory_acceptance_determined"] is False


def test_stable_api_contract_is_frozen_and_resolvable():
    contract = load("stable-api-contract.json")
    digest = verify_stable_api_contract(contract)
    assert len(digest) == 64
    assert contract["frozen_for_v1"] is True
    assert contract["breaking_changes_require_major_version"] is True
    assert len(contract["symbols"]) >= 40


def test_missing_stable_api_symbol_fails_closed():
    contract = copy.deepcopy(load("stable-api-contract.json"))
    contract["symbols"][0]["name"] = "DefinitelyMissingStableSymbol"
    with pytest.raises(GovernanceError, match="stable API symbol is missing"):
        verify_stable_api_contract(contract)


def test_stable_schema_contract_pins_real_git_blob_content():
    contract = load("stable-schema-contract.json")
    digest = verify_stable_schema_contract(contract, ROOT)
    assert len(digest) == 64
    assert len(contract["schemas"]) >= 10
    for item in contract["schemas"]:
        assert git_blob_sha1(ROOT / item["path"]) == item["git_blob_sha1"]


def test_stable_schema_hash_drift_fails_closed():
    contract = copy.deepcopy(load("stable-schema-contract.json"))
    contract["schemas"][0]["git_blob_sha1"] = "0" * 40
    with pytest.raises(GovernanceError, match="stable schema blob changed"):
        verify_stable_schema_contract(contract, ROOT)


def test_repository_governance_policy_records_unverified_enforcement_without_review_hassle():
    policy = load("repository-governance-policy.json")
    assert verify_repository_governance_policy(policy) is False
    assert policy["enforcement_verified"] is False
    assert policy["required_approving_reviews"] == 0
    assert policy["require_last_push_approval"] is False
    assert policy["pull_request_required"] is True
    assert policy["force_pushes_allowed"] is False
    assert policy["branch_deletion_allowed"] is False


def test_release_gate_is_reference_stability_gate_not_production_or_compliance_gate():
    gate = load("release-candidate-gate.json")
    assert gate["candidate_version"] == doraops.__version__
    assert gate["checks"]["package_version_is_required_release"] is (doraops.__version__ == "1.0.0")
    assert gate["formal_stable_reference_release_eligible"] is (doraops.__version__ == "1.0.0")
    assert gate["repository_governance_enforcement_verified"] is False
    assert gate["production_readiness_determined"] is False
    assert gate["dora_compliance_determined"] is False
    assert gate["supervisory_acceptance_determined"] is False


def test_codeql_workflow_is_present_with_python_analysis():
    source = (ROOT / ".github" / "workflows" / "codeql.yml").read_text(encoding="utf-8")
    assert "name: CodeQL (python)" in source
    assert "github/codeql-action/init@v3" in source
    assert "languages: python" in source
    assert "github/codeql-action/analyze@v3" in source


def test_release_candidate_verifier_is_offline():
    source = (ROOT / "src" / "doraops" / "release_candidate.py").read_text(encoding="utf-8")
    for forbidden in ("requests", "urllib", "socket", "subprocess", "httpx"):
        assert forbidden not in source
