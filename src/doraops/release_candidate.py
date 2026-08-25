from __future__ import annotations

import hashlib
import importlib
import json
from pathlib import Path, PurePosixPath
from typing import Any

from ._release import PACKAGE_VERSION
from .inventory import GovernanceError


_API_KEYS = {
    "contract_version",
    "release_version",
    "stable_surface_scope",
    "frozen_for_v1",
    "symbols",
    "breaking_changes_require_major_version",
    "production_readiness_determined",
    "dora_compliance_determined",
}
_SCHEMA_KEYS = {
    "contract_version",
    "release_version",
    "frozen_for_v1",
    "schemas",
    "breaking_changes_require_major_version",
    "production_readiness_determined",
    "dora_compliance_determined",
}
_GOVERNANCE_KEYS = {
    "policy_version",
    "target_branch",
    "enforcement_verified",
    "pull_request_required",
    "required_approving_reviews",
    "dismiss_stale_reviews",
    "require_last_push_approval",
    "conversation_resolution_required",
    "force_pushes_allowed",
    "branch_deletion_allowed",
    "required_workflows",
    "notes",
}
_GATE_KEYS = {
    "gate_version",
    "required_release_version",
    "candidate_version",
    "formal_stable_reference_release_eligible",
    "checks",
    "repository_governance_enforcement_verified",
    "production_readiness_determined",
    "dora_compliance_determined",
    "supervisory_acceptance_determined",
}
_CHECK_KEYS = {
    "stable_api_contract_frozen",
    "stable_schema_contract_frozen",
    "codeql_workflow_defined",
    "release_evidence_gate_defined",
    "security_boundary_gate_defined",
    "deployment_hardening_gate_defined",
    "control_evidence_matrix_gate_defined",
    "repository_governance_policy_defined",
    "package_version_is_required_release",
}


def _text(name: str, value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise GovernanceError(f"{name} must be non-empty text")
    return value.strip()


def _object(name: str, value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise GovernanceError(f"{name} must be an object")
    return value


def _exact_keys(name: str, value: dict[str, Any], expected: set[str]) -> None:
    if set(value) != expected:
        raise GovernanceError(f"{name} has unexpected fields")


def _load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GovernanceError(f"cannot load release-candidate document: {path}") from exc
    return _object(str(path), payload)


def git_blob_sha1(path: Path) -> str:
    try:
        content = path.read_bytes()
    except OSError as exc:
        raise GovernanceError(f"cannot read stable schema: {path}") from exc
    header = f"blob {len(content)}\0".encode("ascii")
    return hashlib.sha1(header + content).hexdigest()


def _schema_path(root: Path, value: Any) -> Path:
    raw = _text("stable schema path", value)
    if "\\" in raw:
        raise GovernanceError("stable schema path must use POSIX separators")
    posix = PurePosixPath(raw)
    if posix.is_absolute() or raw != posix.as_posix() or any(part in {"", ".", ".."} for part in posix.parts):
        raise GovernanceError("stable schema path must be normalized and relative")
    if len(posix.parts) != 2 or posix.parts[0] != "schemas" or not posix.name.endswith(".schema.json"):
        raise GovernanceError("stable schema path must identify a direct schemas/*.schema.json file")
    return root / Path(*posix.parts)


def verify_stable_api_contract(payload: Any) -> str:
    contract = _object("stable API contract", payload)
    _exact_keys("stable API contract", contract, _API_KEYS)
    _text("contract_version", contract["contract_version"])
    if contract["release_version"] != PACKAGE_VERSION:
        raise GovernanceError("stable API contract release_version differs from package version")
    if contract["stable_surface_scope"] != "declared_symbols_only":
        raise GovernanceError("stable API contract scope must be declared_symbols_only")
    if contract["frozen_for_v1"] is not True or contract["breaking_changes_require_major_version"] is not True:
        raise GovernanceError("stable API contract must be frozen with major-version breaking-change policy")
    if contract["production_readiness_determined"] is not False or contract["dora_compliance_determined"] is not False:
        raise GovernanceError("stable API contract cannot determine production readiness or DORA compliance")
    symbols = contract["symbols"]
    if not isinstance(symbols, list) or not symbols:
        raise GovernanceError("stable API contract must contain symbols")
    normalized: list[tuple[str, str]] = []
    for item in symbols:
        item = _object("stable API symbol", item)
        _exact_keys("stable API symbol", item, {"module", "name"})
        module_name = _text("stable API module", item["module"])
        symbol_name = _text("stable API name", item["name"])
        normalized.append((module_name, symbol_name))
        try:
            module = importlib.import_module(module_name)
        except ImportError as exc:
            raise GovernanceError(f"stable API module cannot be imported: {module_name}") from exc
        if not hasattr(module, symbol_name):
            raise GovernanceError(f"stable API symbol is missing: {module_name}.{symbol_name}")
    if normalized != sorted(normalized) or len(normalized) != len(set(normalized)):
        raise GovernanceError("stable API symbols must be sorted and unique")
    return hashlib.sha256(json.dumps(contract, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def verify_stable_schema_contract(payload: Any, root: Path) -> str:
    contract = _object("stable schema contract", payload)
    _exact_keys("stable schema contract", contract, _SCHEMA_KEYS)
    _text("contract_version", contract["contract_version"])
    if contract["release_version"] != PACKAGE_VERSION:
        raise GovernanceError("stable schema contract release_version differs from package version")
    if contract["frozen_for_v1"] is not True or contract["breaking_changes_require_major_version"] is not True:
        raise GovernanceError("stable schema contract must be frozen with major-version breaking-change policy")
    if contract["production_readiness_determined"] is not False or contract["dora_compliance_determined"] is not False:
        raise GovernanceError("stable schema contract cannot determine production readiness or DORA compliance")
    schemas = contract["schemas"]
    if not isinstance(schemas, list) or not schemas:
        raise GovernanceError("stable schema contract must contain schemas")
    identities: list[str] = []
    for item in schemas:
        item = _object("stable schema entry", item)
        _exact_keys("stable schema entry", item, {"path", "git_blob_sha1"})
        relative = _text("stable schema path", item["path"])
        expected = _text("stable schema git_blob_sha1", item["git_blob_sha1"])
        if len(expected) != 40 or any(ch not in "0123456789abcdef" for ch in expected):
            raise GovernanceError("stable schema git_blob_sha1 must be lowercase Git SHA-1")
        path = _schema_path(root, relative)
        if git_blob_sha1(path) != expected:
            raise GovernanceError(f"stable schema blob changed: {relative}")
        identities.append(relative)
    if identities != sorted(identities) or len(identities) != len(set(identities)):
        raise GovernanceError("stable schema paths must be sorted and unique")
    return hashlib.sha256(json.dumps(contract, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def verify_repository_governance_policy(payload: Any) -> bool:
    policy = _object("repository governance policy", payload)
    _exact_keys("repository governance policy", policy, _GOVERNANCE_KEYS)
    _text("policy_version", policy["policy_version"])
    if policy["target_branch"] != "main":
        raise GovernanceError("repository governance policy must target main")
    if not isinstance(policy["enforcement_verified"], bool):
        raise GovernanceError("repository governance enforcement_verified must be boolean")
    if policy["pull_request_required"] is not True:
        raise GovernanceError("repository governance policy must require pull requests")
    if policy["required_approving_reviews"] != 0:
        raise GovernanceError("single-maintainer policy intentionally requires zero approving reviews")
    if policy["dismiss_stale_reviews"] is not False or policy["require_last_push_approval"] is not False:
        raise GovernanceError("single-maintainer policy cannot require review-refresh or last-push approval")
    if policy["conversation_resolution_required"] is not True:
        raise GovernanceError("repository governance policy must require conversation resolution")
    if policy["force_pushes_allowed"] is not False or policy["branch_deletion_allowed"] is not False:
        raise GovernanceError("repository governance policy must prohibit force pushes and branch deletion")
    workflows = policy["required_workflows"]
    if not isinstance(workflows, list) or not workflows or workflows != sorted(workflows) or len(workflows) != len(set(workflows)):
        raise GovernanceError("required workflows must be a sorted unique non-empty array")
    for workflow in workflows:
        _text("required workflow", workflow)
    _text("repository governance notes", policy["notes"])
    return policy["enforcement_verified"]


def verify_release_candidate(root: Path) -> dict[str, Any]:
    root = Path(root)
    api = _load_json(root / "configs" / "stable-api-contract.json")
    schemas = _load_json(root / "configs" / "stable-schema-contract.json")
    governance = _load_json(root / "configs" / "repository-governance-policy.json")
    gate = _load_json(root / "configs" / "release-candidate-gate.json")

    api_digest = verify_stable_api_contract(api)
    schema_digest = verify_stable_schema_contract(schemas, root)
    enforcement_verified = verify_repository_governance_policy(governance)

    _exact_keys("release candidate gate", gate, _GATE_KEYS)
    _text("gate_version", gate["gate_version"])
    required_version = _text("required_release_version", gate["required_release_version"])
    if required_version != "1.0.0":
        raise GovernanceError("release candidate gate must target 1.0.0")
    if gate["candidate_version"] != PACKAGE_VERSION:
        raise GovernanceError("release candidate gate candidate_version differs from package version")
    checks = _object("release candidate checks", gate["checks"])
    _exact_keys("release candidate checks", checks, _CHECK_KEYS)

    workflow_files = {
        "codeql_workflow_defined": root / ".github" / "workflows" / "codeql.yml",
        "release_evidence_gate_defined": root / ".github" / "workflows" / "release-evidence.yml",
        "security_boundary_gate_defined": root / ".github" / "workflows" / "security-boundary.yml",
        "deployment_hardening_gate_defined": root / ".github" / "workflows" / "deployment-hardening.yml",
        "control_evidence_matrix_gate_defined": root / ".github" / "workflows" / "control-evidence-matrix.yml",
    }
    actual_checks = {
        "stable_api_contract_frozen": True,
        "stable_schema_contract_frozen": True,
        **{name: path.is_file() for name, path in workflow_files.items()},
        "repository_governance_policy_defined": True,
        "package_version_is_required_release": PACKAGE_VERSION == required_version,
    }
    if checks != actual_checks:
        raise GovernanceError("release candidate gate checks do not match verified repository state")
    expected_eligible = all(actual_checks.values())
    if gate["formal_stable_reference_release_eligible"] is not expected_eligible:
        raise GovernanceError("formal stable-reference eligibility is inconsistent with verified checks")
    if gate["repository_governance_enforcement_verified"] is not enforcement_verified:
        raise GovernanceError("release gate governance enforcement state differs from policy")
    for name in ("production_readiness_determined", "dora_compliance_determined", "supervisory_acceptance_determined"):
        if gate[name] is not False:
            raise GovernanceError(f"release candidate gate cannot set {name}=true")

    return {
        "package_version": PACKAGE_VERSION,
        "required_release_version": required_version,
        "formal_stable_reference_release_eligible": expected_eligible,
        "repository_governance_enforcement_verified": enforcement_verified,
        "stable_api_contract_sha256": api_digest,
        "stable_schema_contract_sha256": schema_digest,
        "production_readiness_determined": False,
        "dora_compliance_determined": False,
        "supervisory_acceptance_determined": False,
    }
