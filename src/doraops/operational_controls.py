from __future__ import annotations

from dataclasses import dataclass
import json
import re
from typing import Any, Iterable

from .canonical import canonical_json, sha256_digest
from .inventory import GovernanceError

DEPLOYMENT_PROFILE_SCHEMA_VERSION = "doraops-deployment-control-profile.v1"
OPERATIONAL_EVIDENCE_SCHEMA_VERSION = "doraops-operational-control-evidence.v1"

REQUIRED_OPERATIONAL_CONTROLS = (
    "immutable_deployment",
    "workload_runtime_security",
    "network_egress_default_deny",
    "external_secret_injection",
    "external_key_management",
    "backup_restore_evidence",
    "observability_secret_free",
)

_IMAGE_RE = re.compile(r"^[^\s]+@sha256:[0-9a-f]{64}$")


def _text(name: str, value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise GovernanceError(f"{name} must be non-empty text")
    return value.strip()


def _digest(name: str, value: Any) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(ch not in "0123456789abcdef" for ch in value)
    ):
        raise GovernanceError(f"{name} must be a lowercase SHA-256 digest")
    return value


def _timestamp(name: str, value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise GovernanceError(f"{name} must be a non-negative integer timestamp")
    return value


def _required_true(name: str, value: Any) -> None:
    if value is not True:
        raise GovernanceError(f"deployment profile requires {name}=true")


def _required_false(name: str, value: Any) -> None:
    if value is not False:
        raise GovernanceError(f"deployment profile requires {name}=false")


@dataclass(frozen=True, slots=True)
class DeploymentControlProfile:
    profile_id: str
    release_version: str
    workload_name: str
    image_reference: str
    run_as_non_root: bool = True
    read_only_root_filesystem: bool = True
    allow_privilege_escalation: bool = False
    drop_all_linux_capabilities: bool = True
    seccomp_profile: str = "RuntimeDefault"
    automount_service_account_token: bool = False
    default_deny_egress: bool = True
    tls_required: bool = True
    immutable_image_required: bool = True
    runtime_dependency_install_allowed: bool = False
    external_secret_injection: bool = True
    resource_limits_required: bool = True
    readiness_probe_required: bool = True
    liveness_probe_required: bool = True
    backup_restore_test_required: bool = True
    raw_evidence_logging_allowed: bool = False
    production_effectiveness_determined: bool = False
    schema_version: str = DEPLOYMENT_PROFILE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != DEPLOYMENT_PROFILE_SCHEMA_VERSION:
            raise GovernanceError("unsupported deployment profile schema version")
        for name in ("profile_id", "release_version", "workload_name"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        if not isinstance(self.image_reference, str) or not _IMAGE_RE.fullmatch(self.image_reference):
            raise GovernanceError("image_reference must be an immutable @sha256 image reference")
        _required_true("run_as_non_root", self.run_as_non_root)
        _required_true("read_only_root_filesystem", self.read_only_root_filesystem)
        _required_false("allow_privilege_escalation", self.allow_privilege_escalation)
        _required_true("drop_all_linux_capabilities", self.drop_all_linux_capabilities)
        if self.seccomp_profile != "RuntimeDefault":
            raise GovernanceError("deployment profile requires RuntimeDefault seccomp")
        _required_false("automount_service_account_token", self.automount_service_account_token)
        _required_true("default_deny_egress", self.default_deny_egress)
        _required_true("tls_required", self.tls_required)
        _required_true("immutable_image_required", self.immutable_image_required)
        _required_false("runtime_dependency_install_allowed", self.runtime_dependency_install_allowed)
        _required_true("external_secret_injection", self.external_secret_injection)
        _required_true("resource_limits_required", self.resource_limits_required)
        _required_true("readiness_probe_required", self.readiness_probe_required)
        _required_true("liveness_probe_required", self.liveness_probe_required)
        _required_true("backup_restore_test_required", self.backup_restore_test_required)
        _required_false("raw_evidence_logging_allowed", self.raw_evidence_logging_allowed)
        _required_false("production_effectiveness_determined", self.production_effectiveness_determined)

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class ControlEvidenceItem:
    control_id: str
    artifact_digest: str
    validator_id: str
    negative_path_verified: bool

    def __post_init__(self) -> None:
        object.__setattr__(self, "control_id", _text("control_id", self.control_id))
        if self.control_id not in REQUIRED_OPERATIONAL_CONTROLS:
            raise GovernanceError("unsupported operational control_id")
        _digest("artifact_digest", self.artifact_digest)
        object.__setattr__(self, "validator_id", _text("validator_id", self.validator_id))
        if self.negative_path_verified is not True:
            raise GovernanceError("operational control evidence requires negative-path verification")


@dataclass(frozen=True, slots=True)
class OperationalControlEvidence:
    entity_id: str
    environment_id: str
    deployment_profile_digest: str
    collected_at: int
    controls: tuple[ControlEvidenceItem, ...]
    production_environment: bool
    raw_endpoints_included: bool = False
    secrets_included: bool = False
    production_effectiveness_determined: bool = False
    dora_compliance_determined: bool = False
    supervisory_acceptance_determined: bool = False
    requires_human_review: bool = True
    schema_version: str = OPERATIONAL_EVIDENCE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != OPERATIONAL_EVIDENCE_SCHEMA_VERSION:
            raise GovernanceError("unsupported operational evidence schema version")
        for name in ("entity_id", "environment_id"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        _digest("deployment_profile_digest", self.deployment_profile_digest)
        _timestamp("collected_at", self.collected_at)
        if not isinstance(self.production_environment, bool):
            raise GovernanceError("production_environment must be boolean")
        if not isinstance(self.controls, tuple):
            raise GovernanceError("controls must be a tuple")
        ids = tuple(item.control_id for item in self.controls)
        if ids != tuple(sorted(ids)):
            raise GovernanceError("operational controls must be sorted by control_id")
        if set(ids) != set(REQUIRED_OPERATIONAL_CONTROLS) or len(ids) != len(REQUIRED_OPERATIONAL_CONTROLS):
            raise GovernanceError("operational evidence must contain every required control exactly once")
        artifact_digests = tuple(item.artifact_digest for item in self.controls)
        if len(artifact_digests) != len(set(artifact_digests)):
            raise GovernanceError("operational control evidence artifact digests must be distinct")
        if self.raw_endpoints_included is not False:
            raise GovernanceError("operational evidence must not include raw endpoints")
        if self.secrets_included is not False:
            raise GovernanceError("operational evidence must not include secrets")
        if self.production_effectiveness_determined is not False:
            raise GovernanceError("operational evidence cannot determine production effectiveness")
        if self.dora_compliance_determined is not False:
            raise GovernanceError("operational evidence cannot determine DORA compliance")
        if self.supervisory_acceptance_determined is not False:
            raise GovernanceError("operational evidence cannot determine supervisory acceptance")
        if self.requires_human_review is not True:
            raise GovernanceError("operational evidence requires human review")

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


def build_operational_control_evidence(
    *,
    entity_id: str,
    environment_id: str,
    profile: DeploymentControlProfile,
    collected_at: int,
    production_environment: bool,
    control_evidence: Iterable[ControlEvidenceItem],
) -> OperationalControlEvidence:
    controls = tuple(sorted(tuple(control_evidence), key=lambda item: item.control_id))
    return OperationalControlEvidence(
        entity_id=entity_id,
        environment_id=environment_id,
        deployment_profile_digest=profile.evidence_digest,
        collected_at=collected_at,
        controls=controls,
        production_environment=production_environment,
    )


def profile_document(profile: DeploymentControlProfile) -> dict[str, Any]:
    payload = json.loads(canonical_json(profile))
    return {"profile": payload, "profile_digest": sha256_digest(payload)}


def operational_evidence_document(evidence: OperationalControlEvidence) -> dict[str, Any]:
    payload = json.loads(canonical_json(evidence))
    return {"evidence": payload, "evidence_digest": sha256_digest(payload)}


def verify_profile_document(document: Any) -> str:
    if not isinstance(document, dict) or set(document) != {"profile", "profile_digest"}:
        raise GovernanceError("deployment profile document has unexpected fields")
    payload = document["profile"]
    digest = document["profile_digest"]
    if not isinstance(payload, dict):
        raise GovernanceError("deployment profile payload must be an object")
    _digest("profile_digest", digest)
    if sha256_digest(payload) != digest:
        raise GovernanceError("deployment profile digest mismatch")
    try:
        profile = DeploymentControlProfile(**payload)
    except TypeError as exc:
        raise GovernanceError("deployment profile fields are invalid") from exc
    if profile.evidence_digest != digest:
        raise GovernanceError("deployment profile canonical digest mismatch")
    return digest


def verify_operational_evidence_document(document: Any, profile_document_value: Any) -> str:
    profile_digest = verify_profile_document(profile_document_value)
    if not isinstance(document, dict) or set(document) != {"evidence", "evidence_digest"}:
        raise GovernanceError("operational evidence document has unexpected fields")
    payload = document["evidence"]
    digest = document["evidence_digest"]
    if not isinstance(payload, dict):
        raise GovernanceError("operational evidence payload must be an object")
    _digest("evidence_digest", digest)
    if sha256_digest(payload) != digest:
        raise GovernanceError("operational evidence digest mismatch")
    controls_raw = payload.get("controls")
    if not isinstance(controls_raw, list):
        raise GovernanceError("operational evidence controls must be an array")
    try:
        controls = tuple(ControlEvidenceItem(**item) for item in controls_raw)
        evidence = OperationalControlEvidence(
            **{key: value for key, value in payload.items() if key != "controls"},
            controls=controls,
        )
    except (TypeError, AttributeError) as exc:
        raise GovernanceError("operational evidence fields are invalid") from exc
    if evidence.deployment_profile_digest != profile_digest:
        raise GovernanceError("operational evidence is bound to a different deployment profile")
    if evidence.evidence_digest != digest:
        raise GovernanceError("operational evidence canonical digest mismatch")
    return digest
