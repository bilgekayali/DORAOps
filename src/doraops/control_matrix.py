from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Iterable

from .canonical import sha256_digest
from .inventory import GovernanceError

CONTROL_MATRIX_SCHEMA_VERSION = "doraops-control-evidence-matrix.v1"
MATRIX_ASSESSMENT_SCHEMA_VERSION = "doraops-control-evidence-assessment.v1"


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


@dataclass(frozen=True, slots=True)
class RegulatoryReference:
    source: str
    article: str
    topic: str

    def __post_init__(self) -> None:
        for name in ("source", "article", "topic"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))


@dataclass(frozen=True, slots=True)
class ControlMapping:
    control_id: str
    title: str
    regulatory_references: tuple[RegulatoryReference, ...]
    expected_evidence_types: tuple[str, ...]
    responsible_role: str
    verification_method: str
    applicability_basis: str = "institution_determined"

    def __post_init__(self) -> None:
        for name in ("control_id", "title", "responsible_role", "verification_method"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        if self.applicability_basis != "institution_determined":
            raise GovernanceError("control applicability must remain institution_determined")
        if not self.regulatory_references:
            raise GovernanceError("control mapping requires regulatory references")
        refs = tuple(sorted(self.regulatory_references, key=lambda item: (item.source, item.article, item.topic)))
        if len(refs) != len(set(refs)):
            raise GovernanceError("regulatory references must be unique")
        object.__setattr__(self, "regulatory_references", refs)
        evidence = tuple(sorted({_text("expected evidence type", item) for item in self.expected_evidence_types}))
        if not evidence:
            raise GovernanceError("control mapping requires expected evidence types")
        object.__setattr__(self, "expected_evidence_types", evidence)


@dataclass(frozen=True, slots=True)
class ControlEvidenceMatrix:
    matrix_id: str
    matrix_version: str
    jurisdiction: str
    regulation: str
    mappings: tuple[ControlMapping, ...]
    complete_legal_mapping_claimed: bool = False
    dora_compliance_determined: bool = False
    legal_applicability_determined: bool = False
    supervisory_acceptance_determined: bool = False
    requires_human_review: bool = True
    schema_version: str = CONTROL_MATRIX_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != CONTROL_MATRIX_SCHEMA_VERSION:
            raise GovernanceError("unsupported control matrix schema version")
        for name in ("matrix_id", "matrix_version", "jurisdiction", "regulation"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        if not self.mappings:
            raise GovernanceError("control matrix requires mappings")
        mappings = tuple(sorted(self.mappings, key=lambda item: item.control_id))
        ids = tuple(item.control_id for item in mappings)
        if len(ids) != len(set(ids)):
            raise GovernanceError("control mapping identifiers must be unique")
        object.__setattr__(self, "mappings", mappings)
        if self.complete_legal_mapping_claimed is not False:
            raise GovernanceError("control matrix cannot claim complete legal mapping")
        if self.dora_compliance_determined is not False:
            raise GovernanceError("control matrix cannot determine DORA compliance")
        if self.legal_applicability_determined is not False:
            raise GovernanceError("control matrix cannot determine legal applicability")
        if self.supervisory_acceptance_determined is not False:
            raise GovernanceError("control matrix cannot determine supervisory acceptance")
        if self.requires_human_review is not True:
            raise GovernanceError("control matrix requires human review")

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)

    def mapping(self, control_id: str) -> ControlMapping:
        control_id = _text("control_id", control_id)
        for mapping in self.mappings:
            if mapping.control_id == control_id:
                return mapping
        raise GovernanceError("unknown control_id")


@dataclass(frozen=True, slots=True)
class EvidenceBinding:
    control_id: str
    evidence_type: str
    artifact_digest: str
    accountable_role: str
    verifier_id: str
    observed_at: int

    def __post_init__(self) -> None:
        for name in ("control_id", "evidence_type", "accountable_role", "verifier_id"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        _digest("artifact_digest", self.artifact_digest)
        _timestamp("observed_at", self.observed_at)


class ControlCoverageState(str, Enum):
    REPRESENTED = "represented"
    GAP = "gap"


@dataclass(frozen=True, slots=True)
class ControlCoverage:
    control_id: str
    state: ControlCoverageState
    represented_evidence_types: tuple[str, ...]
    missing_evidence_types: tuple[str, ...]
    artifact_digests: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ControlEvidenceAssessment:
    matrix_digest: str
    assessed_at: int
    controls: tuple[ControlCoverage, ...]
    represented_control_count: int
    gap_control_count: int
    dora_compliance_determined: bool = False
    legal_applicability_determined: bool = False
    supervisory_acceptance_determined: bool = False
    requires_human_review: bool = True
    schema_version: str = MATRIX_ASSESSMENT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != MATRIX_ASSESSMENT_SCHEMA_VERSION:
            raise GovernanceError("unsupported matrix assessment schema version")
        _digest("matrix_digest", self.matrix_digest)
        _timestamp("assessed_at", self.assessed_at)
        if not self.controls:
            raise GovernanceError("matrix assessment requires control coverage")
        ids = tuple(item.control_id for item in self.controls)
        if ids != tuple(sorted(ids)) or len(ids) != len(set(ids)):
            raise GovernanceError("matrix assessment controls must be sorted and unique")
        represented = sum(item.state is ControlCoverageState.REPRESENTED for item in self.controls)
        gaps = sum(item.state is ControlCoverageState.GAP for item in self.controls)
        if self.represented_control_count != represented or self.gap_control_count != gaps:
            raise GovernanceError("matrix assessment counts are inconsistent")
        if represented + gaps != len(self.controls):
            raise GovernanceError("matrix assessment state counts are incomplete")
        if self.dora_compliance_determined is not False:
            raise GovernanceError("matrix assessment cannot determine DORA compliance")
        if self.legal_applicability_determined is not False:
            raise GovernanceError("matrix assessment cannot determine legal applicability")
        if self.supervisory_acceptance_determined is not False:
            raise GovernanceError("matrix assessment cannot determine supervisory acceptance")
        if self.requires_human_review is not True:
            raise GovernanceError("matrix assessment requires human review")

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


def matrix_from_dict(payload: Any) -> ControlEvidenceMatrix:
    if not isinstance(payload, dict):
        raise GovernanceError("control matrix must be an object")
    required = {
        "matrix_id", "matrix_version", "jurisdiction", "regulation", "mappings",
        "complete_legal_mapping_claimed", "dora_compliance_determined",
        "legal_applicability_determined", "supervisory_acceptance_determined",
        "requires_human_review", "schema_version",
    }
    if set(payload) != required:
        raise GovernanceError("control matrix has unexpected fields")
    mappings_raw = payload["mappings"]
    if not isinstance(mappings_raw, list):
        raise GovernanceError("control matrix mappings must be an array")
    mappings: list[ControlMapping] = []
    for item in mappings_raw:
        if not isinstance(item, dict):
            raise GovernanceError("control mapping must be an object")
        item = dict(item)
        refs_raw = item.pop("regulatory_references", None)
        if not isinstance(refs_raw, list):
            raise GovernanceError("control regulatory_references must be an array")
        refs = tuple(RegulatoryReference(**ref) for ref in refs_raw)
        evidence_raw = item.pop("expected_evidence_types", None)
        if not isinstance(evidence_raw, list):
            raise GovernanceError("control expected_evidence_types must be an array")
        mappings.append(
            ControlMapping(
                **item,
                regulatory_references=refs,
                expected_evidence_types=tuple(evidence_raw),
            )
        )
    return ControlEvidenceMatrix(
        **{key: value for key, value in payload.items() if key != "mappings"},
        mappings=tuple(mappings),
    )


def verify_matrix_payload(payload: Any) -> str:
    return matrix_from_dict(payload).evidence_digest


def assess_control_evidence(
    matrix: ControlEvidenceMatrix,
    bindings: Iterable[EvidenceBinding],
    *,
    assessed_at: int,
) -> ControlEvidenceAssessment:
    assessed_at = _timestamp("assessed_at", assessed_at)
    bindings_tuple = tuple(bindings)
    identities: set[tuple[str, str, str]] = set()
    by_control: dict[str, list[EvidenceBinding]] = {item.control_id: [] for item in matrix.mappings}
    for binding in bindings_tuple:
        if binding.observed_at > assessed_at:
            raise GovernanceError("evidence binding cannot be observed after assessment time")
        mapping = matrix.mapping(binding.control_id)
        if binding.evidence_type not in mapping.expected_evidence_types:
            raise GovernanceError("evidence binding type is not expected for control")
        if binding.accountable_role != mapping.responsible_role:
            raise GovernanceError("evidence binding accountable role differs from control responsibility")
        identity = (binding.control_id, binding.evidence_type, binding.artifact_digest)
        if identity in identities:
            raise GovernanceError("duplicate control evidence binding")
        identities.add(identity)
        by_control[binding.control_id].append(binding)

    coverage: list[ControlCoverage] = []
    for mapping in matrix.mappings:
        represented = tuple(sorted({item.evidence_type for item in by_control[mapping.control_id]}))
        missing = tuple(sorted(set(mapping.expected_evidence_types) - set(represented)))
        digests = tuple(sorted({item.artifact_digest for item in by_control[mapping.control_id]}))
        state = ControlCoverageState.GAP if missing else ControlCoverageState.REPRESENTED
        coverage.append(
            ControlCoverage(
                control_id=mapping.control_id,
                state=state,
                represented_evidence_types=represented,
                missing_evidence_types=missing,
                artifact_digests=digests,
            )
        )
    represented_count = sum(item.state is ControlCoverageState.REPRESENTED for item in coverage)
    return ControlEvidenceAssessment(
        matrix_digest=matrix.evidence_digest,
        assessed_at=assessed_at,
        controls=tuple(coverage),
        represented_control_count=represented_count,
        gap_control_count=len(coverage) - represented_count,
    )
