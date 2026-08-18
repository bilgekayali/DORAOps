from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import json
from typing import Any, Iterable

from .canonical import canonical_json, sha256_digest
from .incidents import (
    ClassificationReadinessState,
    IncidentClassificationPolicy,
    IncidentClassificationReview,
    IncidentRegistry,
    assess_classification_readiness,
)
from .inventory import GovernanceError, InventoryRegistry
from .resilience import (
    RemediationEvidence,
    ResilienceFinding,
    ResilienceTestExecution,
    ResilienceTestPlan,
    ResilienceTestResolution,
    RetestEvidence,
    TestResolutionState,
    assert_test_plan_current,
    resolve_test,
)
from .risk import (
    ICTControlObservation,
    ICTRiskDecision,
    ICTRiskPolicy,
    ICTRiskScenario,
    assert_risk_decision_current,
)
from .third_party import (
    ThirdPartyGovernancePolicy,
    ThirdPartyRegister,
    build_register_snapshot,
)

DOSSIER_SCHEMA_VERSION = "doraops-governance-dossier.v1"
RELEASE_VERSION = "0.1.0"


class DossierArtifactState(str, Enum):
    CURRENT = "current"
    WITH_GAPS = "with_gaps"
    REVALIDATION_REQUIRED = "revalidation_required"


class DossierState(str, Enum):
    CURRENT = "current"
    WITH_GAPS = "with_gaps"
    REVALIDATION_REQUIRED = "revalidation_required"


def _text(name: str, value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise GovernanceError(f"{name} must be a non-empty string")
    return value.strip()


def _timestamp(name: str, value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise GovernanceError(f"{name} must be a non-negative integer timestamp")
    return value


def _digest(name: str, value: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(ch not in "0123456789abcdef" for ch in value)
    ):
        raise GovernanceError(f"{name} must be a lowercase SHA-256 digest")
    return value


def _payload(value: Any) -> dict[str, Any]:
    normalized = json.loads(canonical_json(value))
    if not isinstance(normalized, dict):
        raise GovernanceError("dossier artifact payload must canonicalize to an object")
    return normalized


def _unique_findings(values: Iterable[str]) -> tuple[str, ...]:
    findings = tuple(sorted({_text("finding", value) for value in values}))
    return findings


@dataclass(frozen=True, slots=True)
class GovernanceArtifact:
    domain: str
    artifact_type: str
    artifact_id: str
    payload: dict[str, Any]
    digest: str
    state: DossierArtifactState = DossierArtifactState.CURRENT
    findings: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for name in ("domain", "artifact_type", "artifact_id"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        if not isinstance(self.payload, dict):
            raise GovernanceError("artifact payload must be an object")
        _digest("artifact digest", self.digest)
        if sha256_digest(self.payload) != self.digest:
            raise GovernanceError("artifact digest does not match canonical payload")
        object.__setattr__(self, "findings", _unique_findings(self.findings))
        if self.state is DossierArtifactState.CURRENT and self.findings:
            raise GovernanceError("current artifact cannot carry gap or revalidation findings")
        if self.state is not DossierArtifactState.CURRENT and not self.findings:
            raise GovernanceError("non-current artifact must explain its findings")


@dataclass(frozen=True, slots=True)
class GovernanceDossier:
    schema_version: str
    release_version: str
    entity_id: str
    generated_at: int
    source_revision: str
    inventory_snapshot_digest: str
    artifacts: tuple[GovernanceArtifact, ...]
    coverage: dict[str, int]
    state: DossierState
    findings: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.schema_version != DOSSIER_SCHEMA_VERSION:
            raise GovernanceError("unsupported dossier schema version")
        if self.release_version != RELEASE_VERSION:
            raise GovernanceError("unsupported DORAOps release version")
        object.__setattr__(self, "entity_id", _text("entity_id", self.entity_id))
        object.__setattr__(self, "source_revision", _text("source_revision", self.source_revision))
        _timestamp("generated_at", self.generated_at)
        _digest("inventory_snapshot_digest", self.inventory_snapshot_digest)
        if not self.artifacts:
            raise GovernanceError("governance dossier must contain artifacts")
        keys = tuple(
            (item.domain, item.artifact_type, item.artifact_id)
            for item in self.artifacts
        )
        if len(keys) != len(set(keys)):
            raise GovernanceError("dossier artifact identities must be unique")
        if not isinstance(self.coverage, dict) or not self.coverage:
            raise GovernanceError("dossier coverage must be a non-empty object")
        for domain, count in self.coverage.items():
            _text("coverage domain", domain)
            if isinstance(count, bool) or not isinstance(count, int) or count < 0:
                raise GovernanceError("coverage counts must be non-negative integers")
        object.__setattr__(self, "findings", _unique_findings(self.findings))
        expected = _dossier_state(self.artifacts)
        if self.state is not expected:
            raise GovernanceError("dossier state is inconsistent with artifact states")
        expected_findings = tuple(
            sorted(
                f"{item.domain}:{item.artifact_type}:{item.artifact_id}:{finding}"
                for item in self.artifacts
                for finding in item.findings
            )
        )
        if self.findings != expected_findings:
            raise GovernanceError("dossier findings are inconsistent with artifact findings")

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


def _dossier_state(artifacts: Iterable[GovernanceArtifact]) -> DossierState:
    states = {item.state for item in artifacts}
    if DossierArtifactState.REVALIDATION_REQUIRED in states:
        return DossierState.REVALIDATION_REQUIRED
    if DossierArtifactState.WITH_GAPS in states:
        return DossierState.WITH_GAPS
    return DossierState.CURRENT


def _artifact_id(value: Any) -> str:
    for name in (
        "entity_id",
        "provider_id",
        "function_id",
        "process_id",
        "service_id",
        "asset_id",
        "third_party_service_id",
        "edge_id",
        "scenario_id",
        "control_id",
        "policy_id",
        "incident_id",
        "event_id",
        "impact_id",
        "test_id",
        "execution_id",
        "finding_id",
        "remediation_id",
        "retest_id",
        "arrangement_id",
        "observation_id",
        "exit_plan_id",
    ):
        candidate = getattr(value, name, None)
        if isinstance(candidate, str) and candidate.strip():
            return candidate.strip()
    return sha256_digest(value)[:16]


class GovernanceDossierBuilder:
    """Build a deterministic dossier while revalidating represented current state."""

    def __init__(
        self,
        inventory: InventoryRegistry,
        *,
        entity_id: str,
        generated_at: int,
        source_revision: str,
    ) -> None:
        self.inventory = inventory
        self.entity_id = _text("entity_id", entity_id)
        self.generated_at = _timestamp("generated_at", generated_at)
        self.source_revision = _text("source_revision", source_revision)
        self.inventory_snapshot_digest = inventory.snapshot_digest(self.entity_id)
        self._artifacts: dict[tuple[str, str, str], GovernanceArtifact] = {}
        self._add_inventory()

    def _add(
        self,
        domain: str,
        artifact_type: str,
        artifact_id: str,
        value: Any,
        *,
        state: DossierArtifactState = DossierArtifactState.CURRENT,
        findings: Iterable[str] = (),
    ) -> GovernanceArtifact:
        payload = _payload(value)
        artifact = GovernanceArtifact(
            domain=domain,
            artifact_type=artifact_type,
            artifact_id=artifact_id,
            payload=payload,
            digest=sha256_digest(payload),
            state=state,
            findings=tuple(findings),
        )
        key = (artifact.domain, artifact.artifact_type, artifact.artifact_id)
        existing = self._artifacts.get(key)
        if existing is not None and existing != artifact:
            raise GovernanceError("dossier artifact identity conflicts with different content")
        self._artifacts.setdefault(key, artifact)
        return artifact

    def _add_inventory(self) -> None:
        entity = self.inventory.entity(self.entity_id)
        self._add("inventory", "financial_entity", entity.entity_id, entity)
        for provider in self.inventory.providers(self.entity_id):
            self._add("inventory", "third_party_provider", provider.provider_id, provider)
        for node in self.inventory.nodes(self.entity_id):
            self._add("inventory", type(node).__name__, _artifact_id(node), node)
        for edge in self.inventory.edges(self.entity_id):
            self._add("inventory", "dependency_edge", edge.edge_id, edge)
        manifest = self.inventory.snapshot_manifest(self.entity_id)
        artifact = self._add(
            "inventory",
            "inventory_snapshot_manifest",
            self.entity_id,
            manifest,
        )
        if artifact.digest != self.inventory_snapshot_digest:
            raise GovernanceError("inventory snapshot manifest does not reproduce inventory digest")

    def add_risk_decision(
        self,
        decision: ICTRiskDecision,
        scenario: ICTRiskScenario,
        controls: Iterable[ICTControlObservation],
        policy: ICTRiskPolicy,
    ) -> None:
        controls_tuple = tuple(controls)
        if decision.entity_id != self.entity_id:
            raise GovernanceError("risk decision is outside dossier entity scope")
        self._add("ict_risk", "risk_scenario", scenario.scenario_id, scenario)
        self._add("ict_risk", "risk_policy", policy.policy_id, policy)
        for control in controls_tuple:
            self._add("ict_risk", "control_observation", control.control_id, control)
        state = DossierArtifactState.CURRENT
        findings: tuple[str, ...] = ()
        try:
            assert_risk_decision_current(decision, self.inventory, scenario, controls_tuple, policy)
        except GovernanceError as exc:
            state = DossierArtifactState.REVALIDATION_REQUIRED
            findings = (str(exc),)
        self._add(
            "ict_risk",
            "risk_decision",
            decision.scenario_id,
            decision,
            state=state,
            findings=findings,
        )

    def add_incident(
        self,
        registry: IncidentRegistry,
        incident_id: str,
        policy: IncidentClassificationPolicy,
        review: IncidentClassificationReview | None = None,
    ) -> None:
        incident = registry.incident(self.entity_id, incident_id)
        current_inventory = self.inventory.snapshot_digest(self.entity_id)
        incident_state = DossierArtifactState.CURRENT
        incident_findings: tuple[str, ...] = ()
        if incident.inventory_snapshot_digest != current_inventory:
            incident_state = DossierArtifactState.REVALIDATION_REQUIRED
            incident_findings = ("incident inventory snapshot is stale",)
        self._add(
            "incident",
            "incident",
            incident.incident_id,
            incident,
            state=incident_state,
            findings=incident_findings,
        )
        for event in registry.events(self.entity_id, incident_id):
            self._add("incident", "incident_event", event.event_id, event)
        for impact in registry.impacts(self.entity_id, incident_id):
            self._add("incident", "incident_impact", impact.impact_id, impact)
        self._add("incident", "classification_policy", policy.policy_id, policy)

        readiness = assess_classification_readiness(registry, self.entity_id, incident_id, policy)
        readiness_findings = list(readiness.missing_inputs)
        readiness_state = (
            DossierArtifactState.WITH_GAPS
            if readiness.state is ClassificationReadinessState.INCOMPLETE
            else DossierArtifactState.CURRENT
        )
        if incident_state is DossierArtifactState.REVALIDATION_REQUIRED:
            readiness_state = DossierArtifactState.REVALIDATION_REQUIRED
            readiness_findings.append("incident inventory snapshot requires revalidation")
        elif review is None and readiness.state is ClassificationReadinessState.READY_FOR_HUMAN_REVIEW:
            readiness_state = DossierArtifactState.WITH_GAPS
            readiness_findings.append("human_classification_review_missing")
        self._add(
            "incident",
            "classification_readiness",
            incident.incident_id,
            readiness,
            state=readiness_state,
            findings=readiness_findings,
        )

        if review is not None:
            review_state = DossierArtifactState.CURRENT
            review_findings: list[str] = []
            if readiness.state is not ClassificationReadinessState.READY_FOR_HUMAN_REVIEW:
                review_state = DossierArtifactState.REVALIDATION_REQUIRED
                review_findings.append("review exists for incomplete current incident evidence")
            if review.readiness_digest != readiness.evidence_digest:
                review_state = DossierArtifactState.REVALIDATION_REQUIRED
                review_findings.append("review is stale for current readiness")
            if review.incident_evidence_snapshot_digest != readiness.incident_evidence_snapshot_digest:
                review_state = DossierArtifactState.REVALIDATION_REQUIRED
                review_findings.append("review is stale for current incident evidence")
            self._add(
                "incident",
                "classification_review",
                incident.incident_id,
                review,
                state=review_state,
                findings=review_findings,
            )

    def add_resilience_test(
        self,
        plan: ResilienceTestPlan,
        risk_decisions: Iterable[ICTRiskDecision],
        execution: ResilienceTestExecution,
        resolution: ResilienceTestResolution,
        findings: Iterable[ResilienceFinding] = (),
        remediations: Iterable[RemediationEvidence] = (),
        retests: Iterable[RetestEvidence] = (),
    ) -> None:
        risk_tuple = tuple(risk_decisions)
        finding_tuple = tuple(findings)
        remediation_tuple = tuple(remediations)
        retest_tuple = tuple(retests)
        if plan.entity_id != self.entity_id:
            raise GovernanceError("resilience test is outside dossier entity scope")
        self._add("resilience_test", "test_plan", plan.test_id, plan)
        self._add("resilience_test", "test_execution", execution.execution_id, execution)
        for item in finding_tuple:
            self._add("resilience_test", "finding", item.finding_id, item)
        for item in remediation_tuple:
            self._add("resilience_test", "remediation", item.remediation_id, item)
        for item in retest_tuple:
            self._add("resilience_test", "retest", item.retest_id, item)

        resolution_state = DossierArtifactState.CURRENT
        resolution_findings: list[str] = []
        try:
            assert_test_plan_current(plan, self.inventory, risk_tuple)
            current_resolution = resolve_test(
                plan,
                execution,
                finding_tuple,
                remediation_tuple,
                retest_tuple,
            )
            if current_resolution.evidence_digest != resolution.evidence_digest:
                raise GovernanceError("test resolution is stale for current lifecycle evidence")
        except GovernanceError as exc:
            resolution_state = DossierArtifactState.REVALIDATION_REQUIRED
            resolution_findings.append(str(exc))
        if resolution_state is DossierArtifactState.CURRENT and resolution.state in {
            TestResolutionState.BLOCKED,
            TestResolutionState.INCOMPLETE,
        }:
            resolution_state = DossierArtifactState.WITH_GAPS
            resolution_findings.extend(
                f"unresolved_finding:{digest}"
                for digest in resolution.unresolved_finding_digests
            )
            if not resolution_findings:
                resolution_findings.append(f"test_resolution:{resolution.state.value}")
        self._add(
            "resilience_test",
            "test_resolution",
            plan.test_id,
            resolution,
            state=resolution_state,
            findings=resolution_findings,
        )

    def add_third_party_register(
        self,
        register: ThirdPartyRegister,
        policy: ThirdPartyGovernancePolicy,
        *,
        as_of: int,
    ) -> None:
        if policy.entity_id != self.entity_id:
            raise GovernanceError("third-party policy is outside dossier entity scope")
        snapshot = build_register_snapshot(register, policy, as_of=as_of)
        self._add("third_party", "governance_policy", policy.policy_id, policy)
        for arrangement in register.arrangements(self.entity_id):
            self._add("third_party", "arrangement", arrangement.arrangement_id, arrangement)
            observation = register.latest_observation(arrangement)
            if observation is not None:
                self._add("third_party", "dependency_observation", observation.observation_id, observation)
            exit_plan = register.latest_exit_plan(arrangement)
            if exit_plan is not None:
                self._add("third_party", "exit_plan", exit_plan.exit_plan_id, exit_plan)
        state = DossierArtifactState.CURRENT
        findings: tuple[str, ...] = ()
        if snapshot.gaps:
            state = DossierArtifactState.WITH_GAPS
            findings = tuple(
                f"{gap.arrangement_id}:{gap.code.value}:{gap.detail}"
                for gap in snapshot.gaps
            )
        self._add(
            "third_party",
            "register_snapshot",
            self.entity_id,
            snapshot,
            state=state,
            findings=findings,
        )

    def build(self) -> GovernanceDossier:
        artifacts = tuple(
            sorted(
                self._artifacts.values(),
                key=lambda item: (item.domain, item.artifact_type, item.artifact_id),
            )
        )
        coverage: dict[str, int] = {}
        for artifact in artifacts:
            coverage[artifact.domain] = coverage.get(artifact.domain, 0) + 1
        findings = tuple(
            sorted(
                f"{item.domain}:{item.artifact_type}:{item.artifact_id}:{finding}"
                for item in artifacts
                for finding in item.findings
            )
        )
        return GovernanceDossier(
            schema_version=DOSSIER_SCHEMA_VERSION,
            release_version=RELEASE_VERSION,
            entity_id=self.entity_id,
            generated_at=self.generated_at,
            source_revision=self.source_revision,
            inventory_snapshot_digest=self.inventory_snapshot_digest,
            artifacts=artifacts,
            coverage=coverage,
            state=_dossier_state(artifacts),
            findings=findings,
        )


def dossier_document(dossier: GovernanceDossier) -> dict[str, Any]:
    payload = json.loads(canonical_json(dossier))
    return {
        "dossier": payload,
        "dossier_digest": sha256_digest(payload),
    }


def verify_dossier_document(document: Any) -> str:
    if not isinstance(document, dict) or set(document) != {"dossier", "dossier_digest"}:
        raise GovernanceError("dossier document must contain exactly dossier and dossier_digest")
    dossier = document["dossier"]
    digest = document["dossier_digest"]
    if not isinstance(dossier, dict):
        raise GovernanceError("dossier must be an object")
    _digest("dossier_digest", digest)
    if sha256_digest(dossier) != digest:
        raise GovernanceError("dossier digest mismatch")
    if dossier.get("schema_version") != DOSSIER_SCHEMA_VERSION:
        raise GovernanceError("unsupported dossier schema_version")
    if dossier.get("release_version") != RELEASE_VERSION:
        raise GovernanceError("unsupported dossier release_version")
    artifacts = dossier.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise GovernanceError("dossier artifacts must be a non-empty array")

    identities: set[tuple[str, str, str]] = set()
    states: set[str] = set()
    expected_findings: list[str] = []
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            raise GovernanceError("dossier artifact must be an object")
        required = {"domain", "artifact_type", "artifact_id", "payload", "digest", "state", "findings"}
        if set(artifact) != required:
            raise GovernanceError("dossier artifact has unexpected fields")
        identity = (
            _text("artifact domain", artifact["domain"]),
            _text("artifact_type", artifact["artifact_type"]),
            _text("artifact_id", artifact["artifact_id"]),
        )
        if identity in identities:
            raise GovernanceError("duplicate dossier artifact identity")
        identities.add(identity)
        if not isinstance(artifact["payload"], dict):
            raise GovernanceError("artifact payload must be an object")
        _digest("artifact digest", artifact["digest"])
        if sha256_digest(artifact["payload"]) != artifact["digest"]:
            raise GovernanceError("artifact payload digest mismatch")
        try:
            state = DossierArtifactState(artifact["state"])
        except (TypeError, ValueError) as exc:
            raise GovernanceError("unsupported artifact state") from exc
        states.add(state.value)
        artifact_findings = artifact["findings"]
        if not isinstance(artifact_findings, list) or any(
            not isinstance(item, str) or not item.strip() for item in artifact_findings
        ):
            raise GovernanceError("artifact findings must be non-empty strings")
        if len(artifact_findings) != len(set(artifact_findings)):
            raise GovernanceError("artifact findings must be unique")
        if state is DossierArtifactState.CURRENT and artifact_findings:
            raise GovernanceError("current artifact cannot carry findings")
        if state is not DossierArtifactState.CURRENT and not artifact_findings:
            raise GovernanceError("non-current artifact must carry findings")
        expected_findings.extend(
            f"{identity[0]}:{identity[1]}:{identity[2]}:{finding}"
            for finding in artifact_findings
        )

    expected_state = DossierState.CURRENT.value
    if DossierArtifactState.REVALIDATION_REQUIRED.value in states:
        expected_state = DossierState.REVALIDATION_REQUIRED.value
    elif DossierArtifactState.WITH_GAPS.value in states:
        expected_state = DossierState.WITH_GAPS.value
    if dossier.get("state") != expected_state:
        raise GovernanceError("dossier state does not match artifact states")
    if dossier.get("findings") != sorted(expected_findings):
        raise GovernanceError("dossier findings do not match artifact findings")

    inventory_digest = dossier.get("inventory_snapshot_digest")
    _digest("inventory_snapshot_digest", inventory_digest)
    manifests = [
        artifact
        for artifact in artifacts
        if artifact["domain"] == "inventory"
        and artifact["artifact_type"] == "inventory_snapshot_manifest"
    ]
    if len(manifests) != 1 or manifests[0]["digest"] != inventory_digest:
        raise GovernanceError("inventory snapshot manifest does not match dossier inventory digest")
    return digest
