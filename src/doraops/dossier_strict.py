from __future__ import annotations

from typing import Any, Iterable

from .continuity import (
    ContinuityAssessment,
    ContinuityExerciseExecution,
    ContinuityExercisePlan,
    ContinuityFinding,
    ContinuityRemediationEvidence,
    ContinuityResolution,
    ContinuityResolutionState,
    ContinuityRetestEvidence,
    DependencyImpactSnapshot,
    RecoveryAssessmentState,
    RecoveryObjectiveProfile,
    RecoveryObservation,
    assert_continuity_plan_current,
    assert_dependency_impact_current,
    assert_recovery_objective_current,
    assess_continuity_recovery,
)
from .continuity_strict import resolve_continuity
from .dossier import (
    DossierArtifactState,
    GovernanceDossier,
    GovernanceDossierBuilder as _GovernanceDossierBuilder,
)
from .inventory import GovernanceError
from .third_party_strict import (
    ThirdPartyGovernancePolicy,
    ThirdPartyRegister,
    build_register_snapshot,
)


def _inventory_node_id(node: Any) -> str:
    for name in (
        "function_id",
        "process_id",
        "service_id",
        "asset_id",
        "third_party_service_id",
    ):
        value = getattr(node, name, None)
        if isinstance(value, str) and value.strip():
            return value.strip()
    raise GovernanceError("inventory node does not expose a governed identity")


class GovernanceDossierBuilder(_GovernanceDossierBuilder):
    """Public dossier builder preserving strict release-governance boundaries."""

    def _add_inventory(self) -> None:
        entity = self.inventory.entity(self.entity_id)
        self._add("inventory", "financial_entity", entity.entity_id, entity)
        for provider in self.inventory.providers(self.entity_id):
            self._add("inventory", "third_party_provider", provider.provider_id, provider)
        for node in self.inventory.nodes(self.entity_id):
            self._add("inventory", type(node).__name__, _inventory_node_id(node), node)
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

    def add_third_party_register(
        self,
        register: ThirdPartyRegister,
        policy: ThirdPartyGovernancePolicy,
        *,
        as_of: int,
    ) -> None:
        if not isinstance(register, ThirdPartyRegister):
            raise GovernanceError("dossier requires the strict public ThirdPartyRegister")
        if policy.entity_id != self.entity_id:
            raise GovernanceError("third-party policy is outside dossier entity scope")
        snapshot = build_register_snapshot(register, policy, as_of=as_of)
        self._add("third_party", "governance_policy", policy.policy_id, policy)
        for arrangement in register.arrangements(self.entity_id):
            self._add("third_party", "arrangement", arrangement.arrangement_id, arrangement)
            observation = register.latest_observation(arrangement)
            if observation is not None:
                self._add(
                    "third_party",
                    "dependency_observation",
                    observation.observation_id,
                    observation,
                )
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

    def add_continuity_recovery(
        self,
        objective: RecoveryObjectiveProfile,
        plan: ContinuityExercisePlan,
        execution: ContinuityExerciseExecution,
        assessment: ContinuityAssessment,
        *,
        observations: Iterable[RecoveryObservation] = (),
        impact_snapshot: DependencyImpactSnapshot | None = None,
        findings: Iterable[ContinuityFinding] = (),
        remediations: Iterable[ContinuityRemediationEvidence] = (),
        retests: Iterable[ContinuityRetestEvidence] = (),
        resolution: ContinuityResolution | None = None,
    ) -> None:
        """Add exact continuity/recovery evidence and revalidate represented current state."""
        if objective.entity_id != self.entity_id or plan.entity_id != self.entity_id:
            raise GovernanceError("continuity evidence is outside dossier entity scope")
        observation_tuple = tuple(observations)
        finding_tuple = tuple(findings)
        remediation_tuple = tuple(remediations)
        retest_tuple = tuple(retests)

        objective_state = DossierArtifactState.CURRENT
        objective_findings: list[str] = []
        try:
            assert_recovery_objective_current(objective, self.inventory)
        except GovernanceError as exc:
            objective_state = DossierArtifactState.REVALIDATION_REQUIRED
            objective_findings.append(str(exc))
        self._add(
            "continuity",
            "recovery_objective",
            objective.objective_id,
            objective,
            state=objective_state,
            findings=objective_findings,
        )

        plan_state = DossierArtifactState.CURRENT
        plan_findings: list[str] = []
        try:
            assert_continuity_plan_current(plan, objective, self.inventory)
        except GovernanceError as exc:
            plan_state = DossierArtifactState.REVALIDATION_REQUIRED
            plan_findings.append(str(exc))
        self._add(
            "continuity",
            "exercise_plan",
            plan.exercise_id,
            plan,
            state=plan_state,
            findings=plan_findings,
        )
        self._add("continuity", "exercise_execution", execution.execution_id, execution)
        for item in observation_tuple:
            self._add("continuity", "recovery_observation", item.observation_id, item)

        assessment_state = DossierArtifactState.CURRENT
        assessment_findings: list[str] = []
        try:
            current = assess_continuity_recovery(
                plan,
                objective,
                execution,
                observation_tuple,
                self.inventory,
                assessed_at=assessment.assessed_at,
            )
            if current.evidence_digest != assessment.evidence_digest:
                raise GovernanceError("continuity assessment is stale for current recovery evidence")
        except GovernanceError as exc:
            assessment_state = DossierArtifactState.REVALIDATION_REQUIRED
            assessment_findings.append(str(exc))
        if assessment_state is DossierArtifactState.CURRENT:
            if assessment.state is RecoveryAssessmentState.BREACHED:
                assessment_state = DossierArtifactState.WITH_GAPS
                assessment_findings.append("recovery_objectives_breached")
            elif assessment.state is RecoveryAssessmentState.INCOMPLETE:
                assessment_state = DossierArtifactState.WITH_GAPS
                assessment_findings.extend(assessment.gaps or ("recovery_evidence_incomplete",))
        self._add(
            "continuity",
            "recovery_assessment",
            plan.exercise_id,
            assessment,
            state=assessment_state,
            findings=assessment_findings,
        )

        if impact_snapshot is not None:
            impact_state = DossierArtifactState.CURRENT
            impact_findings: list[str] = []
            try:
                if impact_snapshot.entity_id != self.entity_id:
                    raise GovernanceError("dependency impact snapshot is outside dossier entity scope")
                assert_dependency_impact_current(impact_snapshot, self.inventory)
            except GovernanceError as exc:
                impact_state = DossierArtifactState.REVALIDATION_REQUIRED
                impact_findings.append(str(exc))
            self._add(
                "continuity",
                "dependency_impact_snapshot",
                plan.exercise_id,
                impact_snapshot,
                state=impact_state,
                findings=impact_findings,
            )

        for item in finding_tuple:
            self._add("continuity", "finding", item.finding_id, item)
        for item in remediation_tuple:
            self._add("continuity", "remediation", item.remediation_id, item)
        for item in retest_tuple:
            self._add("continuity", "retest", item.retest_id, item)

        if resolution is not None:
            resolution_state = DossierArtifactState.CURRENT
            resolution_findings: list[str] = []
            try:
                current_resolution = resolve_continuity(
                    plan,
                    assessment,
                    finding_tuple,
                    remediation_tuple,
                    retest_tuple,
                )
                if current_resolution.evidence_digest != resolution.evidence_digest:
                    raise GovernanceError("continuity resolution is stale for current lifecycle evidence")
            except GovernanceError as exc:
                resolution_state = DossierArtifactState.REVALIDATION_REQUIRED
                resolution_findings.append(str(exc))
            if resolution_state is DossierArtifactState.CURRENT and resolution.state in {
                ContinuityResolutionState.BLOCKED,
                ContinuityResolutionState.INCOMPLETE,
            }:
                resolution_state = DossierArtifactState.WITH_GAPS
                resolution_findings.extend(
                    f"unresolved_finding:{digest}"
                    for digest in resolution.unresolved_finding_digests
                )
                if not resolution_findings:
                    resolution_findings.append(f"continuity_resolution:{resolution.state.value}")
            self._add(
                "continuity",
                "continuity_resolution",
                plan.exercise_id,
                resolution,
                state=resolution_state,
                findings=resolution_findings,
            )

    def build(self) -> GovernanceDossier:
        if self.inventory.snapshot_digest(self.entity_id) != self.inventory_snapshot_digest:
            raise GovernanceError("inventory changed during dossier construction; rebuild required")
        return super().build()
