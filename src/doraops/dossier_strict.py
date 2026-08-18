from __future__ import annotations

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


class GovernanceDossierBuilder(_GovernanceDossierBuilder):
    """Public dossier builder preserving strict release-governance boundaries."""

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

    def build(self) -> GovernanceDossier:
        if self.inventory.snapshot_digest(self.entity_id) != self.inventory_snapshot_digest:
            raise GovernanceError("inventory changed during dossier construction; rebuild required")
        return super().build()
