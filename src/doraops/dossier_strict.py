from __future__ import annotations

from typing import Any

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

    def build(self) -> GovernanceDossier:
        if self.inventory.snapshot_digest(self.entity_id) != self.inventory_snapshot_digest:
            raise GovernanceError("inventory changed during dossier construction; rebuild required")
        return super().build()
