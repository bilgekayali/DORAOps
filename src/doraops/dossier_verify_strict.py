from __future__ import annotations

from typing import Any

from .dossier import verify_dossier_document as _verify_dossier_document
from .inventory import GovernanceError


def _digest_list(name: str, value: Any) -> list[str]:
    if not isinstance(value, list):
        raise GovernanceError(f"inventory manifest {name} must be an array")
    if value != sorted(value) or len(value) != len(set(value)):
        raise GovernanceError(f"inventory manifest {name} must be sorted and unique")
    for digest in value:
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(ch not in "0123456789abcdef" for ch in digest)
        ):
            raise GovernanceError(f"inventory manifest {name} contains an invalid digest")
    return value


def _require_digest_ref(name: str, value: Any, index: dict[str, dict[str, Any]]) -> dict[str, Any]:
    if not isinstance(value, str) or value not in index:
        raise GovernanceError(f"continuity {name} does not resolve to an embedded artifact")
    return index[value]


def _verify_continuity(
    artifacts: list[dict[str, Any]],
    *,
    entity_id: str,
    inventory_snapshot_digest: str,
) -> None:
    continuity = [item for item in artifacts if item["domain"] == "continuity"]
    if not continuity:
        return
    by_digest = {item["digest"]: item for item in continuity}
    by_type: dict[str, list[dict[str, Any]]] = {}
    for item in continuity:
        by_type.setdefault(item["artifact_type"], []).append(item)

    for item in by_type.get("recovery_objective", []):
        payload = item["payload"]
        if payload.get("entity_id") != entity_id:
            raise GovernanceError("continuity recovery objective is outside dossier entity scope")
        if payload.get("inventory_snapshot_digest") != inventory_snapshot_digest:
            raise GovernanceError("continuity recovery objective is stale for dossier inventory snapshot")
        target = payload.get("target")
        if not isinstance(target, dict) or target.get("entity_id") != entity_id:
            raise GovernanceError("continuity recovery objective target is outside dossier entity scope")

    for item in by_type.get("exercise_plan", []):
        payload = item["payload"]
        if payload.get("entity_id") != entity_id:
            raise GovernanceError("continuity exercise plan is outside dossier entity scope")
        if payload.get("inventory_snapshot_digest") != inventory_snapshot_digest:
            raise GovernanceError("continuity exercise plan is stale for dossier inventory snapshot")
        objective = _require_digest_ref("exercise objective_digest", payload.get("objective_digest"), by_digest)
        if objective["artifact_type"] != "recovery_objective":
            raise GovernanceError("continuity exercise objective_digest resolves to wrong artifact type")
        if payload.get("objective_target") != objective["payload"].get("target"):
            raise GovernanceError("continuity exercise objective target does not match recovery objective")

    for item in by_type.get("exercise_execution", []):
        payload = item["payload"]
        plan = _require_digest_ref("execution plan_digest", payload.get("plan_digest"), by_digest)
        if plan["artifact_type"] != "exercise_plan":
            raise GovernanceError("continuity execution plan_digest resolves to wrong artifact type")

    for item in by_type.get("recovery_observation", []):
        payload = item["payload"]
        plan = _require_digest_ref("observation plan_digest", payload.get("plan_digest"), by_digest)
        execution = _require_digest_ref("observation execution_digest", payload.get("execution_digest"), by_digest)
        if plan["artifact_type"] != "exercise_plan" or execution["artifact_type"] != "exercise_execution":
            raise GovernanceError("continuity recovery observation resolves to wrong plan/execution type")
        if execution["payload"].get("plan_digest") != plan["digest"]:
            raise GovernanceError("continuity recovery observation plan/execution bindings disagree")

    for item in by_type.get("recovery_assessment", []):
        payload = item["payload"]
        if payload.get("entity_id") != entity_id:
            raise GovernanceError("continuity recovery assessment is outside dossier entity scope")
        plan = _require_digest_ref("assessment plan_digest", payload.get("plan_digest"), by_digest)
        execution = _require_digest_ref("assessment execution_digest", payload.get("execution_digest"), by_digest)
        objective = _require_digest_ref("assessment objective_digest", payload.get("objective_digest"), by_digest)
        if plan["artifact_type"] != "exercise_plan" or execution["artifact_type"] != "exercise_execution":
            raise GovernanceError("continuity assessment resolves to wrong plan/execution type")
        if objective["artifact_type"] != "recovery_objective":
            raise GovernanceError("continuity assessment resolves to wrong recovery objective type")
        observation_digest = payload.get("observation_digest")
        if observation_digest is not None:
            observation = _require_digest_ref("assessment observation_digest", observation_digest, by_digest)
            if observation["artifact_type"] != "recovery_observation":
                raise GovernanceError("continuity assessment observation_digest resolves to wrong artifact type")
            if observation["payload"].get("plan_digest") != plan["digest"]:
                raise GovernanceError("continuity assessment observation belongs to different plan")
            if observation["payload"].get("execution_digest") != execution["digest"]:
                raise GovernanceError("continuity assessment observation belongs to different execution")
        if payload.get("operational_resilience_determined") is not False:
            raise GovernanceError("continuity assessment cannot determine operational resilience")
        if payload.get("regulatory_compliance_determined") is not False:
            raise GovernanceError("continuity assessment cannot determine regulatory compliance")

    for item in by_type.get("dependency_impact_snapshot", []):
        payload = item["payload"]
        if payload.get("entity_id") != entity_id:
            raise GovernanceError("dependency impact snapshot is outside dossier entity scope")
        if payload.get("inventory_snapshot_digest") != inventory_snapshot_digest:
            raise GovernanceError("dependency impact snapshot is stale for dossier inventory snapshot")
        if payload.get("runtime_impact_determined") is not False:
            raise GovernanceError("dependency topology evidence cannot determine runtime impact")

    for item in by_type.get("finding", []):
        payload = item["payload"]
        if payload.get("entity_id") != entity_id:
            raise GovernanceError("continuity finding is outside dossier entity scope")
        assessment = _require_digest_ref("finding assessment_digest", payload.get("assessment_digest"), by_digest)
        if assessment["artifact_type"] != "recovery_assessment":
            raise GovernanceError("continuity finding assessment_digest resolves to wrong artifact type")

    for item in by_type.get("remediation", []):
        payload = item["payload"]
        finding = _require_digest_ref("remediation finding_digest", payload.get("finding_digest"), by_digest)
        if finding["artifact_type"] != "finding":
            raise GovernanceError("continuity remediation finding_digest resolves to wrong artifact type")

    for item in by_type.get("retest", []):
        payload = item["payload"]
        finding = _require_digest_ref("retest finding_digest", payload.get("finding_digest"), by_digest)
        remediation = _require_digest_ref("retest remediation_digest", payload.get("remediation_digest"), by_digest)
        if finding["artifact_type"] != "finding" or remediation["artifact_type"] != "remediation":
            raise GovernanceError("continuity retest resolves to wrong lifecycle artifact type")
        if remediation["payload"].get("finding_digest") != finding["digest"]:
            raise GovernanceError("continuity retest finding/remediation bindings disagree")

    for item in by_type.get("continuity_resolution", []):
        payload = item["payload"]
        plan = _require_digest_ref("resolution plan_digest", payload.get("plan_digest"), by_digest)
        assessment = _require_digest_ref("resolution assessment_digest", payload.get("assessment_digest"), by_digest)
        if plan["artifact_type"] != "exercise_plan" or assessment["artifact_type"] != "recovery_assessment":
            raise GovernanceError("continuity resolution resolves to wrong plan/assessment artifact type")
        unresolved = payload.get("unresolved_finding_digests")
        if not isinstance(unresolved, list):
            raise GovernanceError("continuity resolution unresolved_finding_digests must be an array")
        for finding_digest in unresolved:
            finding = _require_digest_ref("resolution unresolved finding", finding_digest, by_digest)
            if finding["artifact_type"] != "finding":
                raise GovernanceError("continuity resolution unresolved digest is not a finding")


def verify_dossier_document(document: Any) -> str:
    """Verify cryptographic and cross-artifact dossier semantics offline."""
    digest = _verify_dossier_document(document)
    dossier = document["dossier"]
    artifacts = dossier["artifacts"]

    coverage: dict[str, int] = {}
    for artifact in artifacts:
        domain = artifact["domain"]
        coverage[domain] = coverage.get(domain, 0) + 1
    if dossier.get("coverage") != coverage:
        raise GovernanceError("dossier coverage does not match embedded artifacts")

    entity_id = dossier.get("entity_id")
    if not isinstance(entity_id, str) or not entity_id.strip():
        raise GovernanceError("dossier entity_id must be a non-empty string")
    generated_at = dossier.get("generated_at")
    if isinstance(generated_at, bool) or not isinstance(generated_at, int) or generated_at < 0:
        raise GovernanceError("dossier generated_at must be a non-negative integer")
    source_revision = dossier.get("source_revision")
    if not isinstance(source_revision, str) or not source_revision.strip():
        raise GovernanceError("dossier source_revision must be a non-empty string")

    inventory = [item for item in artifacts if item["domain"] == "inventory"]
    manifests = [item for item in inventory if item["artifact_type"] == "inventory_snapshot_manifest"]
    entities = [item for item in inventory if item["artifact_type"] == "financial_entity"]
    if len(manifests) != 1 or len(entities) != 1:
        raise GovernanceError("dossier requires exactly one inventory manifest and financial entity")
    if entities[0]["artifact_id"] != entity_id:
        raise GovernanceError("financial entity artifact does not match dossier entity_id")

    manifest = manifests[0]["payload"]
    if not isinstance(manifest, dict) or set(manifest) != {"entity", "nodes", "providers", "edges"}:
        raise GovernanceError("inventory snapshot manifest has unexpected fields")
    nodes = _digest_list("nodes", manifest["nodes"])
    providers = _digest_list("providers", manifest["providers"])
    edges = _digest_list("edges", manifest["edges"])
    entity_digest = manifest["entity"]
    if entity_digest != entities[0]["digest"]:
        raise GovernanceError("inventory manifest entity digest does not match embedded entity")

    expected_providers = sorted(
        item["digest"] for item in inventory if item["artifact_type"] == "third_party_provider"
    )
    expected_edges = sorted(
        item["digest"] for item in inventory if item["artifact_type"] == "dependency_edge"
    )
    excluded = {
        "inventory_snapshot_manifest",
        "financial_entity",
        "third_party_provider",
        "dependency_edge",
    }
    expected_nodes = sorted(
        item["digest"] for item in inventory if item["artifact_type"] not in excluded
    )
    if providers != expected_providers:
        raise GovernanceError("inventory manifest provider digests do not match embedded providers")
    if edges != expected_edges:
        raise GovernanceError("inventory manifest edge digests do not match embedded edges")
    if nodes != expected_nodes:
        raise GovernanceError("inventory manifest node digests do not match embedded nodes")

    for artifact in inventory:
        if artifact["artifact_type"] == "inventory_snapshot_manifest":
            continue
        payload = artifact["payload"]
        if payload.get("entity_id") != entity_id:
            raise GovernanceError("inventory artifact is outside dossier entity scope")

    _verify_continuity(
        artifacts,
        entity_id=entity_id,
        inventory_snapshot_digest=dossier.get("inventory_snapshot_digest"),
    )
    return digest
