from __future__ import annotations

from typing import Any

from .dossier import verify_dossier_document as _verify_dossier_document
from .inventory import GovernanceError


_RECOVERY_METRICS = {
    "maximum_tolerable_disruption",
    "recovery_time_objective",
    "recovery_point_objective",
    "minimum_service_level",
}


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


def _non_negative_int(name: str, value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise GovernanceError(f"continuity {name} must be a non-negative integer")
    return value


def _require_digest_ref(name: str, value: Any, index: dict[str, dict[str, Any]]) -> dict[str, Any]:
    if not isinstance(value, str) or value not in index:
        raise GovernanceError(f"continuity {name} does not resolve to an embedded artifact")
    return index[value]


def _assessment_semantics(
    assessment: dict[str, Any],
    objective: dict[str, Any],
    observation: dict[str, Any] | None,
) -> None:
    metrics = assessment.get("metric_assessments")
    if not isinstance(metrics, list) or len(metrics) != 4:
        raise GovernanceError("continuity assessment must contain exactly four recovery metrics")
    metric_names = [item.get("metric") for item in metrics if isinstance(item, dict)]
    if len(metric_names) != 4 or set(metric_names) != _RECOVERY_METRICS or len(metric_names) != len(set(metric_names)):
        raise GovernanceError("continuity assessment recovery metric set is invalid")

    thresholds = {
        "maximum_tolerable_disruption": objective.get("maximum_tolerable_disruption_seconds"),
        "recovery_time_objective": objective.get("recovery_time_objective_seconds"),
        "recovery_point_objective": objective.get("recovery_point_objective_seconds"),
        "minimum_service_level": objective.get("minimum_service_level_basis_points"),
    }
    observed = {
        "maximum_tolerable_disruption": None if observation is None else observation.get("restoration_time_seconds"),
        "recovery_time_objective": None if observation is None else observation.get("restoration_time_seconds"),
        "recovery_point_objective": None if observation is None else observation.get("recovery_point_loss_seconds"),
        "minimum_service_level": None if observation is None else observation.get("achieved_service_level_basis_points"),
    }

    derived_states: list[str] = []
    expected_gaps: list[str] = []
    for item in metrics:
        if not isinstance(item, dict):
            raise GovernanceError("continuity recovery metric assessment must be an object")
        metric = item.get("metric")
        threshold = _non_negative_int(f"{metric} threshold", thresholds[metric])
        if item.get("threshold_value") != threshold:
            raise GovernanceError("continuity assessment threshold differs from bound recovery objective")
        value = observed[metric]
        if value is None:
            expected_state = "incomplete"
            expected_gaps.append(f"missing_metric:{metric}")
            if item.get("observed_value") is not None:
                raise GovernanceError("incomplete continuity metric cannot carry an observed value")
        else:
            value = _non_negative_int(f"{metric} observed value", value)
            if item.get("observed_value") != value:
                raise GovernanceError("continuity assessment observed value differs from bound recovery observation")
            met = value >= threshold if metric == "minimum_service_level" else value <= threshold
            expected_state = "met" if met else "breached"
        if item.get("state") != expected_state:
            raise GovernanceError("continuity recovery metric state is inconsistent with threshold evidence")
        derived_states.append(expected_state)

    if "incomplete" in derived_states:
        expected_assessment_state = "incomplete"
    elif "breached" in derived_states:
        expected_assessment_state = "breached"
    else:
        expected_assessment_state = "met"
    if assessment.get("state") != expected_assessment_state:
        raise GovernanceError("continuity assessment aggregate state is inconsistent with recovery metrics")
    if assessment.get("gaps") != sorted(expected_gaps):
        raise GovernanceError("continuity assessment gaps are inconsistent with missing recovery metrics")


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
    if len(by_digest) != len(continuity):
        raise GovernanceError("continuity artifact digests must be unique within the dossier")
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
        mtd = _non_negative_int("maximum tolerable disruption", payload.get("maximum_tolerable_disruption_seconds"))
        rto = _non_negative_int("recovery time objective", payload.get("recovery_time_objective_seconds"))
        if mtd < 1 or rto < 1 or rto > mtd:
            raise GovernanceError("continuity recovery objective contains incoherent MTD/RTO values")
        _non_negative_int("recovery point objective", payload.get("recovery_point_objective_seconds"))
        service_level = _non_negative_int("minimum service level", payload.get("minimum_service_level_basis_points"))
        if not 1 <= service_level <= 10_000:
            raise GovernanceError("continuity minimum service level must be between 1 and 10000 basis points")

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
        _non_negative_int("exercise planned_at", payload.get("planned_at"))

    for item in by_type.get("exercise_execution", []):
        payload = item["payload"]
        plan = _require_digest_ref("execution plan_digest", payload.get("plan_digest"), by_digest)
        if plan["artifact_type"] != "exercise_plan":
            raise GovernanceError("continuity execution plan_digest resolves to wrong artifact type")
        started_at = _non_negative_int("execution started_at", payload.get("started_at"))
        completed_at = _non_negative_int("execution completed_at", payload.get("completed_at"))
        if started_at < plan["payload"].get("planned_at") or completed_at < started_at:
            raise GovernanceError("continuity execution timestamp ordering is invalid")

    for item in by_type.get("recovery_observation", []):
        payload = item["payload"]
        plan = _require_digest_ref("observation plan_digest", payload.get("plan_digest"), by_digest)
        execution = _require_digest_ref("observation execution_digest", payload.get("execution_digest"), by_digest)
        if plan["artifact_type"] != "exercise_plan" or execution["artifact_type"] != "exercise_execution":
            raise GovernanceError("continuity recovery observation resolves to wrong plan/execution type")
        if execution["payload"].get("plan_digest") != plan["digest"]:
            raise GovernanceError("continuity recovery observation plan/execution bindings disagree")
        observed_at = _non_negative_int("recovery observation observed_at", payload.get("observed_at"))
        if observed_at < execution["payload"].get("started_at"):
            raise GovernanceError("continuity recovery observation predates exercise execution")

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
        if plan["payload"].get("objective_digest") != objective["digest"]:
            raise GovernanceError("continuity assessment plan/objective bindings disagree")
        if execution["payload"].get("plan_digest") != plan["digest"]:
            raise GovernanceError("continuity assessment execution belongs to different plan")
        assessed_at = _non_negative_int("assessment assessed_at", payload.get("assessed_at"))
        if assessed_at < execution["payload"].get("completed_at"):
            raise GovernanceError("continuity assessment predates exercise completion")

        related_observations = [
            observation
            for observation in by_type.get("recovery_observation", [])
            if observation["payload"].get("plan_digest") == plan["digest"]
            and observation["payload"].get("execution_digest") == execution["digest"]
        ]
        observation: dict[str, Any] | None = None
        observation_digest = payload.get("observation_digest")
        if related_observations:
            latest_at = max(_non_negative_int("observation observed_at", obs["payload"].get("observed_at")) for obs in related_observations)
            latest = [obs for obs in related_observations if obs["payload"].get("observed_at") == latest_at]
            if len({obs["digest"] for obs in latest}) > 1:
                raise GovernanceError("conflicting latest recovery observations fail closed offline verification")
            observation = latest[0]
            if latest_at > assessed_at:
                raise GovernanceError("continuity assessment uses a future recovery observation")
            if observation_digest != observation["digest"]:
                raise GovernanceError("continuity assessment does not bind the deterministic latest recovery observation")
        elif observation_digest is not None:
            raise GovernanceError("continuity assessment references recovery observation not present for plan/execution")

        if payload.get("operational_resilience_determined") is not False:
            raise GovernanceError("continuity assessment cannot determine operational resilience")
        if payload.get("regulatory_compliance_determined") is not False:
            raise GovernanceError("continuity assessment cannot determine regulatory compliance")
        _assessment_semantics(payload, objective["payload"], None if observation is None else observation["payload"])

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
        if assessment["payload"].get("state") == "met":
            raise GovernanceError("met continuity assessment cannot carry continuity findings")

    for item in by_type.get("remediation", []):
        payload = item["payload"]
        finding = _require_digest_ref("remediation finding_digest", payload.get("finding_digest"), by_digest)
        if finding["artifact_type"] != "finding":
            raise GovernanceError("continuity remediation finding_digest resolves to wrong artifact type")
        if payload.get("completed_at", -1) < finding["payload"].get("identified_at", 0):
            raise GovernanceError("continuity remediation predates finding identification")

    for item in by_type.get("retest", []):
        payload = item["payload"]
        finding = _require_digest_ref("retest finding_digest", payload.get("finding_digest"), by_digest)
        remediation = _require_digest_ref("retest remediation_digest", payload.get("remediation_digest"), by_digest)
        if finding["artifact_type"] != "finding" or remediation["artifact_type"] != "remediation":
            raise GovernanceError("continuity retest resolves to wrong lifecycle artifact type")
        if remediation["payload"].get("finding_digest") != finding["digest"]:
            raise GovernanceError("continuity retest finding/remediation bindings disagree")
        if payload.get("tested_at", -1) < remediation["payload"].get("completed_at", 0):
            raise GovernanceError("continuity retest predates remediation completion")

    for item in by_type.get("continuity_resolution", []):
        payload = item["payload"]
        plan = _require_digest_ref("resolution plan_digest", payload.get("plan_digest"), by_digest)
        assessment = _require_digest_ref("resolution assessment_digest", payload.get("assessment_digest"), by_digest)
        if plan["artifact_type"] != "exercise_plan" or assessment["artifact_type"] != "recovery_assessment":
            raise GovernanceError("continuity resolution resolves to wrong plan/assessment artifact type")
        finding_resolutions = payload.get("finding_resolutions")
        unresolved = payload.get("unresolved_finding_digests")
        if not isinstance(finding_resolutions, list) or not isinstance(unresolved, list):
            raise GovernanceError("continuity resolution lifecycle fields must be arrays")
        if unresolved != sorted(set(unresolved)):
            raise GovernanceError("continuity resolution unresolved finding digests must be sorted and unique")

        derived_unresolved: list[str] = []
        represented_finding_digests: list[str] = []
        for finding_resolution in finding_resolutions:
            if not isinstance(finding_resolution, dict):
                raise GovernanceError("continuity finding resolution must be an object")
            finding = _require_digest_ref(
                "resolution finding_resolution finding_digest",
                finding_resolution.get("finding_digest"),
                by_digest,
            )
            if finding["artifact_type"] != "finding" or finding["payload"].get("assessment_digest") != assessment["digest"]:
                raise GovernanceError("continuity resolution finding belongs to different assessment")
            finding_digest = finding["digest"]
            represented_finding_digests.append(finding_digest)
            expected_blocking = finding["payload"].get("severity") in {"high", "critical"}
            if finding_resolution.get("blocking") is not expected_blocking:
                raise GovernanceError("continuity finding resolution blocking flag is inconsistent with severity")
            status = finding_resolution.get("status")
            remediation_digest = finding_resolution.get("remediation_digest")
            retest_digest = finding_resolution.get("retest_digest")
            if remediation_digest is not None:
                remediation = _require_digest_ref("resolution remediation_digest", remediation_digest, by_digest)
                if remediation["artifact_type"] != "remediation" or remediation["payload"].get("finding_digest") != finding_digest:
                    raise GovernanceError("continuity finding resolution remediation is bound to different finding")
            if retest_digest is not None:
                retest = _require_digest_ref("resolution retest_digest", retest_digest, by_digest)
                if retest["artifact_type"] != "retest" or retest["payload"].get("finding_digest") != finding_digest:
                    raise GovernanceError("continuity finding resolution retest is bound to different finding")
                if remediation_digest is None or retest["payload"].get("remediation_digest") != remediation_digest:
                    raise GovernanceError("continuity finding resolution retest/remediation bindings disagree")
            if status == "closed":
                if remediation_digest is None or retest_digest is None:
                    raise GovernanceError("closed continuity finding requires remediation and retest evidence")
                if retest["payload"].get("outcome") != "passed":
                    raise GovernanceError("closed continuity finding requires passed retest evidence")
            else:
                derived_unresolved.append(finding_digest)

        if len(represented_finding_digests) != len(set(represented_finding_digests)):
            raise GovernanceError("continuity resolution finding identities must be unique")
        if unresolved != sorted(derived_unresolved):
            raise GovernanceError("continuity resolution unresolved finding set is inconsistent with finding statuses")

        assessment_state = assessment["payload"].get("state")
        if unresolved:
            expected_state = "incomplete" if assessment_state == "incomplete" else "blocked"
        elif finding_resolutions:
            expected_state = "successful_with_findings"
        elif assessment_state == "met":
            expected_state = "successful"
        elif assessment_state == "incomplete":
            expected_state = "incomplete"
        else:
            expected_state = "blocked"
        if payload.get("state") != expected_state:
            raise GovernanceError("continuity resolution state is inconsistent with assessment/finding lifecycle")


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
