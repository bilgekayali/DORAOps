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
    return digest
