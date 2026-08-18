from __future__ import annotations

from copy import deepcopy

import pytest

from doraops import (
    FinancialEntity,
    GovernanceDossierBuilder,
    GovernanceError,
    InventoryRegistry,
    dossier_document,
    sha256_digest,
    verify_dossier_document,
)


def _builder():
    registry = InventoryRegistry()
    registry.register_entity(FinancialEntity("bank-a", "Bank A", "DE"))
    return registry, GovernanceDossierBuilder(
        registry,
        entity_id="bank-a",
        generated_at=1_800_000_000,
        source_revision="sha",
    )


def test_public_builder_fails_closed_if_inventory_changes_mid_build():
    registry, builder = _builder()
    registry.register_entity(FinancialEntity("bank-b", "Bank B", "FR"))
    # Cross-entity changes do not affect the governed bank-a snapshot.
    builder.build()

    from doraops import ICTService

    registry.register_node(ICTService("bank-a", "svc", "Service", "owner", "application"))
    with pytest.raises(GovernanceError, match="inventory changed during dossier construction"):
        builder.build()


def test_hardened_verifier_rejects_forged_coverage_with_recomputed_outer_digest():
    _, builder = _builder()
    document = dossier_document(builder.build())
    forged = deepcopy(document)
    forged["dossier"]["coverage"]["inventory"] += 1
    forged["dossier_digest"] = sha256_digest(forged["dossier"])
    with pytest.raises(GovernanceError, match="coverage does not match"):
        verify_dossier_document(forged)


def test_hardened_verifier_rejects_manifest_not_matching_embedded_inventory():
    _, builder = _builder()
    document = dossier_document(builder.build())
    forged = deepcopy(document)
    manifest = next(
        item
        for item in forged["dossier"]["artifacts"]
        if item["artifact_type"] == "inventory_snapshot_manifest"
    )
    manifest["payload"]["nodes"] = ["0" * 64]
    manifest["digest"] = sha256_digest(manifest["payload"])
    forged["dossier"]["inventory_snapshot_digest"] = manifest["digest"]
    forged["dossier_digest"] = sha256_digest(forged["dossier"])
    with pytest.raises(GovernanceError, match="node digests do not match"):
        verify_dossier_document(forged)
