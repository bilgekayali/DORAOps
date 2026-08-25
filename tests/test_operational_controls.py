from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

import doraops
from doraops.canonical import sha256_digest
from doraops.inventory import GovernanceError
from doraops.operational_controls import (
    ControlEvidenceItem,
    DeploymentControlProfile,
    REQUIRED_OPERATIONAL_CONTROLS,
    build_operational_control_evidence,
    operational_evidence_document,
    profile_document,
    verify_operational_evidence_document,
    verify_profile_document,
)


ROOT = Path(__file__).resolve().parents[1]


def profile(*, image_suffix: str = "a") -> DeploymentControlProfile:
    return DeploymentControlProfile(
        profile_id="standard-hardened",
        release_version=doraops.__version__,
        workload_name="doraops",
        image_reference=f"registry.example.invalid/doraops@sha256:{image_suffix * 64}",
    )


def control_items() -> tuple[ControlEvidenceItem, ...]:
    return tuple(
        ControlEvidenceItem(
            control_id=control_id,
            artifact_digest=sha256_digest({"control": control_id}),
            validator_id=f"validator:{control_id}",
            negative_path_verified=True,
        )
        for control_id in sorted(REQUIRED_OPERATIONAL_CONTROLS)
    )


def evidence(profile_value: DeploymentControlProfile):
    return build_operational_control_evidence(
        entity_id="bank-a",
        environment_id="prod-eu-1",
        profile=profile_value,
        collected_at=1_800_000_000,
        production_environment=True,
        control_evidence=control_items(),
    )


def test_deployment_profile_and_operational_evidence_round_trip():
    profile_value = profile()
    profile_doc = profile_document(profile_value)
    evidence_value = evidence(profile_value)
    evidence_doc = operational_evidence_document(evidence_value)

    assert verify_profile_document(profile_doc) == profile_doc["profile_digest"]
    assert verify_operational_evidence_document(evidence_doc, profile_doc) == evidence_doc["evidence_digest"]
    assert evidence_value.production_environment is True
    assert evidence_value.production_effectiveness_determined is False
    assert evidence_value.dora_compliance_determined is False
    assert evidence_value.supervisory_acceptance_determined is False
    assert evidence_value.requires_human_review is True


def test_profile_rejects_mutable_image_even_when_outer_digest_is_recomputed():
    document = profile_document(profile())
    document["profile"]["image_reference"] = "registry.example.invalid/doraops:latest"
    document["profile_digest"] = sha256_digest(document["profile"])
    with pytest.raises(GovernanceError, match="immutable @sha256"):
        verify_profile_document(document)


def test_evidence_requires_every_control_exactly_once():
    profile_value = profile()
    document = operational_evidence_document(evidence(profile_value))
    document["evidence"]["controls"] = document["evidence"]["controls"][:-1]
    document["evidence_digest"] = sha256_digest(document["evidence"])
    with pytest.raises(GovernanceError, match="every required control exactly once"):
        verify_operational_evidence_document(document, profile_document(profile_value))


def test_control_artifact_digests_must_be_distinct():
    items = list(control_items())
    items[1] = ControlEvidenceItem(
        control_id=items[1].control_id,
        artifact_digest=items[0].artifact_digest,
        validator_id=items[1].validator_id,
        negative_path_verified=True,
    )
    with pytest.raises(GovernanceError, match="artifact digests must be distinct"):
        build_operational_control_evidence(
            entity_id="bank-a",
            environment_id="prod-eu-1",
            profile=profile(),
            collected_at=1,
            production_environment=True,
            control_evidence=items,
        )


def test_control_item_requires_negative_path_verification():
    with pytest.raises(GovernanceError, match="negative-path"):
        ControlEvidenceItem(
            control_id="immutable_deployment",
            artifact_digest="a" * 64,
            validator_id="validator",
            negative_path_verified=False,
        )


def test_operational_evidence_fails_if_profile_binding_changes():
    original = profile(image_suffix="a")
    different = profile(image_suffix="b")
    document = operational_evidence_document(evidence(original))
    with pytest.raises(GovernanceError, match="different deployment profile"):
        verify_operational_evidence_document(document, profile_document(different))


def test_non_claims_fail_closed_even_if_outer_digest_is_recomputed():
    profile_value = profile()
    document = operational_evidence_document(evidence(profile_value))
    document["evidence"]["production_effectiveness_determined"] = True
    document["evidence_digest"] = sha256_digest(document["evidence"])
    with pytest.raises(GovernanceError, match="cannot determine production effectiveness"):
        verify_operational_evidence_document(document, profile_document(profile_value))


def test_v07_schemas_validate_generated_documents():
    profile_value = profile()
    documents = {
        "deployment-control-profile.schema.json": profile_document(profile_value),
        "operational-control-evidence.schema.json": operational_evidence_document(evidence(profile_value)),
    }
    for name, document in documents.items():
        schema = json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator.check_schema(schema)
        jsonschema.Draft202012Validator(schema).validate(document)


def test_kubernetes_reference_contains_hardening_invariants():
    source = (ROOT / "deployment" / "kubernetes-reference.yaml").read_text(encoding="utf-8")
    required_markers = (
        "automountServiceAccountToken: false",
        "runAsNonRoot: true",
        "type: RuntimeDefault",
        "allowPrivilegeEscalation: false",
        "readOnlyRootFilesystem: true",
        "- ALL",
        "@sha256:",
        "secretKeyRef:",
        "limits:",
        "readinessProbe:",
        "livenessProbe:",
        "kind: NetworkPolicy",
        "egress: []",
    )
    for marker in required_markers:
        assert marker in source, marker
