from __future__ import annotations

import base64
import json
from pathlib import Path

import jsonschema
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from doraops import GovernanceDossierBuilder, GovernanceError, dossier_document
from doraops.canonical import canonical_json
from doraops.release_evidence import (
    PROVENANCE_SCHEMA_VERSION,
    RELEASE_EVIDENCE_SCHEMA_VERSION,
    BuildProvenance,
    ReleaseEvidenceManifest,
    SourceMaterial,
    assemble_regulatory_evidence_envelope,
    build_dependency_sbom,
    build_regulatory_evidence_statement,
    descriptor_from_bytes,
    provenance_document,
    regulatory_evidence_signing_payload,
    release_manifest_document,
    verify_dependency_sbom,
    verify_provenance_document,
    verify_regulatory_evidence_envelope,
    verify_release_manifest_document,
)
from tests.test_dossier import governed_risk_fixture


SOURCE_REVISION = "a" * 40


def _dossier_document(source_revision: str = SOURCE_REVISION):
    registry, _, scenario, policy, decision = governed_risk_fixture()
    builder = GovernanceDossierBuilder(
        registry,
        entity_id="bank-a",
        generated_at=1_800_000_000,
        source_revision=source_revision,
    )
    builder.add_risk_decision(decision, scenario, (), policy)
    return dossier_document(builder.build())


def _public_key_bytes(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def test_regulatory_evidence_external_signature_round_trip() -> None:
    document = _dossier_document()
    statement = build_regulatory_evidence_statement(
        document,
        signer_id="independent-control-owner",
        key_id="validator-key-2026-01",
        signed_at=1_800_000_100,
        purpose="approve represented regulatory evidence",
    )
    private_key = Ed25519PrivateKey.generate()
    signature = private_key.sign(regulatory_evidence_signing_payload(statement))
    envelope = assemble_regulatory_evidence_envelope(statement, base64.b64encode(signature).decode("ascii"))
    assert verify_regulatory_evidence_envelope(
        envelope,
        document,
        _public_key_bytes(private_key),
        expected_key_id="validator-key-2026-01",
    ) == document["dossier_digest"]


def test_regulatory_evidence_rejects_wrong_key_tamper_and_dossier_drift() -> None:
    document = _dossier_document()
    statement = build_regulatory_evidence_statement(
        document,
        signer_id="reviewer",
        key_id="trusted-key",
        signed_at=1_800_000_100,
        purpose="review",
    )
    private_key = Ed25519PrivateKey.generate()
    envelope = assemble_regulatory_evidence_envelope(
        statement,
        base64.b64encode(private_key.sign(regulatory_evidence_signing_payload(statement))).decode("ascii"),
    )
    with pytest.raises(GovernanceError, match="key_id is not trusted"):
        verify_regulatory_evidence_envelope(envelope, document, _public_key_bytes(private_key), expected_key_id="different-key")

    tampered = json.loads(json.dumps(envelope))
    tampered["statement"]["purpose"] = "tampered"
    with pytest.raises(GovernanceError, match="signature verification failed"):
        verify_regulatory_evidence_envelope(tampered, document, _public_key_bytes(private_key))

    drifted = _dossier_document("b" * 40)
    with pytest.raises(GovernanceError, match="dossier_digest does not match dossier"):
        verify_regulatory_evidence_envelope(envelope, drifted, _public_key_bytes(private_key))


def test_regulatory_evidence_module_never_handles_private_signing_keys() -> None:
    source = (Path(__file__).resolve().parents[1] / "src" / "doraops" / "release_evidence.py").read_text(encoding="utf-8")
    assert "Ed25519PrivateKey" not in source
    assert "private_key" not in source


def test_provenance_and_release_manifest_verify_exact_artifact_bytes() -> None:
    wheel_bytes = b"reference-wheel-bytes"
    wheel = descriptor_from_bytes("doraops-0.5.0-py3-none-any.whl", wheel_bytes, "application/vnd.python.wheel")
    sbom = build_dependency_sbom("doraops", "0.5.0", (("jsonschema", "4.26.0"), ("cryptography", "46.0.7")))
    sbom_bytes = (canonical_json(sbom) + "\n").encode("utf-8")
    sbom_path = "doraops-0.5.0.dependencies.cdx.json"

    provenance = BuildProvenance(
        schema_version=PROVENANCE_SCHEMA_VERSION,
        package_name="doraops",
        package_version="0.5.0",
        source_revision=SOURCE_REVISION,
        builder_id="github-actions",
        build_type="https://doraops.dev/build/python-wheel/v1",
        invocation_id="run-1",
        started_at=100,
        finished_at=101,
        subjects=(wheel,),
        materials=(SourceMaterial(uri=f"git+https://github.com/bilgekayali/DORAOps@{SOURCE_REVISION}", revision=SOURCE_REVISION),),
        production_build_attested=False,
    )
    provenance_value = provenance_document(provenance)
    assert verify_provenance_document(provenance_value) == provenance_value["provenance_digest"]
    provenance_bytes = (canonical_json(provenance_value) + "\n").encode("utf-8")
    provenance_path = "doraops-0.5.0.provenance.json"

    artifacts = tuple(sorted((
        wheel,
        descriptor_from_bytes(sbom_path, sbom_bytes, "application/vnd.cyclonedx+json"),
        descriptor_from_bytes(provenance_path, provenance_bytes, "application/json"),
    ), key=lambda item: item.path))
    manifest = ReleaseEvidenceManifest(
        schema_version=RELEASE_EVIDENCE_SCHEMA_VERSION,
        package_name="doraops",
        package_version="0.5.0",
        source_revision=SOURCE_REVISION,
        artifacts=artifacts,
        provenance_path=provenance_path,
        sbom_path=sbom_path,
    )
    document = release_manifest_document(manifest)
    contents = {wheel.path: wheel_bytes, sbom_path: sbom_bytes, provenance_path: provenance_bytes}
    assert verify_release_manifest_document(document, contents) == document["manifest_digest"]

    tampered = dict(contents)
    tampered[wheel.path] = wheel_bytes + b"-tampered"
    with pytest.raises(GovernanceError, match="artifact integrity mismatch"):
        verify_release_manifest_document(document, tampered)


def test_release_evidence_rejects_path_traversal_and_claim_inflation() -> None:
    with pytest.raises(GovernanceError, match="parent segments"):
        descriptor_from_bytes("../secret", b"x", "application/octet-stream")

    sbom = build_dependency_sbom("doraops", "0.5.0", (("jsonschema", "4.26.0"),))
    sbom["doraops_nonclaims"]["vulnerability_assessment_performed"] = True
    with pytest.raises(GovernanceError, match="non-claims"):
        verify_dependency_sbom(sbom, expected_package_name="doraops", expected_package_version="0.5.0")

    wheel = descriptor_from_bytes("wheel.whl", b"x", "application/vnd.python.wheel")
    with pytest.raises(GovernanceError, match="formal attestation"):
        ReleaseEvidenceManifest(
            schema_version=RELEASE_EVIDENCE_SCHEMA_VERSION,
            package_name="doraops",
            package_version="0.5.0",
            source_revision=SOURCE_REVISION,
            artifacts=(
                descriptor_from_bytes("a.json", b"{}", "application/json"),
                descriptor_from_bytes("b.json", b"{}", "application/json"),
                wheel,
            ),
            provenance_path="a.json",
            sbom_path="b.json",
            formal_release_attested=True,
        )


def test_v06_schemas_accept_generated_reference_documents() -> None:
    root = Path(__file__).resolve().parents[1] / "schemas"

    dossier = _dossier_document()
    statement = build_regulatory_evidence_statement(dossier, signer_id="reviewer", key_id="key-1", signed_at=1_800_000_100, purpose="review")
    private_key = Ed25519PrivateKey.generate()
    envelope = assemble_regulatory_evidence_envelope(statement, base64.b64encode(private_key.sign(regulatory_evidence_signing_payload(statement))).decode("ascii"))
    regulatory_schema = json.loads((root / "regulatory-evidence-envelope.schema.json").read_text())
    jsonschema.Draft202012Validator(regulatory_schema).validate(envelope)

    wheel_bytes = b"wheel"
    wheel = descriptor_from_bytes("wheel.whl", wheel_bytes, "application/vnd.python.wheel")
    sbom = build_dependency_sbom("doraops", "0.5.0", (("jsonschema", "4.26.0"),))
    sbom_schema = json.loads((root / "dependency-sbom.schema.json").read_text())
    jsonschema.Draft202012Validator(sbom_schema).validate(sbom)
    sbom_bytes = (canonical_json(sbom) + "\n").encode()

    provenance = BuildProvenance(
        schema_version=PROVENANCE_SCHEMA_VERSION,
        package_name="doraops",
        package_version="0.5.0",
        source_revision=SOURCE_REVISION,
        builder_id="builder",
        build_type="python-wheel",
        invocation_id="invocation",
        started_at=1,
        finished_at=2,
        subjects=(wheel,),
        materials=(SourceMaterial("git+https://example.invalid/repo", SOURCE_REVISION),),
    )
    provenance_value = provenance_document(provenance)
    provenance_schema = json.loads((root / "build-provenance.schema.json").read_text())
    jsonschema.Draft202012Validator(provenance_schema).validate(provenance_value)
    provenance_bytes = (canonical_json(provenance_value) + "\n").encode()

    artifacts = tuple(sorted((
        wheel,
        descriptor_from_bytes("sbom.json", sbom_bytes, "application/vnd.cyclonedx+json"),
        descriptor_from_bytes("provenance.json", provenance_bytes, "application/json"),
    ), key=lambda item: item.path))
    manifest = release_manifest_document(ReleaseEvidenceManifest(
        schema_version=RELEASE_EVIDENCE_SCHEMA_VERSION,
        package_name="doraops",
        package_version="0.5.0",
        source_revision=SOURCE_REVISION,
        artifacts=artifacts,
        provenance_path="provenance.json",
        sbom_path="sbom.json",
    ))
    manifest_schema = json.loads((root / "release-evidence-manifest.schema.json").read_text())
    jsonschema.Draft202012Validator(manifest_schema).validate(manifest)
