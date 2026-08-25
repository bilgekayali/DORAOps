from __future__ import annotations

import base64
import binascii
import hashlib
import json
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any, Iterable, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .canonical import canonical_json, sha256_digest
from .dossier_verify_reporting import verify_dossier_document
from .inventory import GovernanceError


REGULATORY_EVIDENCE_SCHEMA_VERSION = "doraops-regulatory-evidence-signature.v1"
PROVENANCE_SCHEMA_VERSION = "doraops-build-provenance.v1"
RELEASE_EVIDENCE_SCHEMA_VERSION = "doraops-release-evidence-manifest.v1"
SIGNATURE_ALGORITHM = "Ed25519"
SIGNATURE_SCOPE = "canonical-json-v1"


def _text(name: str, value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise GovernanceError(f"{name} must be non-empty text")
    return value.strip()


def _timestamp(name: str, value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise GovernanceError(f"{name} must be a non-negative integer timestamp")
    return value


def _digest(name: str, value: Any) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
        raise GovernanceError(f"{name} must be a lowercase SHA-256 digest")
    return value


def _source_revision(value: Any) -> str:
    value = _text("source_revision", value)
    if len(value) != 40 or any(ch not in "0123456789abcdef" for ch in value):
        raise GovernanceError("source_revision must be a full lowercase Git SHA-1")
    return value


def _safe_relative_path(value: Any) -> str:
    value = _text("artifact path", value)
    if "\\" in value:
        raise GovernanceError("artifact path must use POSIX separators")
    path = PurePosixPath(value)
    if path.is_absolute() or value != path.as_posix():
        raise GovernanceError("artifact path must be a normalized relative POSIX path")
    if any(part in {"", ".", ".."} for part in path.parts):
        raise GovernanceError("artifact path cannot contain empty, dot, or parent segments")
    return value


def _sha256_bytes(content: bytes) -> str:
    if not isinstance(content, bytes):
        raise GovernanceError("artifact content must be bytes")
    return hashlib.sha256(content).hexdigest()


def _canonical_object(value: Any) -> dict[str, Any]:
    normalized = json.loads(canonical_json(value))
    if not isinstance(normalized, dict):
        raise GovernanceError("canonical value must be an object")
    return normalized


@dataclass(frozen=True, slots=True)
class ArtifactDescriptor:
    path: str
    sha256: str
    size: int
    media_type: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "path", _safe_relative_path(self.path))
        _digest("artifact sha256", self.sha256)
        if isinstance(self.size, bool) or not isinstance(self.size, int) or self.size < 0:
            raise GovernanceError("artifact size must be a non-negative integer")
        object.__setattr__(self, "media_type", _text("artifact media_type", self.media_type))


@dataclass(frozen=True, slots=True)
class SourceMaterial:
    uri: str
    revision: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "uri", _text("material uri", self.uri))
        object.__setattr__(self, "revision", _source_revision(self.revision))


@dataclass(frozen=True, slots=True)
class BuildProvenance:
    schema_version: str
    package_name: str
    package_version: str
    source_revision: str
    builder_id: str
    build_type: str
    invocation_id: str
    started_at: int
    finished_at: int
    subjects: tuple[ArtifactDescriptor, ...]
    materials: tuple[SourceMaterial, ...]
    production_build_attested: bool = False

    def __post_init__(self) -> None:
        if self.schema_version != PROVENANCE_SCHEMA_VERSION:
            raise GovernanceError("unsupported provenance schema version")
        for name in ("package_name", "package_version", "builder_id", "build_type", "invocation_id"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        object.__setattr__(self, "source_revision", _source_revision(self.source_revision))
        _timestamp("provenance started_at", self.started_at)
        _timestamp("provenance finished_at", self.finished_at)
        if self.finished_at < self.started_at:
            raise GovernanceError("provenance finished_at cannot precede started_at")
        if not self.subjects:
            raise GovernanceError("provenance must contain at least one subject")
        subject_paths = [item.path for item in self.subjects]
        if subject_paths != sorted(subject_paths) or len(subject_paths) != len(set(subject_paths)):
            raise GovernanceError("provenance subjects must be sorted by unique path")
        if not self.materials:
            raise GovernanceError("provenance must contain at least one source material")
        material_keys = [(item.uri, item.revision) for item in self.materials]
        if material_keys != sorted(material_keys) or len(material_keys) != len(set(material_keys)):
            raise GovernanceError("provenance materials must be sorted and unique")
        if self.production_build_attested is not False:
            raise GovernanceError("reference provenance cannot claim production build attestation")

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class ReleaseEvidenceManifest:
    schema_version: str
    package_name: str
    package_version: str
    source_revision: str
    artifacts: tuple[ArtifactDescriptor, ...]
    provenance_path: str
    sbom_path: str
    formal_release_attested: bool = False
    production_readiness_determined: bool = False
    dora_compliance_determined: bool = False

    def __post_init__(self) -> None:
        if self.schema_version != RELEASE_EVIDENCE_SCHEMA_VERSION:
            raise GovernanceError("unsupported release evidence schema version")
        for name in ("package_name", "package_version"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        object.__setattr__(self, "source_revision", _source_revision(self.source_revision))
        if not self.artifacts:
            raise GovernanceError("release evidence manifest must contain artifacts")
        paths = [item.path for item in self.artifacts]
        if paths != sorted(paths) or len(paths) != len(set(paths)):
            raise GovernanceError("release artifacts must be sorted by unique path")
        object.__setattr__(self, "provenance_path", _safe_relative_path(self.provenance_path))
        object.__setattr__(self, "sbom_path", _safe_relative_path(self.sbom_path))
        if self.provenance_path == self.sbom_path:
            raise GovernanceError("provenance and SBOM paths must be distinct")
        if self.provenance_path not in paths or self.sbom_path not in paths:
            raise GovernanceError("release manifest must contain its provenance and SBOM artifacts")
        if self.formal_release_attested is not False:
            raise GovernanceError("preview release evidence cannot claim formal attestation")
        if self.production_readiness_determined is not False:
            raise GovernanceError("release evidence cannot determine production readiness")
        if self.dora_compliance_determined is not False:
            raise GovernanceError("release evidence cannot determine DORA compliance")

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


def descriptor_from_bytes(path: str, content: bytes, media_type: str) -> ArtifactDescriptor:
    return ArtifactDescriptor(path=path, sha256=_sha256_bytes(content), size=len(content), media_type=media_type)


def provenance_document(provenance: BuildProvenance) -> dict[str, Any]:
    payload = _canonical_object(provenance)
    return {"provenance": payload, "provenance_digest": sha256_digest(payload)}


def _descriptor_from_payload(value: Any) -> ArtifactDescriptor:
    if not isinstance(value, dict) or set(value) != {"path", "sha256", "size", "media_type"}:
        raise GovernanceError("artifact descriptor has unexpected fields")
    return ArtifactDescriptor(path=value["path"], sha256=value["sha256"], size=value["size"], media_type=value["media_type"])


def _material_from_payload(value: Any) -> SourceMaterial:
    if not isinstance(value, dict) or set(value) != {"uri", "revision"}:
        raise GovernanceError("source material has unexpected fields")
    return SourceMaterial(uri=value["uri"], revision=value["revision"])


def verify_provenance_document(document: Any) -> str:
    if not isinstance(document, dict) or set(document) != {"provenance", "provenance_digest"}:
        raise GovernanceError("provenance document has unexpected fields")
    payload = document["provenance"]
    digest = document["provenance_digest"]
    if not isinstance(payload, dict):
        raise GovernanceError("provenance payload must be an object")
    _digest("provenance_digest", digest)
    if sha256_digest(payload) != digest:
        raise GovernanceError("provenance digest mismatch")
    required = {"schema_version","package_name","package_version","source_revision","builder_id","build_type","invocation_id","started_at","finished_at","subjects","materials","production_build_attested"}
    if set(payload) != required:
        raise GovernanceError("provenance payload has unexpected fields")
    subjects = payload["subjects"]
    materials = payload["materials"]
    if not isinstance(subjects, list) or not isinstance(materials, list):
        raise GovernanceError("provenance subjects and materials must be arrays")
    BuildProvenance(
        schema_version=payload["schema_version"], package_name=payload["package_name"], package_version=payload["package_version"],
        source_revision=payload["source_revision"], builder_id=payload["builder_id"], build_type=payload["build_type"],
        invocation_id=payload["invocation_id"], started_at=payload["started_at"], finished_at=payload["finished_at"],
        subjects=tuple(_descriptor_from_payload(item) for item in subjects),
        materials=tuple(_material_from_payload(item) for item in materials),
        production_build_attested=payload["production_build_attested"],
    )
    return digest


def build_dependency_sbom(package_name: str, package_version: str, dependencies: Iterable[tuple[str, str]]) -> dict[str, Any]:
    name = _text("package_name", package_name)
    version = _text("package_version", package_version)
    normalized = sorted(set((_text("dependency name", n).lower().replace("_","-"), _text("dependency version", v)) for n, v in dependencies))
    components = [{"type":"library","name":n,"version":v,"purl":f"pkg:pypi/{n}@{v}"} for n, v in normalized]
    return {
        "bomFormat":"CycloneDX","specVersion":"1.6","version":1,
        "metadata":{"component":{"type":"application","name":name,"version":version}},
        "components":components,
        "doraops_nonclaims":{"complete_transitive_inventory":False,"vulnerability_assessment_performed":False},
    }


def verify_dependency_sbom(sbom: Any, *, expected_package_name: str, expected_package_version: str) -> str:
    if not isinstance(sbom, dict) or set(sbom) != {"bomFormat","specVersion","version","metadata","components","doraops_nonclaims"}:
        raise GovernanceError("dependency SBOM has unexpected fields")
    if sbom["bomFormat"] != "CycloneDX" or sbom["specVersion"] != "1.6" or sbom["version"] != 1:
        raise GovernanceError("unsupported dependency SBOM profile")
    metadata = sbom["metadata"]
    if not isinstance(metadata, dict) or set(metadata) != {"component"}:
        raise GovernanceError("dependency SBOM metadata has unexpected fields")
    component = metadata["component"]
    expected_component = {"type":"application","name":_text("expected_package_name", expected_package_name),"version":_text("expected_package_version", expected_package_version)}
    if component != expected_component:
        raise GovernanceError("dependency SBOM package identity mismatch")
    components = sbom["components"]
    if not isinstance(components, list):
        raise GovernanceError("dependency SBOM components must be an array")
    keys = []
    for item in components:
        if not isinstance(item, dict) or set(item) != {"type","name","version","purl"}:
            raise GovernanceError("dependency SBOM component has unexpected fields")
        if item["type"] != "library":
            raise GovernanceError("dependency SBOM component type must be library")
        dep_name = _text("dependency component name", item["name"]).lower().replace("_","-")
        dep_version = _text("dependency component version", item["version"])
        if item["purl"] != f"pkg:pypi/{dep_name}@{dep_version}":
            raise GovernanceError("dependency SBOM purl is inconsistent")
        keys.append((dep_name, dep_version))
    if keys != sorted(keys) or len(keys) != len(set(keys)):
        raise GovernanceError("dependency SBOM components must be sorted and unique")
    if sbom["doraops_nonclaims"] != {"complete_transitive_inventory":False,"vulnerability_assessment_performed":False}:
        raise GovernanceError("dependency SBOM non-claims are invalid")
    return sha256_digest(sbom)


def release_manifest_document(manifest: ReleaseEvidenceManifest) -> dict[str, Any]:
    payload = _canonical_object(manifest)
    return {"manifest": payload, "manifest_digest": sha256_digest(payload)}


def _manifest_from_payload(payload: dict[str, Any]) -> ReleaseEvidenceManifest:
    required = {"schema_version","package_name","package_version","source_revision","artifacts","provenance_path","sbom_path","formal_release_attested","production_readiness_determined","dora_compliance_determined"}
    if set(payload) != required:
        raise GovernanceError("release evidence manifest has unexpected fields")
    if not isinstance(payload["artifacts"], list):
        raise GovernanceError("release evidence artifacts must be an array")
    return ReleaseEvidenceManifest(
        schema_version=payload["schema_version"], package_name=payload["package_name"], package_version=payload["package_version"],
        source_revision=payload["source_revision"], artifacts=tuple(_descriptor_from_payload(item) for item in payload["artifacts"]),
        provenance_path=payload["provenance_path"], sbom_path=payload["sbom_path"],
        formal_release_attested=payload["formal_release_attested"], production_readiness_determined=payload["production_readiness_determined"],
        dora_compliance_determined=payload["dora_compliance_determined"],
    )


def verify_release_manifest_document(document: Any, artifact_contents: Mapping[str, bytes]) -> str:
    if not isinstance(document, dict) or set(document) != {"manifest","manifest_digest"}:
        raise GovernanceError("release evidence document has unexpected fields")
    payload = document["manifest"]
    digest = document["manifest_digest"]
    if not isinstance(payload, dict):
        raise GovernanceError("release evidence manifest payload must be an object")
    _digest("manifest_digest", digest)
    if sha256_digest(payload) != digest:
        raise GovernanceError("release evidence manifest digest mismatch")
    manifest = _manifest_from_payload(payload)
    if set(artifact_contents) != {item.path for item in manifest.artifacts}:
        raise GovernanceError("release evidence artifact set differs from manifest")
    descriptors = {item.path:item for item in manifest.artifacts}
    for path, content in artifact_contents.items():
        descriptor = descriptors[path]
        if not isinstance(content, bytes):
            raise GovernanceError("release evidence artifact content must be bytes")
        if len(content) != descriptor.size or _sha256_bytes(content) != descriptor.sha256:
            raise GovernanceError(f"release evidence artifact integrity mismatch: {path}")
    try:
        provenance_value = json.loads(artifact_contents[manifest.provenance_path].decode("utf-8"))
        sbom_value = json.loads(artifact_contents[manifest.sbom_path].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GovernanceError("release provenance and SBOM artifacts must be UTF-8 JSON") from exc
    verify_provenance_document(provenance_value)
    provenance = provenance_value["provenance"]
    if provenance["package_name"] != manifest.package_name or provenance["package_version"] != manifest.package_version:
        raise GovernanceError("release provenance package identity mismatch")
    if provenance["source_revision"] != manifest.source_revision:
        raise GovernanceError("release provenance source revision mismatch")
    verify_dependency_sbom(sbom_value, expected_package_name=manifest.package_name, expected_package_version=manifest.package_version)
    for subject in provenance["subjects"]:
        descriptor = descriptors.get(subject["path"])
        if descriptor is None:
            raise GovernanceError("provenance subject is missing from release manifest")
        if descriptor.sha256 != subject["sha256"] or descriptor.size != subject["size"] or descriptor.media_type != subject["media_type"]:
            raise GovernanceError("provenance subject differs from release manifest descriptor")
    return digest


_REGULATORY_STATEMENT_FIELDS = {"schema_version","algorithm","signature_scope","dossier_digest","entity_id","release_version","source_revision","signer_id","key_id","signed_at","purpose","dora_compliance_determined","supervisory_acceptance_determined"}


def build_regulatory_evidence_statement(dossier_document: Any, *, signer_id: str, key_id: str, signed_at: int, purpose: str) -> dict[str, Any]:
    dossier_digest = verify_dossier_document(dossier_document)
    dossier = dossier_document["dossier"]
    return {
        "schema_version":REGULATORY_EVIDENCE_SCHEMA_VERSION,"algorithm":SIGNATURE_ALGORITHM,"signature_scope":SIGNATURE_SCOPE,
        "dossier_digest":dossier_digest,"entity_id":_text("dossier entity_id", dossier.get("entity_id")),
        "release_version":_text("dossier release_version", dossier.get("release_version")),
        "source_revision":_text("dossier source_revision", dossier.get("source_revision")),
        "signer_id":_text("signer_id", signer_id),"key_id":_text("key_id", key_id),"signed_at":_timestamp("signed_at", signed_at),
        "purpose":_text("purpose", purpose),"dora_compliance_determined":False,"supervisory_acceptance_determined":False,
    }


def _validate_regulatory_statement(statement: Any) -> dict[str, Any]:
    if not isinstance(statement, dict) or set(statement) != _REGULATORY_STATEMENT_FIELDS:
        raise GovernanceError("regulatory evidence statement has unexpected fields")
    if statement["schema_version"] != REGULATORY_EVIDENCE_SCHEMA_VERSION:
        raise GovernanceError("unsupported regulatory evidence signature schema")
    if statement["algorithm"] != SIGNATURE_ALGORITHM or statement["signature_scope"] != SIGNATURE_SCOPE:
        raise GovernanceError("unsupported regulatory evidence signature profile")
    _digest("dossier_digest", statement["dossier_digest"])
    for name in ("entity_id","release_version","source_revision","signer_id","key_id","purpose"):
        _text(name, statement[name])
    _timestamp("signed_at", statement["signed_at"])
    if statement["dora_compliance_determined"] is not False or statement["supervisory_acceptance_determined"] is not False:
        raise GovernanceError("signed evidence non-claims are invalid")
    return statement


def regulatory_evidence_signing_payload(statement: Any) -> bytes:
    return canonical_json(_validate_regulatory_statement(statement)).encode("utf-8")


def assemble_regulatory_evidence_envelope(statement: Any, signature_b64: str) -> dict[str, Any]:
    statement = _validate_regulatory_statement(statement)
    signature_b64 = _text("signature", signature_b64)
    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise GovernanceError("signature must be canonical base64") from exc
    if len(signature) != 64 or base64.b64encode(signature).decode("ascii") != signature_b64:
        raise GovernanceError("Ed25519 signature must be exactly 64 canonical base64 bytes")
    return {"statement":json.loads(canonical_json(statement)),"signature":signature_b64}


def verify_regulatory_evidence_envelope(envelope: Any, dossier_document: Any, trusted_public_key: bytes, *, expected_key_id: str | None = None) -> str:
    if not isinstance(envelope, dict) or set(envelope) != {"statement","signature"}:
        raise GovernanceError("regulatory evidence envelope has unexpected fields")
    statement = _validate_regulatory_statement(envelope["statement"])
    dossier_digest = verify_dossier_document(dossier_document)
    dossier = dossier_document["dossier"]
    expected = {"dossier_digest":dossier_digest,"entity_id":dossier.get("entity_id"),"release_version":dossier.get("release_version"),"source_revision":dossier.get("source_revision")}
    for field, value in expected.items():
        if statement[field] != value:
            raise GovernanceError(f"regulatory evidence {field} does not match dossier")
    if expected_key_id is not None and statement["key_id"] != _text("expected_key_id", expected_key_id):
        raise GovernanceError("regulatory evidence key_id is not trusted")
    if not isinstance(trusted_public_key, bytes) or len(trusted_public_key) != 32:
        raise GovernanceError("trusted Ed25519 public key must be 32 raw bytes")
    signature_b64 = _text("signature", envelope["signature"])
    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise GovernanceError("signature must be canonical base64") from exc
    if len(signature) != 64 or base64.b64encode(signature).decode("ascii") != signature_b64:
        raise GovernanceError("invalid Ed25519 signature encoding")
    try:
        Ed25519PublicKey.from_public_bytes(trusted_public_key).verify(signature, regulatory_evidence_signing_payload(statement))
    except (ValueError, InvalidSignature) as exc:
        raise GovernanceError("regulatory evidence signature verification failed") from exc
    return dossier_digest
