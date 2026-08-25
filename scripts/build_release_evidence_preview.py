from __future__ import annotations

import argparse
from importlib.metadata import PackageNotFoundError, version as installed_version
import json
from pathlib import Path
import re
import sys
import time
import tomllib

from doraops.canonical import canonical_json
from doraops.release_evidence import (
    PROVENANCE_SCHEMA_VERSION,
    RELEASE_EVIDENCE_SCHEMA_VERSION,
    BuildProvenance,
    ReleaseEvidenceManifest,
    SourceMaterial,
    build_dependency_sbom,
    descriptor_from_bytes,
    provenance_document,
    release_manifest_document,
    verify_release_manifest_document,
)


def _dependency_name(requirement: str) -> str:
    match = re.match(r"\s*([A-Za-z0-9_.-]+)", requirement)
    if match is None:
        raise ValueError(f"cannot parse dependency requirement: {requirement}")
    return match.group(1).lower().replace("_", "-")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build a DORAOps release-evidence preview bundle")
    parser.add_argument("--wheel", required=True)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--output-dir", default="release-preview")
    parser.add_argument("--builder-id", default="local-reference-builder")
    parser.add_argument("--invocation-id", default="manual")
    args = parser.parse_args(argv)

    wheel_path = Path(args.wheel)
    if not wheel_path.is_file():
        raise SystemExit(f"wheel not found: {wheel_path}")
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    project = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))["project"]
    package_name = project["name"]
    package_version = project["version"]

    resolved_dependencies: list[tuple[str, str]] = []
    for requirement in project.get("dependencies", []):
        name = _dependency_name(requirement)
        try:
            resolved_dependencies.append((name, installed_version(name)))
        except PackageNotFoundError as exc:
            raise SystemExit(f"dependency is not installed: {name}") from exc

    sbom = build_dependency_sbom(package_name, package_version, resolved_dependencies)
    sbom_bytes = (canonical_json(sbom) + "\n").encode("utf-8")
    sbom_name = f"{package_name}-{package_version}.dependencies.cdx.json"
    (output_dir / sbom_name).write_bytes(sbom_bytes)

    wheel_bytes = wheel_path.read_bytes()
    wheel_descriptor = descriptor_from_bytes(wheel_path.name, wheel_bytes, "application/vnd.python.wheel")

    now = int(time.time())
    provenance = BuildProvenance(
        schema_version=PROVENANCE_SCHEMA_VERSION,
        package_name=package_name,
        package_version=package_version,
        source_revision=args.source_revision,
        builder_id=args.builder_id,
        build_type="https://doraops.dev/build/python-wheel/v1",
        invocation_id=args.invocation_id,
        started_at=now,
        finished_at=now,
        subjects=(wheel_descriptor,),
        materials=(SourceMaterial(
            uri=f"git+https://github.com/bilgekayali/DORAOps@{args.source_revision}",
            revision=args.source_revision,
        ),),
        production_build_attested=False,
    )
    provenance_value = provenance_document(provenance)
    provenance_bytes = (canonical_json(provenance_value) + "\n").encode("utf-8")
    provenance_name = f"{package_name}-{package_version}.provenance.json"
    (output_dir / provenance_name).write_bytes(provenance_bytes)

    artifacts = tuple(sorted((
        wheel_descriptor,
        descriptor_from_bytes(sbom_name, sbom_bytes, "application/vnd.cyclonedx+json"),
        descriptor_from_bytes(provenance_name, provenance_bytes, "application/json"),
    ), key=lambda item: item.path))
    manifest = ReleaseEvidenceManifest(
        schema_version=RELEASE_EVIDENCE_SCHEMA_VERSION,
        package_name=package_name,
        package_version=package_version,
        source_revision=args.source_revision,
        artifacts=artifacts,
        provenance_path=provenance_name,
        sbom_path=sbom_name,
        formal_release_attested=False,
        production_readiness_determined=False,
        dora_compliance_determined=False,
    )
    manifest_value = release_manifest_document(manifest)
    manifest_name = f"{package_name}-{package_version}.release-evidence.json"
    (output_dir / manifest_name).write_bytes((canonical_json(manifest_value) + "\n").encode("utf-8"))

    verify_release_manifest_document(
        manifest_value,
        {wheel_path.name: wheel_bytes, sbom_name: sbom_bytes, provenance_name: provenance_bytes},
    )
    print(json.dumps({"manifest": manifest_name, "manifest_digest": manifest_value["manifest_digest"]}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
