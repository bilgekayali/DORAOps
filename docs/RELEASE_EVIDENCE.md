# DORAOps v0.6 Signed Evidence and Release Provenance

DORAOps v0.6 adds a reference integrity layer around governance dossiers and release artifacts.

## Regulatory evidence signature flow

The repository does not generate, load, store or use a long-lived signing private key.

```text
verified governance dossier
  -> canonical regulatory evidence statement
  -> signing payload bytes
  -> external Ed25519 signing boundary
  -> signature envelope
  -> trusted public-key verification
```

The signed statement binds:

- the exact governance dossier SHA-256 digest;
- financial-entity identifier;
- DORAOps release version;
- dossier source revision;
- signer identifier and external key identifier;
- signing time and human-defined purpose;
- structural non-claims that the signature does not determine DORA compliance or supervisory acceptance.

A valid cryptographic signature proves only that the supplied trusted key signed the exact canonical statement. Trust in the signer, authorization, legal effect and governance approval remain external responsibilities.

## Build provenance

`BuildProvenance` binds a full 40-character Git source revision to:

- package name and version;
- builder and invocation identifiers;
- build type;
- build start/end timestamps;
- exact subject artifact path, byte size, media type and SHA-256;
- source material URI and exact Git revision.

Reference provenance always carries `production_build_attested=false`. It is an integrity record, not a production attestation.

## Dependency SBOM

The deterministic dependency SBOM uses a strict CycloneDX-shaped JSON profile (`bomFormat=CycloneDX`, `specVersion=1.6`) for the package and its directly resolved runtime dependencies.

The profile deliberately records:

- `complete_transitive_inventory=false`;
- `vulnerability_assessment_performed=false`.

Therefore the preview must not be represented as a complete software-composition analysis or vulnerability assessment.

## Release evidence manifest

The release manifest binds the exact bytes of:

- the built wheel;
- dependency SBOM;
- build provenance document.

Every artifact has a normalized relative POSIX path, exact byte count, media type and SHA-256. Verification fails closed on path traversal, missing/extra files, byte changes, provenance/source mismatch, package/version mismatch or SBOM profile drift.

The manifest structurally fixes these fields to false:

- `formal_release_attested`;
- `production_readiness_determined`;
- `dora_compliance_determined`.

## Preview builder

After building a wheel:

```bash
python scripts/build_release_evidence_preview.py \
  --wheel dist/doraops-<version>-py3-none-any.whl \
  --source-revision <40-character-git-sha> \
  --builder-id github-actions \
  --invocation-id <run-id>
```

The command writes a preview SBOM, provenance document and release-evidence manifest and then verifies the full bundle against the exact artifact bytes.

## Non-claims

v0.6 does not establish:

- identity or legal authority of a real-world signer;
- production custody, rotation or protection of a signing key;
- formal artifact attestation;
- complete transitive SBOM coverage;
- vulnerability-free dependencies;
- production deployment integrity;
- DORA compliance;
- supervisory acceptance.

Those require independent operational, security, legal and governance validation.
