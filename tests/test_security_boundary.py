from __future__ import annotations

import base64
import json
from dataclasses import replace
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jsonschema import Draft202012Validator

from doraops.security import (
    EvidenceKeyReference,
    IdentityPolicy,
    SecurityBoundaryError,
    SecurityObservation,
    TenantContext,
    decrypt_evidence,
    encrypt_evidence,
    verify_ed25519_oidc_token,
)

ROOT = Path(__file__).resolve().parents[1]


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _token(private_key: Ed25519PrivateKey, claims: dict, *, alg: str = "EdDSA") -> str:
    header = {"alg": alg, "typ": "JWT", "kid": "reference-key-1"}
    encoded_header = _encode(json.dumps(header, sort_keys=True, separators=(",", ":")).encode())
    encoded_claims = _encode(json.dumps(claims, sort_keys=True, separators=(",", ":")).encode())
    signature = private_key.sign(f"{encoded_header}.{encoded_claims}".encode("ascii"))
    return f"{encoded_header}.{encoded_claims}.{_encode(signature)}"


@pytest.fixture()
def identity_material():
    private_key = Ed25519PrivateKey.generate()
    policy = IdentityPolicy(
        issuer="https://id.example.test",
        audience="doraops",
        required_roles=("doraops-evidence-reviewer",),
        require_mfa=True,
        clock_skew_seconds=0,
    )
    claims = {
        "iss": policy.issuer,
        "aud": [policy.audience, "other-audience"],
        "sub": "principal-7",
        "entity_id": "entity-a",
        "roles": ["doraops-evidence-reviewer", "doraops-reader"],
        "mfa": True,
        "nbf": 1_700_000_000,
        "exp": 1_700_000_600,
    }
    return private_key, private_key.public_key(), policy, claims


def test_valid_ed25519_oidc_token_maps_exact_financial_entity(identity_material):
    private_key, public_key, policy, claims = identity_material
    context = verify_ed25519_oidc_token(
        _token(private_key, claims), public_key, policy,
        expected_entity_id="entity-a", now=1_700_000_100,
    )
    assert context.entity_id == "entity-a"
    assert context.principal_id == "principal-7"
    assert context.roles == ("doraops-evidence-reviewer", "doraops-reader")
    assert context.mfa_verified is True


def test_cross_entity_token_is_rejected(identity_material):
    private_key, public_key, policy, claims = identity_material
    with pytest.raises(SecurityBoundaryError, match="scope"):
        verify_ed25519_oidc_token(
            _token(private_key, claims), public_key, policy,
            expected_entity_id="entity-b", now=1_700_000_100,
        )


def test_expired_token_is_rejected(identity_material):
    private_key, public_key, policy, claims = identity_material
    with pytest.raises(SecurityBoundaryError, match="expired"):
        verify_ed25519_oidc_token(
            _token(private_key, claims), public_key, policy,
            expected_entity_id="entity-a", now=1_700_000_601,
        )


def test_missing_mfa_is_rejected(identity_material):
    private_key, public_key, policy, claims = identity_material
    with pytest.raises(SecurityBoundaryError, match="MFA"):
        verify_ed25519_oidc_token(
            _token(private_key, {**claims, "mfa": False}), public_key, policy,
            expected_entity_id="entity-a", now=1_700_000_100,
        )


def test_unsupported_jwt_algorithm_is_rejected(identity_material):
    private_key, public_key, policy, claims = identity_material
    with pytest.raises(SecurityBoundaryError, match="EdDSA"):
        verify_ed25519_oidc_token(
            _token(private_key, claims, alg="HS256"), public_key, policy,
            expected_entity_id="entity-a", now=1_700_000_100,
        )


def _context(entity_id: str) -> TenantContext:
    return TenantContext(
        entity_id=entity_id,
        principal_id="principal-7",
        roles=("doraops-evidence-reviewer",),
        issuer="https://id.example.test",
        audience="doraops",
        token_expires_at=1_800_000_000,
        mfa_verified=True,
    )


def test_aes_256_gcm_round_trip_is_entity_bound():
    key = bytes(range(32))
    envelope = encrypt_evidence(
        b'{"incident_id":"INC-7"}',
        _context("entity-a"),
        EvidenceKeyReference("external-kms", "doraops/evidence", "42"),
        key,
        artifact_type="incident-evidence",
        nonce=b"\x01" * 12,
    )
    assert envelope.algorithm == "AES-256-GCM"
    assert envelope.production_key_management_validated is False
    assert decrypt_evidence(envelope, _context("entity-a"), key) == b'{"incident_id":"INC-7"}'


def test_cross_entity_decryption_fails_closed():
    key = bytes(range(32))
    envelope = encrypt_evidence(
        b"sensitive-evidence", _context("entity-a"),
        EvidenceKeyReference("external-kms", "doraops/evidence", "1"), key,
        artifact_type="governance-dossier", nonce=b"\x02" * 12,
    )
    with pytest.raises(SecurityBoundaryError, match="cross-entity"):
        decrypt_evidence(envelope, _context("entity-b"), key)


def test_ciphertext_tampering_fails_authentication():
    key = bytes(range(32))
    envelope = encrypt_evidence(
        b"sensitive-evidence", _context("entity-a"),
        EvidenceKeyReference("external-kms", "doraops/evidence", "1"), key,
        artifact_type="governance-dossier", nonce=b"\x03" * 12,
    )
    ciphertext = base64.urlsafe_b64decode(envelope.ciphertext_b64url + "==")
    damaged = replace(envelope, ciphertext_b64url=_encode(bytes([ciphertext[0] ^ 1]) + ciphertext[1:]))
    with pytest.raises(SecurityBoundaryError, match="authentication failed"):
        decrypt_evidence(damaged, _context("entity-a"), key)


def test_key_reference_cannot_embed_secret_material():
    with pytest.raises(SecurityBoundaryError, match="reference"):
        EvidenceKeyReference("external-kms", "password=do-not-store-this", "1")


def test_security_observation_is_metadata_only():
    observation = SecurityObservation(
        observed_at="2026-08-24T13:00:00Z",
        event_type="evidence.decrypt",
        entity_id="entity-a",
        principal_id="principal-7",
        outcome="allowed",
        correlation_id="corr-123",
        artifact_type="governance-dossier",
    )
    assert observation.raw_content_logged is False
    assert observation.secrets_logged is False
    assert observation.production_observability_validated is False
    assert len(observation.evidence_digest) == 64


def test_security_boundary_schemas_are_strict_and_validate_reference_examples():
    context = {
        "schema_version": "1.0", "entity_id": "entity-a", "principal_id": "principal-7",
        "roles": ["doraops-reader"], "issuer": "https://id.example.test", "audience": "doraops",
        "token_expires_at": 1_800_000_000, "mfa_verified": True,
        "production_identity_validated": False,
    }
    observation = {
        "schema_version": "1.0", "observed_at": "2026-08-24T13:00:00Z",
        "event_type": "identity.verify", "entity_id": "entity-a", "principal_id": "principal-7",
        "outcome": "allowed", "correlation_id": "corr-123", "artifact_type": None,
        "raw_content_logged": False, "secrets_logged": False,
        "production_observability_validated": False,
    }
    for name, payload in (("tenant-context.schema.json", context), ("security-observation.schema.json", observation)):
        schema = json.loads((ROOT / "schemas" / name).read_text())
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(payload)


def test_postgresql_reference_forces_rls_and_non_bypass_role():
    sql = (ROOT / "deployment" / "postgresql-entity-rls.sql").read_text()
    assert "ENABLE ROW LEVEL SECURITY" in sql
    assert "FORCE ROW LEVEL SECURITY" in sql
    assert "NOBYPASSRLS" in sql
    assert "current_setting('doraops.entity_id', true)" in sql
    assert "production isolation validation" in sql.lower()
