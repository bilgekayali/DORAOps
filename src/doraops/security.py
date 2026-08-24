from __future__ import annotations

import base64
import json
import re
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Iterable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .canonical import canonical_json, sha256_digest
from .inventory import GovernanceError


class SecurityBoundaryError(GovernanceError):
    """Raised when a DORAOps security-boundary contract fails closed."""


def _text(name: str, value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise SecurityBoundaryError(f"{name} must be a non-empty string")
    return value.strip()


def _roles(values: Iterable[str]) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise SecurityBoundaryError("roles must be a collection of strings")
    cleaned = tuple(sorted({_text("role", value) for value in values}))
    if not cleaned:
        raise SecurityBoundaryError("roles must not be empty")
    return cleaned


def _b64url_decode(segment: str) -> bytes:
    if not isinstance(segment, str) or not segment or not re.fullmatch(r"[A-Za-z0-9_-]+", segment):
        raise SecurityBoundaryError("invalid base64url token segment")
    padding = "=" * (-len(segment) % 4)
    try:
        return base64.urlsafe_b64decode(segment + padding)
    except Exception as exc:
        raise SecurityBoundaryError("invalid base64url token segment") from exc


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _json_object(segment: str, name: str) -> dict[str, Any]:
    try:
        payload = json.loads(_b64url_decode(segment).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SecurityBoundaryError(f"{name} must be valid UTF-8 JSON") from exc
    if not isinstance(payload, dict):
        raise SecurityBoundaryError(f"{name} must be a JSON object")
    return payload


def _numeric_claim(claims: dict[str, Any], name: str) -> int:
    value = claims.get(name)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise SecurityBoundaryError(f"{name} claim must be numeric")
    integer = int(value)
    if integer != value:
        raise SecurityBoundaryError(f"{name} claim must be an integer epoch timestamp")
    return integer


@dataclass(frozen=True, slots=True)
class TenantContext:
    entity_id: str
    principal_id: str
    roles: tuple[str, ...]
    issuer: str
    audience: str
    token_expires_at: int
    mfa_verified: bool

    def __post_init__(self) -> None:
        object.__setattr__(self, "entity_id", _text("entity_id", self.entity_id))
        object.__setattr__(self, "principal_id", _text("principal_id", self.principal_id))
        object.__setattr__(self, "issuer", _text("issuer", self.issuer))
        object.__setattr__(self, "audience", _text("audience", self.audience))
        object.__setattr__(self, "roles", _roles(self.roles))
        if self.token_expires_at <= 0:
            raise SecurityBoundaryError("token_expires_at must be a positive epoch timestamp")
        if not isinstance(self.mfa_verified, bool):
            raise SecurityBoundaryError("mfa_verified must be boolean")

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class IdentityPolicy:
    issuer: str
    audience: str
    required_roles: tuple[str, ...]
    require_mfa: bool = True
    entity_claim: str = "entity_id"
    principal_claim: str = "sub"
    roles_claim: str = "roles"
    mfa_claim: str = "mfa"
    clock_skew_seconds: int = 60

    def __post_init__(self) -> None:
        for name in ("issuer", "audience", "entity_claim", "principal_claim", "roles_claim", "mfa_claim"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        object.__setattr__(self, "required_roles", tuple(sorted({_text("required_role", r) for r in self.required_roles})))
        if not isinstance(self.require_mfa, bool):
            raise SecurityBoundaryError("require_mfa must be boolean")
        if not isinstance(self.clock_skew_seconds, int) or isinstance(self.clock_skew_seconds, bool):
            raise SecurityBoundaryError("clock_skew_seconds must be an integer")
        if not 0 <= self.clock_skew_seconds <= 300:
            raise SecurityBoundaryError("clock_skew_seconds must be between 0 and 300")


def verify_ed25519_oidc_token(
    token: str,
    public_key: Ed25519PublicKey,
    policy: IdentityPolicy,
    *,
    expected_entity_id: str,
    now: int | None = None,
) -> TenantContext:
    """Verify a pre-resolved Ed25519 OIDC/JWT token without network/JWKS access."""
    expected_entity = _text("expected_entity_id", expected_entity_id)
    if not isinstance(public_key, Ed25519PublicKey):
        raise SecurityBoundaryError("public_key must be an Ed25519 public key")
    parts = token.split(".") if isinstance(token, str) else []
    if len(parts) != 3:
        raise SecurityBoundaryError("token must contain exactly three JWT segments")
    encoded_header, encoded_claims, encoded_signature = parts
    header = _json_object(encoded_header, "JWT header")
    claims = _json_object(encoded_claims, "JWT claims")

    if header.get("alg") != "EdDSA":
        raise SecurityBoundaryError("only EdDSA JWT signatures are accepted")
    if header.get("typ") not in (None, "JWT"):
        raise SecurityBoundaryError("JWT typ must be JWT when present")
    try:
        public_key.verify(
            _b64url_decode(encoded_signature),
            f"{encoded_header}.{encoded_claims}".encode("ascii"),
        )
    except (InvalidSignature, ValueError) as exc:
        raise SecurityBoundaryError("JWT signature verification failed") from exc

    if claims.get("iss") != policy.issuer:
        raise SecurityBoundaryError("JWT issuer does not match policy")
    audience_claim = claims.get("aud")
    if isinstance(audience_claim, str):
        audiences = (audience_claim,)
    elif isinstance(audience_claim, list) and all(isinstance(item, str) for item in audience_claim):
        audiences = tuple(audience_claim)
    else:
        raise SecurityBoundaryError("JWT audience claim is invalid")
    if policy.audience not in audiences:
        raise SecurityBoundaryError("JWT audience does not match policy")

    current = int(time.time()) if now is None else int(now)
    expires_at = _numeric_claim(claims, "exp")
    if current > expires_at + policy.clock_skew_seconds:
        raise SecurityBoundaryError("JWT is expired")
    if "nbf" in claims:
        not_before = _numeric_claim(claims, "nbf")
        if current + policy.clock_skew_seconds < not_before:
            raise SecurityBoundaryError("JWT is not yet valid")

    principal_id = _text(policy.principal_claim, claims.get(policy.principal_claim))
    entity_id = _text(policy.entity_claim, claims.get(policy.entity_claim))
    if entity_id != expected_entity:
        raise SecurityBoundaryError("JWT financial-entity scope does not match request context")

    raw_roles = claims.get(policy.roles_claim)
    if not isinstance(raw_roles, list):
        raise SecurityBoundaryError("JWT roles claim must be an array")
    roles = _roles(raw_roles)
    missing_roles = sorted(set(policy.required_roles) - set(roles))
    if missing_roles:
        raise SecurityBoundaryError(f"JWT is missing required roles: {missing_roles}")

    mfa_verified = claims.get(policy.mfa_claim) is True
    if policy.require_mfa and not mfa_verified:
        raise SecurityBoundaryError("JWT does not contain required MFA evidence")

    return TenantContext(
        entity_id=entity_id,
        principal_id=principal_id,
        roles=roles,
        issuer=policy.issuer,
        audience=policy.audience,
        token_expires_at=expires_at,
        mfa_verified=mfa_verified,
    )


def assert_entity_scope(context: TenantContext, entity_id: str) -> None:
    if context.entity_id != _text("entity_id", entity_id):
        raise SecurityBoundaryError("cross-entity access is not permitted")


@dataclass(frozen=True, slots=True)
class EvidenceKeyReference:
    provider: str
    key_id: str
    key_version: str

    def __post_init__(self) -> None:
        for name in ("provider", "key_id", "key_version"):
            value = _text(name, getattr(self, name))
            lowered = value.lower()
            if any(marker in lowered for marker in ("-----begin", "private key", "secret=", "password=")):
                raise SecurityBoundaryError(f"{name} must be a reference, not secret material")
            object.__setattr__(self, name, value)


@dataclass(frozen=True, slots=True)
class EncryptedEvidenceEnvelope:
    schema_version: str
    algorithm: str
    entity_id: str
    artifact_type: str
    key_reference: EvidenceKeyReference
    nonce_b64url: str
    ciphertext_b64url: str
    aad_sha256: str
    raw_content_logged: bool = False
    secrets_logged: bool = False
    production_key_management_validated: bool = False

    def __post_init__(self) -> None:
        if self.schema_version != "1.0":
            raise SecurityBoundaryError("encrypted evidence schema_version must be 1.0")
        if self.algorithm != "AES-256-GCM":
            raise SecurityBoundaryError("only AES-256-GCM evidence envelopes are supported")
        object.__setattr__(self, "entity_id", _text("entity_id", self.entity_id))
        object.__setattr__(self, "artifact_type", _text("artifact_type", self.artifact_type))
        if len(_b64url_decode(self.nonce_b64url)) != 12:
            raise SecurityBoundaryError("AES-GCM nonce must be exactly 12 bytes")
        if not _b64url_decode(self.ciphertext_b64url):
            raise SecurityBoundaryError("ciphertext must not be empty")
        if not re.fullmatch(r"[0-9a-f]{64}", self.aad_sha256):
            raise SecurityBoundaryError("aad_sha256 must be lowercase SHA-256")
        if self.raw_content_logged is not False or self.secrets_logged is not False:
            raise SecurityBoundaryError("security envelope cannot claim raw-content or secret logging")
        if self.production_key_management_validated is not False:
            raise SecurityBoundaryError("reference envelope cannot claim production key-management validation")


def _aad(entity_id: str, artifact_type: str, key_reference: EvidenceKeyReference) -> bytes:
    payload = {
        "entity_id": _text("entity_id", entity_id),
        "artifact_type": _text("artifact_type", artifact_type),
        "key_reference": {
            "provider": key_reference.provider,
            "key_id": key_reference.key_id,
            "key_version": key_reference.key_version,
        },
    }
    return canonical_json(payload).encode("utf-8")


def encrypt_evidence(
    plaintext: bytes,
    context: TenantContext,
    key_reference: EvidenceKeyReference,
    key_bytes: bytes,
    *,
    artifact_type: str,
    nonce: bytes | None = None,
) -> EncryptedEvidenceEnvelope:
    if not isinstance(plaintext, bytes) or not plaintext:
        raise SecurityBoundaryError("plaintext must be non-empty bytes")
    if not isinstance(key_bytes, bytes) or len(key_bytes) != 32:
        raise SecurityBoundaryError("AES-256-GCM key material must be exactly 32 bytes")
    selected_nonce = nonce
    if selected_nonce is None:
        import os
        selected_nonce = os.urandom(12)
    if not isinstance(selected_nonce, bytes) or len(selected_nonce) != 12:
        raise SecurityBoundaryError("AES-GCM nonce must be exactly 12 bytes")
    aad = _aad(context.entity_id, artifact_type, key_reference)
    ciphertext = AESGCM(key_bytes).encrypt(selected_nonce, plaintext, aad)
    return EncryptedEvidenceEnvelope(
        schema_version="1.0",
        algorithm="AES-256-GCM",
        entity_id=context.entity_id,
        artifact_type=artifact_type,
        key_reference=key_reference,
        nonce_b64url=_b64url_encode(selected_nonce),
        ciphertext_b64url=_b64url_encode(ciphertext),
        aad_sha256=sha256_digest(json.loads(aad.decode("utf-8"))),
    )


def decrypt_evidence(
    envelope: EncryptedEvidenceEnvelope,
    context: TenantContext,
    key_bytes: bytes,
) -> bytes:
    assert_entity_scope(context, envelope.entity_id)
    if not isinstance(key_bytes, bytes) or len(key_bytes) != 32:
        raise SecurityBoundaryError("AES-256-GCM key material must be exactly 32 bytes")
    aad = _aad(envelope.entity_id, envelope.artifact_type, envelope.key_reference)
    if sha256_digest(json.loads(aad.decode("utf-8"))) != envelope.aad_sha256:
        raise SecurityBoundaryError("encrypted evidence AAD digest does not match envelope metadata")
    try:
        return AESGCM(key_bytes).decrypt(
            _b64url_decode(envelope.nonce_b64url),
            _b64url_decode(envelope.ciphertext_b64url),
            aad,
        )
    except Exception as exc:
        raise SecurityBoundaryError("encrypted evidence authentication failed") from exc


@dataclass(frozen=True, slots=True)
class SecurityObservation:
    observed_at: str
    event_type: str
    entity_id: str
    principal_id: str
    outcome: str
    correlation_id: str
    artifact_type: str | None = None
    raw_content_logged: bool = False
    secrets_logged: bool = False
    production_observability_validated: bool = False

    def __post_init__(self) -> None:
        for name in ("event_type", "entity_id", "principal_id", "outcome", "correlation_id"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        if self.artifact_type is not None:
            object.__setattr__(self, "artifact_type", _text("artifact_type", self.artifact_type))
        try:
            parsed = datetime.fromisoformat(self.observed_at.replace("Z", "+00:00"))
        except ValueError as exc:
            raise SecurityBoundaryError("observed_at must be ISO-8601") from exc
        if parsed.tzinfo is None:
            raise SecurityBoundaryError("observed_at must include a timezone")
        if self.raw_content_logged is not False or self.secrets_logged is not False:
            raise SecurityBoundaryError("security observations must be metadata-only")
        if self.production_observability_validated is not False:
            raise SecurityBoundaryError("reference observation cannot claim production validation")

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)
