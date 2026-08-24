# v0.5 Security and Financial-Entity Boundary

DORAOps v0.5 turns the existing `FinancialEntity.entity_id` governance scope into an explicit runtime security boundary while preserving the project's offline, evidence-first posture.

## Reference flow

```text
pre-resolved Ed25519 OIDC/JWT
  -> issuer/audience/time/MFA/role verification
  -> exact FinancialEntity entity_id binding
  -> TenantContext
  -> entity-bound AES-256-GCM evidence envelope
  -> metadata-only SecurityObservation
  -> PostgreSQL RLS deployment reference
```

## Identity boundary

`doraops.security.verify_ed25519_oidc_token()` accepts only EdDSA/Ed25519 signatures and requires a separately supplied public key. It does not fetch JWKS, discover an identity provider, perform revocation checks or claim production identity validation.

The verifier checks exact issuer and audience, `exp` and optional `nbf`, configured principal/entity/roles/MFA claims, exact requested `FinancialEntity.entity_id`, and institution-owned required roles.

A valid reference token produces a `TenantContext`; it does not authenticate a real production user unless the calling environment has separately established key distribution, issuer trust, revocation, rotation and session controls.

## Evidence encryption

`encrypt_evidence()` uses AES-256-GCM with a 32-byte key supplied at the call boundary, a 96-bit nonce, and authenticated additional data containing exact entity, artifact type and external key reference. The repository contains no production encryption key.

`EvidenceKeyReference` stores only provider/key/version references. Cross-entity decryption is rejected before plaintext release.

## Observability

`SecurityObservation` is intentionally metadata-only. Its contract structurally fixes `raw_content_logged=false`, `secrets_logged=false` and `production_observability_validated=false`.

## PostgreSQL reference

`deployment/postgresql-entity-rls.sql` defines a non-superuser `NOBYPASSRLS` role, enables and forces RLS, and binds access to `current_setting('doraops.entity_id', true)`.

CI verifies the reference semantics only. Production isolation requires separate validation against the actual database, connection pool, maintenance roles and operational procedures.

## Explicit non-claims

v0.5 reference validation does not establish production tenant isolation, real IdP/JWKS/revocation/key-rotation validation, KMS/HSM/key-management effectiveness, production logging/monitoring effectiveness, DORA compliance or supervisory acceptance.
