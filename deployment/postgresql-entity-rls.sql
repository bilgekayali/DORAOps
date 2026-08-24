-- DORAOps v0.5 PostgreSQL entity-isolation reference.
-- This file is a deployment/reference contract only. Passing it in CI is not
-- production isolation validation and does not establish DORA compliance.

CREATE ROLE doraops_app NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;

ALTER TABLE dora_evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE dora_evidence FORCE ROW LEVEL SECURITY;

CREATE POLICY dora_evidence_entity_isolation
ON dora_evidence
USING (
  entity_id = current_setting('doraops.entity_id', true)
)
WITH CHECK (
  entity_id = current_setting('doraops.entity_id', true)
);

REVOKE ALL ON dora_evidence FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON dora_evidence TO doraops_app;

-- Application transactions must set the authenticated entity scope locally:
--   BEGIN;
--   SET LOCAL doraops.entity_id = 'entity-a';
--   ... statements ...
--   COMMIT;
--
-- Production validation must separately prove:
-- * the application role is non-superuser and NOBYPASSRLS;
-- * FORCE ROW LEVEL SECURITY remains enabled;
-- * connection-pool reuse cannot leak a previous entity setting;
-- * cross-entity SELECT/INSERT/UPDATE/DELETE paths fail closed;
-- * backup/restore, maintenance and break-glass roles are separately governed.
