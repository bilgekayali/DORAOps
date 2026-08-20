from __future__ import annotations

import json
from pathlib import Path

import jsonschema


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_NAMES = (
    "reporting-applicability-decision.schema.json",
    "incident-reporting-route.schema.json",
    "incident-report-package.schema.json",
    "submission-receipt-evidence.schema.json",
    "authority-acknowledgement-evidence.schema.json",
    "deadline-adjustment-evidence.schema.json",
    "delay-notification-evidence.schema.json",
    "reporting-deadline.schema.json",
    "reporting-workflow-assessment.schema.json",
)


def load(name: str):
    return json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8"))


def test_v03_reporting_schemas_are_strict_draft_2020_12_contracts():
    for name in SCHEMA_NAMES:
        schema = load(name)
        assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
        assert schema["additionalProperties"] is False
        jsonschema.Draft202012Validator.check_schema(schema)


def test_report_package_profiles_and_nonclaims_are_pinned():
    package = load("incident-report-package.schema.json")
    assert package["properties"]["rts_content_profile"]["const"] == "EU-2025-301@2025-02-20"
    assert package["properties"]["its_template_profile"]["const"] == "EU-2025-302-ANNEX-I@2025-02-20"

    assessment = load("reporting-workflow-assessment.schema.json")
    assert assessment["properties"]["regulatory_compliance_determined"]["const"] is False
    assert assessment["properties"]["authority_acceptance_determined"]["const"] is False


def test_alternative_submission_schema_requires_technical_impossibility_evidence():
    schema = load("submission-receipt-evidence.schema.json")
    base = {
        "entity_id": "bank-a",
        "incident_id": "INC-1",
        "report_type": "initial_notification",
        "sequence": 1,
        "package_digest": "a" * 64,
        "submitted_at": 100,
        "channel": "alternative",
        "external_submission_evidence_digest": "b" * 64,
        "authority_reference": "AUTH-1",
        "technical_impossibility_evidence_digest": None,
    }
    validator = jsonschema.Draft202012Validator(schema)
    assert list(validator.iter_errors(base))
    base["technical_impossibility_evidence_digest"] = "c" * 64
    validator.validate(base)


def test_aggregated_route_schema_requires_permission_and_scope_evidence():
    schema = load("incident-reporting-route.schema.json")
    payload = {
        "entity_id": "bank-a",
        "route_id": "agg",
        "version": 1,
        "competent_authority_id": "DE-NCA",
        "member_state": "DE",
        "submission_mode": "aggregated",
        "submitter_id": "provider-x",
        "contact_evidence_digest": "a" * 64,
        "outsourcing_evidence_digest": "b" * 64,
        "authority_permission_evidence_digest": None,
        "aggregation_scope_evidence_digest": None,
        "registered_at": 100,
    }
    validator = jsonschema.Draft202012Validator(schema)
    assert list(validator.iter_errors(payload))
    payload["authority_permission_evidence_digest"] = "c" * 64
    payload["aggregation_scope_evidence_digest"] = "d" * 64
    validator.validate(payload)


def test_without_undue_delay_schema_cannot_carry_fabricated_numeric_due_time():
    schema = load("reporting-deadline.schema.json")
    payload = {
        "entity_id": "bank-a",
        "incident_id": "INC-1",
        "report_type": "intermediate_report",
        "sequence": 2,
        "basis": "recovery_update_without_undue_delay",
        "triggered_at": 100,
        "statutory_due_at": 200,
        "effective_due_at": 200,
        "adjustment_digest": None,
    }
    validator = jsonschema.Draft202012Validator(schema)
    assert list(validator.iter_errors(payload))
    payload["statutory_due_at"] = None
    payload["effective_due_at"] = None
    validator.validate(payload)
