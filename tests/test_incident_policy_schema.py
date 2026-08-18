import json
from pathlib import Path

import jsonschema

from doraops import ImpactDimension, IncidentClassificationPolicy, canonical_json


def test_incident_classification_policy_validates_against_release_schema():
    policy = IncidentClassificationPolicy(
        entity_id="bank-a",
        policy_id="incident-policy",
        version="1",
        required_impact_dimensions=(
            ImpactDimension.SERVICE_AVAILABILITY,
            ImpactDimension.CLIENT_IMPACT,
        ),
        require_recovery_event=True,
        require_root_cause_reference=True,
        require_remediation_reference=True,
        require_notification_decision=True,
    )
    root = Path(__file__).resolve().parents[1]
    schema = json.loads((root / "schemas" / "incident-classification-policy.schema.json").read_text())
    payload = json.loads(canonical_json(policy))
    jsonschema.Draft202012Validator(schema).validate(payload)
