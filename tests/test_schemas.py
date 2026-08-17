import json
from pathlib import Path

import jsonschema
import pytest

from doraops import (
    BusinessFunction,
    DependencyEdge,
    DependencyRelationship,
    FinancialEntity,
    FunctionClassification,
    NodeKind,
    NodeRef,
    ThirdPartyProvider,
    ThirdPartyService,
    canonical_json,
)


ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / "schemas"


def schema(name: str) -> dict:
    return json.loads((SCHEMAS / name).read_text(encoding="utf-8"))


def payload(value) -> object:
    return json.loads(canonical_json(value))


def test_all_schemas_are_valid_draft_2020_12() -> None:
    for path in SCHEMAS.glob("*.schema.json"):
        jsonschema.Draft202012Validator.check_schema(
            json.loads(path.read_text(encoding="utf-8"))
        )


def test_real_inventory_artifacts_match_strict_schemas() -> None:
    financial_entity = FinancialEntity("bank-a", "Bank A", "TR")
    function = BusinessFunction(
        "bank-a",
        "payments",
        "Payment Processing",
        FunctionClassification.CRITICAL_OR_IMPORTANT,
        "operational-risk",
        "Material customer impact if disrupted",
    )
    provider = ThirdPartyProvider(
        "bank-a",
        "cloud-provider",
        "Cloud Provider Ltd",
        "internal_reference",
        "CP-001",
    )
    service = ThirdPartyService(
        "bank-a",
        "cloud-primary",
        "cloud-provider",
        "Primary Cloud",
        "cloud_infrastructure",
        True,
        1,
    )
    edge = DependencyEdge(
        "bank-a",
        "function-cloud",
        NodeRef("bank-a", NodeKind.BUSINESS_FUNCTION, "payments"),
        NodeRef("bank-a", NodeKind.THIRD_PARTY_SERVICE, "cloud-primary"),
        DependencyRelationship.SUPPORTED_BY,
        "Critical function depends on cloud service",
    )

    jsonschema.validate(payload(financial_entity), schema("financial-entity.schema.json"))
    jsonschema.validate(payload(function), schema("inventory-node.schema.json"))
    jsonschema.validate(payload(provider), schema("third-party-provider.schema.json"))
    jsonschema.validate(payload(service), schema("inventory-node.schema.json"))
    jsonschema.validate(payload(edge), schema("dependency-edge.schema.json"))


def test_unknown_security_relevant_field_is_rejected() -> None:
    value = payload(FinancialEntity("bank-a", "Bank A", "TR"))
    assert isinstance(value, dict)
    value["silently_trust_provider"] = True
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(value, schema("financial-entity.schema.json"))
