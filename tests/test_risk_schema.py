import json
from pathlib import Path

import jsonschema

from doraops import (
    BusinessFunction,
    ControlEffectiveness,
    FinancialEntity,
    FunctionClassification,
    ICTControlObservation,
    ICTRiskPolicy,
    ICTRiskScenario,
    ICTService,
    Impact,
    InventoryRegistry,
    Likelihood,
    NodeKind,
    NodeRef,
    RiskTreatmentPlan,
    TreatmentType,
    assess_ict_risk,
    canonical_json,
)


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "schemas" / "ict-risk.schema.json").read_text(encoding="utf-8"))


def payload(value) -> object:
    return json.loads(canonical_json(value))


def artifacts():
    registry = InventoryRegistry()
    registry.register_entity(FinancialEntity("bank-a", "Bank A", "TR"))
    registry.register_node(
        BusinessFunction(
            "bank-a",
            "payments",
            "Payment Processing",
            FunctionClassification.CRITICAL_OR_IMPORTANT,
            "operational-risk",
            "Material customer impact",
        )
    )
    registry.register_node(
        ICTService("bank-a", "payments-api", "Payments API", "platform-owner", "application_service")
    )
    scenario = ICTRiskScenario(
        "bank-a",
        "payments-outage",
        "Payment outage",
        "Platform outage",
        "Insufficient failover",
        "operational-risk",
        (
            NodeRef("bank-a", NodeKind.BUSINESS_FUNCTION, "payments"),
            NodeRef("bank-a", NodeKind.ICT_SERVICE, "payments-api"),
        ),
        Likelihood.LIKELY,
        Impact.CRITICAL,
    )
    control = ICTControlObservation(
        "bank-a",
        "failover",
        "Failover capability",
        "availability",
        ControlEffectiveness.ADEQUATE,
        "1" * 64,
    )
    policy = ICTRiskPolicy("bank-a", "ict-risk", "1")
    treatment = RiskTreatmentPlan(
        TreatmentType.MITIGATE,
        "technology-risk-owner",
        "Increase resilience capacity",
        target_timestamp=1_800_000_000,
    )
    decision = assess_ict_risk(registry, scenario, (control,), policy, treatment)
    return scenario, control, policy, treatment, decision


def test_real_risk_artifacts_match_strict_schema() -> None:
    jsonschema.Draft202012Validator.check_schema(SCHEMA)
    for artifact in artifacts():
        jsonschema.validate(payload(artifact), SCHEMA)
