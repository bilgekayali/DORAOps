from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from doraops import (
    BusinessFunction,
    DossierState,
    FinancialEntity,
    FunctionClassification,
    GovernanceDossierBuilder,
    GovernanceError,
    ICTIncident,
    ICTRiskPolicy,
    ICTRiskScenario,
    ICTService,
    Impact,
    ImpactDimension,
    IncidentClassificationPolicy,
    IncidentRegistry,
    InventoryRegistry,
    Likelihood,
    NodeKind,
    NodeRef,
    ProviderDesignation,
    ResilienceTestType,
    RiskTreatmentPlan,
    TestExecutionOutcome,
    ThirdPartyGovernancePolicy,
    ThirdPartyProvider,
    ThirdPartyRegister,
    ThirdPartyService,
    TreatmentType,
    assess_ict_risk,
    build_resilience_test_plan,
    build_third_party_arrangement,
    canonical_json,
    dossier_document,
    record_test_execution,
    resolve_test,
    sha256_digest,
    verify_dossier_document,
)
from doraops.cli import main as cli_main
from doraops.third_party import ThirdPartyRegister as LooseThirdPartyRegister


def governed_risk_fixture():
    registry = InventoryRegistry()
    registry.register_entity(FinancialEntity("bank-a", "Bank A", "DE"))
    function = BusinessFunction(
        "bank-a",
        "payments",
        "Payments",
        FunctionClassification.CRITICAL_OR_IMPORTANT,
        "board-owner",
        "human classification",
    )
    service = ICTService("bank-a", "payment-api", "Payment API", "svc-owner", "application")
    registry.register_node(function)
    registry.register_node(service)
    refs = (
        NodeRef("bank-a", NodeKind.BUSINESS_FUNCTION, "payments"),
        NodeRef("bank-a", NodeKind.ICT_SERVICE, "payment-api"),
    )
    scenario = ICTRiskScenario(
        entity_id="bank-a",
        scenario_id="risk-1",
        title="Payment API outage",
        threat="service disruption",
        vulnerability="single processing path",
        risk_owner_id="risk-owner",
        affected_nodes=refs,
        likelihood=Likelihood.LIKELY,
        impact=Impact.SEVERE,
    )
    policy = ICTRiskPolicy("bank-a", "risk-policy", "1")
    treatment = RiskTreatmentPlan(
        TreatmentType.MITIGATE,
        "treatment-owner",
        "reduce outage exposure",
        target_timestamp=500,
    )
    decision = assess_ict_risk(registry, scenario, (), policy, treatment)
    return registry, refs, scenario, policy, decision


def test_current_dossier_is_schema_valid_and_offline_verifiable(tmp_path: Path):
    registry, refs, scenario, policy, decision = governed_risk_fixture()
    builder = GovernanceDossierBuilder(
        registry,
        entity_id="bank-a",
        generated_at=1_800_000_000,
        source_revision="release-candidate-sha",
    )
    builder.add_risk_decision(decision, scenario, (), policy)

    plan = build_resilience_test_plan(
        registry,
        (decision,),
        entity_id="bank-a",
        test_id="test-1",
        title="Payment recovery",
        test_type=ResilienceTestType.SCENARIO_BASED,
        objective="Exercise payment recovery",
        test_owner_id="test-owner",
        independent_reviewer_id=None,
        scope_nodes=refs,
        scenario="primary path loss",
        planned_at=200,
    )
    execution = record_test_execution(
        plan,
        registry,
        (decision,),
        execution_id="exec-1",
        executed_at=300,
        executor_id="operator",
        outcome=TestExecutionOutcome.PASSED,
        evidence_digests=(sha256_digest({"evidence": "execution"}),),
        notes="completed",
    )
    resolution = resolve_test(plan, execution, ())
    builder.add_resilience_test(plan, (decision,), execution, resolution)

    dossier = builder.build()
    assert dossier.state is DossierState.CURRENT
    assert dossier.inventory_snapshot_digest == registry.snapshot_digest("bank-a")
    document = dossier_document(dossier)
    assert verify_dossier_document(document) == document["dossier_digest"]

    schema = json.loads(
        (Path(__file__).resolve().parents[1] / "schemas" / "governance-dossier.schema.json").read_text()
    )
    jsonschema.Draft202012Validator(schema).validate(document)

    dossier_path = tmp_path / "dossier.json"
    dossier_path.write_text(json.dumps(document), encoding="utf-8")
    assert cli_main(["dossier", "verify", str(dossier_path)]) == 0
    assert cli_main(["digest", str(dossier_path)]) == 0


def test_tampered_embedded_artifact_fails_even_if_outer_digest_is_recomputed():
    registry, _, scenario, policy, decision = governed_risk_fixture()
    builder = GovernanceDossierBuilder(
        registry,
        entity_id="bank-a",
        generated_at=1_800_000_000,
        source_revision="sha",
    )
    builder.add_risk_decision(decision, scenario, (), policy)
    document = dossier_document(builder.build())
    artifact = next(
        item
        for item in document["dossier"]["artifacts"]
        if item["artifact_type"] == "financial_entity"
    )
    artifact["payload"]["legal_name"] = "Tampered Bank"
    document["dossier_digest"] = sha256_digest(document["dossier"])
    with pytest.raises(GovernanceError, match="artifact payload digest mismatch"):
        verify_dossier_document(document)


def test_stale_risk_decision_is_packaged_as_revalidation_required():
    registry, _, scenario, policy, decision = governed_risk_fixture()
    registry.register_node(ICTService("bank-a", "new-api", "New API", "owner", "application"))
    builder = GovernanceDossierBuilder(
        registry,
        entity_id="bank-a",
        generated_at=1_800_000_000,
        source_revision="sha",
    )
    builder.add_risk_decision(decision, scenario, (), policy)
    dossier = builder.build()
    assert dossier.state is DossierState.REVALIDATION_REQUIRED
    assert any("stale for current inventory snapshot" in item for item in dossier.findings)


def test_incomplete_incident_evidence_is_explicit_gap_not_final_classification():
    registry, refs, _, _, _ = governed_risk_fixture()
    incidents = IncidentRegistry(registry)
    incident = ICTIncident(
        entity_id="bank-a",
        incident_id="inc-1",
        title="Payment interruption",
        incident_owner_id="incident-owner",
        occurred_at=100,
        detected_at=110,
        inventory_snapshot_digest=registry.snapshot_digest("bank-a"),
        affected_nodes=(refs[0],),
    )
    incidents.register_incident(incident)
    policy = IncidentClassificationPolicy(
        entity_id="bank-a",
        policy_id="incident-policy",
        version="1",
        required_impact_dimensions=(ImpactDimension.SERVICE_AVAILABILITY,),
    )
    builder = GovernanceDossierBuilder(
        registry,
        entity_id="bank-a",
        generated_at=1_800_000_000,
        source_revision="sha",
    )
    builder.add_incident(incidents, "inc-1", policy)
    dossier = builder.build()
    assert dossier.state is DossierState.WITH_GAPS
    assert any("impact_observation" in item for item in dossier.findings)


def test_public_dossier_builder_rejects_loose_third_party_register_boundary():
    registry, _, _, _, _ = governed_risk_fixture()
    loose = LooseThirdPartyRegister(registry)
    policy = ThirdPartyGovernancePolicy("bank-a", "third-party-policy", "1")
    builder = GovernanceDossierBuilder(
        registry,
        entity_id="bank-a",
        generated_at=1_800_000_000,
        source_revision="sha",
    )
    with pytest.raises(GovernanceError, match="strict public ThirdPartyRegister"):
        builder.add_third_party_register(loose, policy, as_of=500)


def test_third_party_policy_gaps_are_carried_into_dossier():
    registry, _, _, _, _ = governed_risk_fixture()
    registry.register_provider(ThirdPartyProvider("bank-a", "cloud", "Cloud Co", "internal", "cloud"))
    registry.register_node(
        ThirdPartyService(
            "bank-a",
            "cloud-service",
            "cloud",
            "Cloud Hosting",
            "cloud",
            True,
            1,
        )
    )
    register = ThirdPartyRegister(registry)
    arrangement = build_third_party_arrangement(
        registry,
        entity_id="bank-a",
        arrangement_id="arr-1",
        contract_reference="contract-1",
        direct_provider_id="cloud",
        direct_service_ids=("cloud-service",),
        subcontracted_service_ids=(),
        supported_function_ids=("payments",),
        critical_or_important_function_ids=("payments",),
        provider_designation=ProviderDesignation.UNASSESSED,
        provider_designation_owner="third-party-owner",
        provider_designation_rationale="assessment pending",
        effective_from=100,
    )
    register.register_arrangement(arrangement)
    policy = ThirdPartyGovernancePolicy("bank-a", "third-party-policy", "1")
    builder = GovernanceDossierBuilder(
        registry,
        entity_id="bank-a",
        generated_at=1_800_000_000,
        source_revision="sha",
    )
    builder.add_third_party_register(register, policy, as_of=500)
    dossier = builder.build()
    assert dossier.state is DossierState.WITH_GAPS
    assert any("provider_designation_unassessed" in item for item in dossier.findings)


def test_canonical_document_is_deterministic():
    registry, _, scenario, policy, decision = governed_risk_fixture()
    builder = GovernanceDossierBuilder(
        registry,
        entity_id="bank-a",
        generated_at=1_800_000_000,
        source_revision="sha",
    )
    builder.add_risk_decision(decision, scenario, (), policy)
    dossier = builder.build()
    assert canonical_json(dossier_document(dossier)) == canonical_json(dossier_document(dossier))
