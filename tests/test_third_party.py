from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path

import jsonschema
import pytest

from doraops import (
    BusinessFunction,
    ConcentrationAssessment,
    DependencyObservation,
    ExitTransitionPlan,
    FinancialEntity,
    FunctionClassification,
    GeographicLocation,
    GovernanceError,
    ICTService,
    InventoryRegistry,
    ProviderDesignation,
    RegisterAssessmentState,
    SubstitutabilityAssessment,
    ThirdPartyGapCode,
    ThirdPartyGovernancePolicy,
    ThirdPartyProvider,
    ThirdPartyRegister,
    ThirdPartyService,
    build_register_snapshot,
    build_third_party_arrangement,
    canonical_json,
    sha256_digest,
)


def digest(seed: str) -> str:
    return sha256_digest({"seed": seed})


def inventory_fixture() -> InventoryRegistry:
    inventory = InventoryRegistry()
    inventory.register_entity(FinancialEntity("bank-a", "Bank A", "DE"))
    inventory.register_node(
        BusinessFunction(
            "bank-a",
            "payments",
            "Payments",
            FunctionClassification.CRITICAL_OR_IMPORTANT,
            "board-owner",
            "human criticality decision",
        )
    )
    inventory.register_node(
        BusinessFunction(
            "bank-a",
            "reporting",
            "Reporting",
            FunctionClassification.STANDARD,
            "board-owner",
            "human standard classification",
        )
    )
    for provider_id in ("provider-a", "provider-b", "provider-c"):
        inventory.register_provider(
            ThirdPartyProvider(
                "bank-a",
                provider_id,
                provider_id.replace("-", " ").title(),
                "internal_reference",
                f"ID-{provider_id}",
            )
        )
    inventory.register_node(
        ThirdPartyService(
            "bank-a",
            "cloud-primary",
            "provider-a",
            "Primary Cloud",
            "cloud",
            True,
            1,
        )
    )
    inventory.register_node(
        ThirdPartyService(
            "bank-a",
            "cloud-subprocessor",
            "provider-b",
            "Subprocessor",
            "data_processing",
            False,
            2,
            "cloud-primary",
        )
    )
    inventory.register_node(
        ThirdPartyService(
            "bank-a",
            "other-direct",
            "provider-c",
            "Other Direct",
            "hosting",
            True,
            1,
        )
    )
    inventory.register_node(
        ThirdPartyService(
            "bank-a",
            "other-subprocessor",
            "provider-b",
            "Other Subprocessor",
            "data_processing",
            False,
            2,
            "other-direct",
        )
    )
    return inventory


def arrangement_fixture(*, complete: bool = True):
    inventory = inventory_fixture()
    arrangement = build_third_party_arrangement(
        inventory,
        entity_id="bank-a",
        arrangement_id="ARR-1",
        contract_reference="CONTRACT-2026-001",
        direct_provider_id="provider-a",
        direct_service_ids=("cloud-primary",),
        subcontracted_service_ids=("cloud-subprocessor",),
        supported_function_ids=("payments", "reporting"),
        critical_or_important_function_ids=("payments",),
        provider_designation=(
            ProviderDesignation.NOT_DESIGNATED_CRITICAL
            if complete
            else ProviderDesignation.UNASSESSED
        ),
        provider_designation_owner="third-party-risk-owner",
        provider_designation_rationale="authoritative governance input",
        data_locations=(GeographicLocation("DE", "Frankfurt", "data at rest"),) if complete else (),
        service_locations=(GeographicLocation("IE", "Dublin", "service delivery"),) if complete else (),
        contract_evidence_digests=(digest("contract"),) if complete else (),
        control_requirement_evidence_digests=(digest("controls"),) if complete else (),
        effective_from=100,
    )
    register = ThirdPartyRegister(inventory)
    register.register_arrangement(arrangement)
    return inventory, register, arrangement


def observation(arrangement, *, observation_id="OBS-1", observed_at=150):
    return DependencyObservation(
        entity_id="bank-a",
        arrangement_id=arrangement.arrangement_id,
        arrangement_digest=arrangement.evidence_digest,
        observation_id=observation_id,
        observed_at=observed_at,
        substitutability=SubstitutabilityAssessment.DIFFICULT,
        concentration=ConcentrationAssessment.HIGH,
        rationale="institution assessment based on current dependency evidence",
        evidence_digest=digest(observation_id),
    )


def exit_plan(arrangement):
    return ExitTransitionPlan(
        entity_id="bank-a",
        arrangement_id=arrangement.arrangement_id,
        arrangement_digest=arrangement.evidence_digest,
        exit_plan_id="EXIT-1",
        owner_id="exit-owner",
        updated_at=160,
        trigger_conditions=("provider failure", "material contract termination"),
        transition_steps=("activate transition governance", "migrate service workload"),
        evidence_digests=(digest("exit-plan"),),
        alternate_provider_reference="ALT-PROVIDER-ASSESSMENT-1",
    )


def policy(**kwargs):
    return ThirdPartyGovernancePolicy(
        entity_id="bank-a",
        policy_id="third-party-policy",
        version="1",
        **kwargs,
    )


def test_arrangement_resolves_provider_services_functions_and_supply_chain():
    _, register, arrangement = arrangement_fixture()
    register.register_observation(observation(arrangement))
    register.register_exit_plan(exit_plan(arrangement))

    snapshot = build_register_snapshot(register, policy(), as_of=200)

    assert snapshot.state is RegisterAssessmentState.COMPLETE
    assert snapshot.mapping_profile == "EU-2024-2956-support-v1"
    assert [row.service_id for row in snapshot.rows] == [
        "cloud-primary",
        "cloud-subprocessor",
    ]
    assert [row.supply_chain_rank for row in snapshot.rows] == [1, 2]
    assert snapshot.rows[1].parent_service_id == "cloud-primary"
    assert snapshot.rows[0].critical_or_important_function_ids == ("payments",)


def test_explicit_critical_function_input_must_match_authoritative_inventory():
    inventory = inventory_fixture()
    register = ThirdPartyRegister(inventory)
    arrangement = build_third_party_arrangement(
        inventory,
        entity_id="bank-a",
        arrangement_id="ARR-1",
        contract_reference="CONTRACT",
        direct_provider_id="provider-a",
        direct_service_ids=("cloud-primary",),
        subcontracted_service_ids=(),
        supported_function_ids=("payments",),
        critical_or_important_function_ids=(),
        provider_designation=ProviderDesignation.UNASSESSED,
        provider_designation_owner="owner",
        provider_designation_rationale="explicit but inconsistent input",
        effective_from=100,
    )
    with pytest.raises(GovernanceError, match="authoritative function classifications"):
        register.register_arrangement(arrangement)


def test_provider_and_subcontractor_references_fail_closed():
    inventory = inventory_fixture()
    register = ThirdPartyRegister(inventory)
    wrong_provider = build_third_party_arrangement(
        inventory,
        entity_id="bank-a",
        arrangement_id="ARR-provider",
        contract_reference="CONTRACT",
        direct_provider_id="provider-c",
        direct_service_ids=("cloud-primary",),
        subcontracted_service_ids=(),
        supported_function_ids=("reporting",),
        critical_or_important_function_ids=(),
        provider_designation=ProviderDesignation.UNASSESSED,
        provider_designation_owner="owner",
        provider_designation_rationale="explicit input",
        effective_from=100,
    )
    with pytest.raises(GovernanceError, match="different provider"):
        register.register_arrangement(wrong_provider)

    wrong_subtree = build_third_party_arrangement(
        inventory,
        entity_id="bank-a",
        arrangement_id="ARR-subtree",
        contract_reference="CONTRACT",
        direct_provider_id="provider-a",
        direct_service_ids=("cloud-primary",),
        subcontracted_service_ids=("other-subprocessor",),
        supported_function_ids=("reporting",),
        critical_or_important_function_ids=(),
        provider_designation=ProviderDesignation.UNASSESSED,
        provider_designation_owner="owner",
        provider_designation_rationale="explicit input",
        effective_from=100,
    )
    with pytest.raises(GovernanceError, match="does not descend"):
        register.register_arrangement(wrong_subtree)


def test_gap_report_exposes_missing_governance_without_legal_claim():
    _, register, arrangement = arrangement_fixture(complete=False)
    snapshot = build_register_snapshot(register, policy(), as_of=200)
    codes = {gap.code for gap in snapshot.gaps}

    assert snapshot.state is RegisterAssessmentState.WITH_GAPS
    assert codes == {
        ThirdPartyGapCode.PROVIDER_DESIGNATION_UNASSESSED,
        ThirdPartyGapCode.MISSING_DATA_LOCATION,
        ThirdPartyGapCode.MISSING_SERVICE_LOCATION,
        ThirdPartyGapCode.MISSING_CONTRACT_EVIDENCE,
        ThirdPartyGapCode.MISSING_CONTROL_REQUIREMENT_EVIDENCE,
        ThirdPartyGapCode.MISSING_DEPENDENCY_OBSERVATION,
        ThirdPartyGapCode.MISSING_EXIT_PLAN,
    }
    assert snapshot.arrangement_digests == (arrangement.evidence_digest,)


def test_observation_and_exit_plan_complete_policy_driven_evidence():
    _, register, arrangement = arrangement_fixture()
    obs = observation(arrangement)
    plan = exit_plan(arrangement)
    register.register_observation(obs)
    register.register_exit_plan(plan)

    first = build_register_snapshot(register, policy(max_observation_age=100), as_of=200)
    second = build_register_snapshot(register, policy(max_observation_age=100), as_of=200)

    assert first.state is RegisterAssessmentState.COMPLETE
    assert first.evidence_digest == second.evidence_digest
    assert first.observation_digests == (obs.governance_digest,)
    assert first.exit_plan_digests == (plan.governance_digest,)


def test_stale_and_conflicting_latest_observations_fail_closed_or_surface_gap():
    _, register, arrangement = arrangement_fixture()
    register.register_observation(observation(arrangement, observed_at=120))
    register.register_exit_plan(exit_plan(arrangement))
    stale = build_register_snapshot(register, policy(max_observation_age=50), as_of=200)
    assert ThirdPartyGapCode.STALE_DEPENDENCY_OBSERVATION in {gap.code for gap in stale.gaps}

    _, conflicting_register, conflicting_arrangement = arrangement_fixture()
    conflicting_register.register_observation(
        observation(conflicting_arrangement, observation_id="OBS-A", observed_at=150)
    )
    conflicting_register.register_observation(
        observation(conflicting_arrangement, observation_id="OBS-B", observed_at=150)
    )
    with pytest.raises(GovernanceError, match="conflicting latest"):
        build_register_snapshot(conflicting_register, policy(), as_of=200)


def test_arrangement_is_immutable_and_stale_after_inventory_change():
    inventory, register, arrangement = arrangement_fixture()
    changed = replace(arrangement, contract_reference="CHANGED")
    with pytest.raises(GovernanceError, match="different content"):
        register.register_arrangement(changed)

    inventory.register_node(ICTService("bank-a", "new-service", "New Service", "owner", "application"))
    with pytest.raises(GovernanceError, match="stale for current inventory"):
        build_register_snapshot(register, policy(), as_of=200)


def test_third_party_artifacts_validate_against_release_schemas():
    _, register, arrangement = arrangement_fixture()
    obs = observation(arrangement)
    plan = exit_plan(arrangement)
    register.register_observation(obs)
    register.register_exit_plan(plan)
    governance_policy = policy(max_observation_age=100)
    snapshot = build_register_snapshot(register, governance_policy, as_of=200)

    root = Path(__file__).resolve().parents[1]
    cases = (
        ("third-party-arrangement.schema.json", arrangement),
        ("third-party-dependency-observation.schema.json", obs),
        ("third-party-exit-plan.schema.json", plan),
        ("third-party-governance-policy.schema.json", governance_policy),
        ("third-party-register-snapshot.schema.json", snapshot),
    )
    for schema_name, artifact in cases:
        schema = json.loads((root / "schemas" / schema_name).read_text())
        payload = json.loads(canonical_json(artifact))
        jsonschema.Draft202012Validator(schema).validate(payload)
