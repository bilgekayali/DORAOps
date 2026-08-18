from __future__ import annotations

from dataclasses import replace

import pytest

from doraops import (
    BusinessFunction,
    ConcentrationAssessment,
    DependencyObservation,
    FinancialEntity,
    FunctionClassification,
    GovernanceError,
    InventoryRegistry,
    ProviderDesignation,
    SubstitutabilityAssessment,
    ThirdPartyGovernancePolicy,
    ThirdPartyProvider,
    ThirdPartyRegister,
    ThirdPartyService,
    build_register_snapshot,
    build_third_party_arrangement,
    sha256_digest,
)


def digest(seed: str) -> str:
    return sha256_digest({"seed": seed})


def fixture():
    inventory = InventoryRegistry()
    inventory.register_entity(FinancialEntity("bank-a", "Bank A", "DE"))
    inventory.register_node(
        BusinessFunction(
            "bank-a",
            "payments",
            "Payments",
            FunctionClassification.CRITICAL_OR_IMPORTANT,
            "owner",
            "human classification",
        )
    )
    inventory.register_provider(
        ThirdPartyProvider(
            "bank-a",
            "provider-a",
            "Provider A",
            "internal_reference",
            "PROVIDER-A",
        )
    )
    inventory.register_node(
        ThirdPartyService(
            "bank-a",
            "service-a",
            "provider-a",
            "Service A",
            "cloud",
            True,
            1,
        )
    )
    arrangement = build_third_party_arrangement(
        inventory,
        entity_id="bank-a",
        arrangement_id="ARR-1",
        contract_reference="CONTRACT-1",
        direct_provider_id="provider-a",
        direct_service_ids=("service-a",),
        subcontracted_service_ids=(),
        supported_function_ids=("payments",),
        critical_or_important_function_ids=("payments",),
        provider_designation=ProviderDesignation.UNASSESSED,
        provider_designation_owner="owner",
        provider_designation_rationale="explicit authoritative input",
        effective_from=100,
    )
    return inventory, arrangement


def test_raw_provider_designation_string_fails_closed():
    inventory, arrangement = fixture()
    register = ThirdPartyRegister(inventory)
    malformed = replace(arrangement, provider_designation="unassessed")
    with pytest.raises(GovernanceError, match="governed enum type"):
        register.register_arrangement(malformed)


def test_raw_observation_enum_strings_fail_closed():
    inventory, arrangement = fixture()
    register = ThirdPartyRegister(inventory)
    register.register_arrangement(arrangement)
    malformed = DependencyObservation(
        entity_id="bank-a",
        arrangement_id="ARR-1",
        arrangement_digest=arrangement.evidence_digest,
        observation_id="OBS-1",
        observed_at=150,
        substitutability="difficult",
        concentration=ConcentrationAssessment.HIGH,
        rationale="malformed raw input",
        evidence_digest=digest("obs"),
    )
    with pytest.raises(GovernanceError, match="governed enum type"):
        register.register_observation(malformed)


def test_integer_policy_boolean_fails_closed():
    inventory, arrangement = fixture()
    register = ThirdPartyRegister(inventory)
    register.register_arrangement(arrangement)
    malformed_policy = ThirdPartyGovernancePolicy(
        entity_id="bank-a",
        policy_id="policy",
        version="1",
        require_data_location=1,
    )
    with pytest.raises(GovernanceError, match="must be a boolean"):
        build_register_snapshot(register, malformed_policy, as_of=200)


def test_valid_governed_enums_remain_accepted():
    inventory, arrangement = fixture()
    register = ThirdPartyRegister(inventory)
    register.register_arrangement(arrangement)
    observation = DependencyObservation(
        entity_id="bank-a",
        arrangement_id="ARR-1",
        arrangement_digest=arrangement.evidence_digest,
        observation_id="OBS-1",
        observed_at=150,
        substitutability=SubstitutabilityAssessment.DIFFICULT,
        concentration=ConcentrationAssessment.HIGH,
        rationale="valid governed input",
        evidence_digest=digest("obs"),
    )
    register.register_observation(observation)
