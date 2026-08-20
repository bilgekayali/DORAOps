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
    GovernanceDossierBuilder,
    GovernanceError,
    InventoryRegistry,
    ProviderDesignation,
    SubstitutabilityAssessment,
    ThirdPartyGovernancePolicy,
    ThirdPartyProvider,
    ThirdPartyRegister,
    ThirdPartyService,
    build_third_party_arrangement,
    canonical_json,
    dossier_document,
    sha256_digest,
)
from doraops.assurance import (
    AssurancePolicy,
    AssuranceState,
    PortfolioAssuranceRegistry,
    verify_portfolio_snapshot,
)
from tests.test_continuity_dossier import build_continuity_dossier
from tests.test_dossier import governed_risk_fixture


def digest(seed: str) -> str:
    return sha256_digest({"seed": seed})


def policy(
    *,
    version: int = 1,
    required_domains: tuple[str, ...] = ("third_party",),
    registered_at: int = 0,
    provider_threshold: int = 2,
    critical_threshold: int = 2,
    max_age: int = 10_000,
) -> AssurancePolicy:
    return AssurancePolicy(
        portfolio_id="group-a",
        policy_id="executive-assurance",
        version=version,
        required_domains=required_domains,
        max_dossier_age_seconds=max_age,
        provider_entity_concentration_threshold=provider_threshold,
        critical_function_concentration_threshold=critical_threshold,
        owner_id="resilience-owner",
        registered_at=registered_at,
    )


def third_party_dossier(
    entity_id: str,
    *,
    generated_at: int = 500,
    source_revision: str = "source-1",
    concentration: ConcentrationAssessment = ConcentrationAssessment.LOW,
    substitutability: SubstitutabilityAssessment = SubstitutabilityAssessment.EASY,
):
    inventory = InventoryRegistry()
    inventory.register_entity(FinancialEntity(entity_id, entity_id.upper(), "DE"))
    inventory.register_node(
        BusinessFunction(
            entity_id,
            "payments",
            "Payments",
            FunctionClassification.CRITICAL_OR_IMPORTANT,
            "board-owner",
            "human criticality decision",
        )
    )
    inventory.register_provider(
        ThirdPartyProvider(
            entity_id,
            "cloud-provider",
            "Cloud Provider",
            "internal_reference",
            "CLOUD-PROVIDER",
        )
    )
    inventory.register_node(
        ThirdPartyService(
            entity_id,
            "cloud-service",
            "cloud-provider",
            "Cloud Service",
            "cloud",
            True,
            1,
        )
    )
    arrangement = build_third_party_arrangement(
        inventory,
        entity_id=entity_id,
        arrangement_id="ARR-1",
        contract_reference="CONTRACT-1",
        direct_provider_id="cloud-provider",
        direct_service_ids=("cloud-service",),
        subcontracted_service_ids=(),
        supported_function_ids=("payments",),
        critical_or_important_function_ids=("payments",),
        provider_designation=ProviderDesignation.NOT_DESIGNATED_CRITICAL,
        provider_designation_owner="third-party-owner",
        provider_designation_rationale="human governance input",
        data_locations=(GeographicLocation("DE", "Frankfurt"),),
        service_locations=(GeographicLocation("DE", "Frankfurt"),),
        contract_evidence_digests=(digest(f"{entity_id}-contract"),),
        control_requirement_evidence_digests=(digest(f"{entity_id}-controls"),),
        effective_from=100,
    )
    register = ThirdPartyRegister(inventory)
    register.register_arrangement(arrangement)
    register.register_observation(
        DependencyObservation(
            entity_id=entity_id,
            arrangement_id=arrangement.arrangement_id,
            arrangement_digest=arrangement.evidence_digest,
            observation_id="OBS-1",
            observed_at=150,
            substitutability=substitutability,
            concentration=concentration,
            rationale="institution-owned dependency assessment",
            evidence_digest=digest(f"{entity_id}-observation"),
        )
    )
    register.register_exit_plan(
        ExitTransitionPlan(
            entity_id=entity_id,
            arrangement_id=arrangement.arrangement_id,
            arrangement_digest=arrangement.evidence_digest,
            exit_plan_id="EXIT-1",
            owner_id="exit-owner",
            updated_at=160,
            trigger_conditions=("provider failure",),
            transition_steps=("activate transition governance",),
            evidence_digests=(digest(f"{entity_id}-exit"),),
            alternate_provider_reference="ALT-1",
        )
    )
    third_party_policy = ThirdPartyGovernancePolicy(
        entity_id=entity_id,
        policy_id="third-party-policy",
        version="1",
    )
    builder = GovernanceDossierBuilder(
        inventory,
        entity_id=entity_id,
        generated_at=generated_at,
        source_revision=source_revision,
    )
    builder.add_third_party_register(register, third_party_policy, as_of=200)
    return dossier_document(builder.build())


def risk_only_dossier(*, generated_at: int = 500):
    registry, _, scenario, risk_policy, decision = governed_risk_fixture()
    builder = GovernanceDossierBuilder(
        registry,
        entity_id="bank-a",
        generated_at=generated_at,
        source_revision="risk-only",
    )
    builder.add_risk_decision(decision, scenario, (), risk_policy)
    return dossier_document(builder.build())


def test_missing_required_domain_is_incomplete_and_nonclaims_remain_locked() -> None:
    registry = PortfolioAssuranceRegistry()
    assurance_policy = policy(required_domains=("continuity",))
    registry.register_policy(assurance_policy)
    registry.register_dossier(risk_only_dossier())

    position = registry.build_entity_position(
        assurance_policy,
        entity_id="bank-a",
        assessed_at=600,
    )
    assert position.state is AssuranceState.INCOMPLETE
    continuity = next(item for item in position.domain_summaries if item.domain == "continuity")
    assert continuity.artifact_count == 0
    assert continuity.state is AssuranceState.INCOMPLETE
    assert position.dora_compliance_determined is False
    assert position.operational_resilience_determined is False
    assert position.supervisory_acceptance_determined is False
    assert position.requires_human_review is True


def test_breached_continuity_evidence_drives_entity_and_portfolio_breach() -> None:
    *_, dossier = build_continuity_dossier(breached=True)
    registry = PortfolioAssuranceRegistry()
    assurance_policy = policy(required_domains=("continuity",), provider_threshold=5, critical_threshold=5)
    registry.register_policy(assurance_policy)
    registry.register_dossier(dossier_document(dossier))

    snapshot = registry.build_snapshot(
        assurance_policy,
        snapshot_id="quarterly",
        sequence=1,
        entity_ids=("bank-a",),
        assembled_at=400,
    )
    assert snapshot.positions[0].state is AssuranceState.BREACHED
    assert snapshot.state is AssuranceState.BREACHED
    assert any("continuity_recovery" in finding for finding in snapshot.positions[0].findings)
    assert snapshot.dora_compliance_determined is False
    assert snapshot.operational_resilience_determined is False


def test_cross_entity_provider_concentration_is_attention_not_legal_determination() -> None:
    registry = PortfolioAssuranceRegistry()
    assurance_policy = policy(provider_threshold=2, critical_threshold=2)
    registry.register_policy(assurance_policy)
    registry.register_dossier(third_party_dossier("bank-a"))
    registry.register_dossier(third_party_dossier("bank-b"))

    snapshot = registry.build_snapshot(
        assurance_policy,
        snapshot_id="quarterly",
        sequence=1,
        entity_ids=("bank-b", "bank-a"),
        assembled_at=600,
    )
    assert [item.state for item in snapshot.positions] == [AssuranceState.HEALTHY, AssuranceState.HEALTHY]
    assert snapshot.state is AssuranceState.ATTENTION
    exposure = snapshot.provider_exposures[0]
    assert exposure.provider_id == "cloud-provider"
    assert exposure.entity_ids == ("bank-a", "bank-b")
    assert exposure.critical_function_refs == ("bank-a:payments", "bank-b:payments")
    assert exposure.entity_concentration_threshold_reached is True
    assert exposure.critical_function_concentration_threshold_reached is True
    assert exposure.legal_concentration_risk_determined is False
    assert snapshot.legal_concentration_risk_determined is False


def test_represented_high_concentration_is_attention_not_breach() -> None:
    registry = PortfolioAssuranceRegistry()
    assurance_policy = policy(provider_threshold=5, critical_threshold=5)
    registry.register_policy(assurance_policy)
    registry.register_dossier(
        third_party_dossier(
            "bank-a",
            concentration=ConcentrationAssessment.HIGH,
            substitutability=SubstitutabilityAssessment.DIFFICULT,
        )
    )
    position = registry.build_entity_position(
        assurance_policy,
        entity_id="bank-a",
        assessed_at=600,
    )
    assert position.state is AssuranceState.ATTENTION
    assert any("third_party_concentration" in item for item in position.findings)


def test_dossier_age_policy_marks_position_for_revalidation() -> None:
    registry = PortfolioAssuranceRegistry()
    assurance_policy = policy(max_age=50)
    registry.register_policy(assurance_policy)
    registry.register_dossier(third_party_dossier("bank-a", generated_at=500))

    position = registry.build_entity_position(
        assurance_policy,
        entity_id="bank-a",
        assessed_at=551,
    )
    assert position.freshness_state is AssuranceState.REVALIDATION_REQUIRED
    assert position.state is AssuranceState.REVALIDATION_REQUIRED
    assert "dossier_age_exceeds_policy" in position.findings


def test_historical_snapshot_verifies_after_dossier_drift_but_is_not_current() -> None:
    registry = PortfolioAssuranceRegistry()
    assurance_policy = policy()
    registry.register_policy(assurance_policy)
    registry.register_dossier(third_party_dossier("bank-a", generated_at=500, source_revision="source-1"))
    first = registry.build_snapshot(
        assurance_policy,
        snapshot_id="quarterly",
        sequence=1,
        entity_ids=("bank-a",),
        assembled_at=600,
    )
    registry.register_snapshot(first, assurance_policy)

    registry.register_dossier(third_party_dossier("bank-a", generated_at=700, source_revision="source-2"))
    assert registry.verify_snapshot(first) == first.evidence_digest
    with pytest.raises(GovernanceError, match="stale for current entity dossier"):
        registry.assert_snapshot_current(first, assurance_policy)


def test_policy_drift_preserves_history_but_blocks_currentness_and_new_stale_builds() -> None:
    registry = PortfolioAssuranceRegistry()
    first_policy = policy(version=1)
    registry.register_policy(first_policy)
    registry.register_dossier(third_party_dossier("bank-a"))
    snapshot = registry.build_snapshot(
        first_policy,
        snapshot_id="quarterly",
        sequence=1,
        entity_ids=("bank-a",),
        assembled_at=600,
    )
    registry.register_snapshot(snapshot, first_policy)

    second_policy = policy(version=2, registered_at=650, provider_threshold=3, critical_threshold=3)
    registry.register_policy(second_policy)
    assert registry.verify_snapshot(snapshot) == snapshot.evidence_digest
    with pytest.raises(GovernanceError, match="policy is not current"):
        registry.assert_snapshot_current(snapshot, first_policy)
    with pytest.raises(GovernanceError, match="policy is not current"):
        registry.build_snapshot(
            first_policy,
            snapshot_id="quarterly",
            sequence=2,
            entity_ids=("bank-a",),
            assembled_at=700,
        )


def test_snapshot_sequence_is_contiguous_and_exact_retry_is_idempotent() -> None:
    registry = PortfolioAssuranceRegistry()
    assurance_policy = policy()
    registry.register_policy(assurance_policy)
    registry.register_dossier(third_party_dossier("bank-a"))
    first = registry.build_snapshot(
        assurance_policy,
        snapshot_id="quarterly",
        sequence=1,
        entity_ids=("bank-a",),
        assembled_at=600,
    )
    digest1 = registry.register_snapshot(first, assurance_policy)
    assert registry.register_snapshot(first, assurance_policy) == digest1

    third = registry.build_snapshot(
        assurance_policy,
        snapshot_id="quarterly",
        sequence=3,
        entity_ids=("bank-a",),
        assembled_at=700,
    )
    with pytest.raises(GovernanceError, match="sequences must be contiguous"):
        registry.register_snapshot(third, assurance_policy)


def test_tampered_portfolio_exposure_fails_current_registration_reproduction() -> None:
    registry = PortfolioAssuranceRegistry()
    assurance_policy = policy(provider_threshold=2, critical_threshold=2)
    registry.register_policy(assurance_policy)
    registry.register_dossier(third_party_dossier("bank-a"))
    registry.register_dossier(third_party_dossier("bank-b"))
    snapshot = registry.build_snapshot(
        assurance_policy,
        snapshot_id="quarterly",
        sequence=1,
        entity_ids=("bank-a", "bank-b"),
        assembled_at=600,
    )
    exposure = replace(
        snapshot.provider_exposures[0],
        entity_concentration_threshold_reached=False,
    )
    tampered = replace(snapshot, provider_exposures=(exposure,))
    with pytest.raises(GovernanceError, match="provider exposures do not reproduce"):
        registry.register_snapshot(tampered, assurance_policy)


def test_v04_runtime_artifacts_validate_against_strict_schemas() -> None:
    registry = PortfolioAssuranceRegistry()
    assurance_policy = policy(provider_threshold=2, critical_threshold=2)
    registry.register_policy(assurance_policy)
    registry.register_dossier(third_party_dossier("bank-a"))
    registry.register_dossier(third_party_dossier("bank-b"))
    snapshot = registry.build_snapshot(
        assurance_policy,
        snapshot_id="quarterly",
        sequence=1,
        entity_ids=("bank-a", "bank-b"),
        assembled_at=600,
    )

    root = Path(__file__).resolve().parents[1]
    cases = (
        ("assurance-policy.schema.json", assurance_policy),
        ("domain-assurance-summary.schema.json", snapshot.positions[0].domain_summaries[0]),
        ("entity-provider-exposure.schema.json", snapshot.positions[0].provider_exposures[0]),
        ("entity-assurance-position.schema.json", snapshot.positions[0]),
        ("provider-portfolio-exposure.schema.json", snapshot.provider_exposures[0]),
        ("portfolio-assurance-snapshot.schema.json", snapshot),
    )
    for name, artifact in cases:
        schema = json.loads((root / "schemas" / name).read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator(schema).validate(json.loads(canonical_json(artifact)))

    assert verify_portfolio_snapshot(snapshot) == snapshot.evidence_digest
