import pytest

from doraops import (
    BusinessFunction,
    BusinessProcess,
    DependencyEdge,
    DependencyRelationship,
    FinancialEntity,
    FunctionClassification,
    GovernanceError,
    ICTAsset,
    ICTService,
    InformationAsset,
    InventoryRegistry,
    NodeKind,
    NodeRef,
    ThirdPartyProvider,
    ThirdPartyService,
    canonical_json,
)


def entity(entity_id: str = "bank-a") -> FinancialEntity:
    return FinancialEntity(
        entity_id=entity_id,
        legal_name=f"{entity_id} Financial Entity",
        country_code="TR",
    )


def critical_function() -> BusinessFunction:
    return BusinessFunction(
        entity_id="bank-a",
        function_id="payments",
        name="Payment Processing",
        classification=FunctionClassification.CRITICAL_OR_IMPORTANT,
        decision_owner="operational-risk",
        classification_rationale="Material customer and settlement impact if disrupted",
    )


def direct_provider_service() -> ThirdPartyService:
    return ThirdPartyService(
        entity_id="bank-a",
        third_party_service_id="cloud-primary",
        provider_id="cloud-provider",
        name="Primary Cloud Hosting",
        service_type="cloud_infrastructure",
        direct_provider=True,
        supply_chain_rank=1,
    )


def build_registry() -> InventoryRegistry:
    registry = InventoryRegistry()
    registry.register_entity(entity())
    registry.register_provider(
        ThirdPartyProvider(
            entity_id="bank-a",
            provider_id="cloud-provider",
            legal_name="Cloud Provider Ltd",
            identifier_type="internal_reference",
            identifier_value="CP-001",
        )
    )
    registry.register_node(critical_function())
    registry.register_node(
        BusinessProcess(
            entity_id="bank-a",
            process_id="payment-processing",
            name="Payment Processing Process",
            owner_id="payments-ops",
        )
    )
    registry.register_node(
        ICTService(
            entity_id="bank-a",
            service_id="payments-api",
            name="Payments API",
            owner_id="payments-platform",
            service_type="application_service",
        )
    )
    registry.register_node(
        InformationAsset(
            entity_id="bank-a",
            asset_id="payment-ledger-data",
            name="Payment Ledger Data",
            owner_id="data-owner",
            classification="confidential",
        )
    )
    registry.register_node(
        ICTAsset(
            entity_id="bank-a",
            asset_id="payments-cluster",
            name="Payments Cluster",
            owner_id="platform-ops",
            asset_type="compute_cluster",
        )
    )
    registry.register_node(direct_provider_service())
    return registry


def test_canonical_json_is_key_order_independent() -> None:
    assert canonical_json({"b": 2, "a": 1}) == canonical_json({"a": 1, "b": 2})


def test_function_classification_requires_explicit_owner_and_rationale() -> None:
    with pytest.raises(GovernanceError, match="classification_rationale"):
        BusinessFunction(
            entity_id="bank-a",
            function_id="payments",
            name="Payment Processing",
            classification=FunctionClassification.CRITICAL_OR_IMPORTANT,
            decision_owner="operational-risk",
            classification_rationale="",
        )


def test_direct_provider_service_must_have_rank_one() -> None:
    with pytest.raises(GovernanceError, match="rank 1"):
        ThirdPartyService(
            entity_id="bank-a",
            third_party_service_id="bad-direct",
            provider_id="cloud-provider",
            name="Bad Direct Service",
            service_type="cloud",
            direct_provider=True,
            supply_chain_rank=2,
        )


def test_subcontractor_requires_parent_and_rank_above_one() -> None:
    with pytest.raises(GovernanceError, match="requires parent"):
        ThirdPartyService(
            entity_id="bank-a",
            third_party_service_id="subcontractor",
            provider_id="cloud-provider",
            name="Subcontracted Service",
            service_type="hosting",
            direct_provider=False,
            supply_chain_rank=2,
        )


def test_third_party_service_requires_registered_provider() -> None:
    registry = InventoryRegistry()
    registry.register_entity(entity())
    with pytest.raises(GovernanceError, match="unknown provider"):
        registry.register_node(direct_provider_service())


def test_subcontractor_requires_known_parent_with_lower_rank() -> None:
    registry = build_registry()
    registry.register_provider(
        ThirdPartyProvider(
            entity_id="bank-a",
            provider_id="sub-provider",
            legal_name="Sub Provider Ltd",
            identifier_type="internal_reference",
            identifier_value="SP-001",
        )
    )
    child = ThirdPartyService(
        entity_id="bank-a",
        third_party_service_id="cloud-subservice",
        provider_id="sub-provider",
        name="Subcontracted Storage",
        service_type="storage",
        direct_provider=False,
        supply_chain_rank=2,
        parent_third_party_service_id="cloud-primary",
    )
    registry.register_node(child)
    assert registry.node(
        NodeRef("bank-a", NodeKind.THIRD_PARTY_SERVICE, "cloud-subservice")
    ) == child


def test_dangling_dependency_edge_fails_closed() -> None:
    registry = build_registry()
    edge = DependencyEdge(
        entity_id="bank-a",
        edge_id="payments-to-missing",
        source=NodeRef("bank-a", NodeKind.BUSINESS_FUNCTION, "payments"),
        target=NodeRef("bank-a", NodeKind.ICT_SERVICE, "missing-service"),
        relationship=DependencyRelationship.SUPPORTED_BY,
        rationale="Function depends on service",
    )
    with pytest.raises(GovernanceError, match="unknown inventory node"):
        registry.register_edge(edge)


def test_cross_entity_dependency_is_rejected_before_registration() -> None:
    with pytest.raises(GovernanceError, match="same entity scope"):
        DependencyEdge(
            entity_id="bank-a",
            edge_id="cross-entity",
            source=NodeRef("bank-a", NodeKind.BUSINESS_FUNCTION, "payments"),
            target=NodeRef("bank-b", NodeKind.ICT_SERVICE, "payments-api"),
            relationship=DependencyRelationship.DEPENDS_ON,
            rationale="Invalid cross-entity dependency",
        )


def test_conflicting_node_identity_cannot_be_overwritten() -> None:
    registry = build_registry()
    conflicting = ICTService(
        entity_id="bank-a",
        service_id="payments-api",
        name="Changed Name",
        owner_id="payments-platform",
        service_type="application_service",
    )
    with pytest.raises(GovernanceError, match="different content"):
        registry.register_node(conflicting)


def test_dependency_graph_registers_exact_relationships() -> None:
    registry = build_registry()
    edges = (
        DependencyEdge(
            entity_id="bank-a",
            edge_id="function-process",
            source=NodeRef("bank-a", NodeKind.BUSINESS_FUNCTION, "payments"),
            target=NodeRef("bank-a", NodeKind.BUSINESS_PROCESS, "payment-processing"),
            relationship=DependencyRelationship.SUPPORTED_BY,
            rationale="Critical function is delivered through this process",
        ),
        DependencyEdge(
            entity_id="bank-a",
            edge_id="process-service",
            source=NodeRef("bank-a", NodeKind.BUSINESS_PROCESS, "payment-processing"),
            target=NodeRef("bank-a", NodeKind.ICT_SERVICE, "payments-api"),
            relationship=DependencyRelationship.DEPENDS_ON,
            rationale="Payment process depends on Payments API",
        ),
        DependencyEdge(
            entity_id="bank-a",
            edge_id="service-provider",
            source=NodeRef("bank-a", NodeKind.ICT_SERVICE, "payments-api"),
            target=NodeRef("bank-a", NodeKind.THIRD_PARTY_SERVICE, "cloud-primary"),
            relationship=DependencyRelationship.PROVIDED_BY,
            rationale="Payments API is hosted through direct cloud service",
        ),
    )
    for edge in edges:
        registry.register_edge(edge)
    assert len(registry.snapshot_digest("bank-a")) == 64


def test_snapshot_digest_is_registration_order_independent() -> None:
    first = InventoryRegistry()
    second = InventoryRegistry()
    bank = entity()
    first.register_entity(bank)
    second.register_entity(bank)

    nodes = (
        critical_function(),
        BusinessProcess("bank-a", "p1", "Process", "owner"),
        ICTService("bank-a", "s1", "Service", "owner", "application"),
    )
    for node in nodes:
        first.register_node(node)
    for node in reversed(nodes):
        second.register_node(node)

    assert first.snapshot_digest("bank-a") == second.snapshot_digest("bank-a")
