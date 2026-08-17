from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import re
from typing import Any

from .canonical import sha256_digest


class GovernanceError(ValueError):
    """Raised when a DORAOps governance contract fails closed."""


class FunctionClassification(str, Enum):
    STANDARD = "standard"
    CRITICAL_OR_IMPORTANT = "critical_or_important"


class NodeKind(str, Enum):
    BUSINESS_FUNCTION = "business_function"
    BUSINESS_PROCESS = "business_process"
    ICT_SERVICE = "ict_service"
    INFORMATION_ASSET = "information_asset"
    ICT_ASSET = "ict_asset"
    THIRD_PARTY_SERVICE = "third_party_service"


class DependencyRelationship(str, Enum):
    SUPPORTED_BY = "supported_by"
    DEPENDS_ON = "depends_on"
    PROCESSED_BY = "processed_by"
    HOSTED_ON = "hosted_on"
    PROVIDED_BY = "provided_by"


def _text(name: str, value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise GovernanceError(f"{name} must be a non-empty string")
    return value.strip()


def _optional_lei(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = value.strip().upper()
    if not re.fullmatch(r"[A-Z0-9]{20}", cleaned):
        raise GovernanceError("lei must be a 20-character alphanumeric identifier")
    return cleaned


@dataclass(frozen=True, slots=True)
class FinancialEntity:
    entity_id: str
    legal_name: str
    country_code: str
    lei: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "entity_id", _text("entity_id", self.entity_id))
        object.__setattr__(self, "legal_name", _text("legal_name", self.legal_name))
        country = _text("country_code", self.country_code).upper()
        if not re.fullmatch(r"[A-Z]{2}", country):
            raise GovernanceError("country_code must be ISO-like alpha-2")
        object.__setattr__(self, "country_code", country)
        object.__setattr__(self, "lei", _optional_lei(self.lei))

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class BusinessFunction:
    entity_id: str
    function_id: str
    name: str
    classification: FunctionClassification
    decision_owner: str
    classification_rationale: str

    def __post_init__(self) -> None:
        for name in ("entity_id", "function_id", "name", "decision_owner", "classification_rationale"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class BusinessProcess:
    entity_id: str
    process_id: str
    name: str
    owner_id: str

    def __post_init__(self) -> None:
        for name in ("entity_id", "process_id", "name", "owner_id"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class ICTService:
    entity_id: str
    service_id: str
    name: str
    owner_id: str
    service_type: str

    def __post_init__(self) -> None:
        for name in ("entity_id", "service_id", "name", "owner_id", "service_type"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class InformationAsset:
    entity_id: str
    asset_id: str
    name: str
    owner_id: str
    classification: str

    def __post_init__(self) -> None:
        for name in ("entity_id", "asset_id", "name", "owner_id", "classification"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class ICTAsset:
    entity_id: str
    asset_id: str
    name: str
    owner_id: str
    asset_type: str
    legacy: bool = False

    def __post_init__(self) -> None:
        for name in ("entity_id", "asset_id", "name", "owner_id", "asset_type"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class ThirdPartyProvider:
    entity_id: str
    provider_id: str
    legal_name: str
    identifier_type: str
    identifier_value: str

    def __post_init__(self) -> None:
        for name in ("entity_id", "provider_id", "legal_name", "identifier_type", "identifier_value"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class ThirdPartyService:
    entity_id: str
    third_party_service_id: str
    provider_id: str
    name: str
    service_type: str
    direct_provider: bool
    supply_chain_rank: int
    parent_third_party_service_id: str | None = None

    def __post_init__(self) -> None:
        for name in ("entity_id", "third_party_service_id", "provider_id", "name", "service_type"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        if self.supply_chain_rank < 1:
            raise GovernanceError("supply_chain_rank must be >= 1")
        if self.direct_provider:
            if self.supply_chain_rank != 1:
                raise GovernanceError("direct ICT third-party service must have supply_chain_rank 1")
            if self.parent_third_party_service_id is not None:
                raise GovernanceError("direct ICT third-party service cannot have a parent service")
        else:
            if self.supply_chain_rank <= 1:
                raise GovernanceError("subcontracted ICT service must have supply_chain_rank > 1")
            if self.parent_third_party_service_id is None:
                raise GovernanceError("subcontracted ICT service requires parent_third_party_service_id")
            object.__setattr__(
                self,
                "parent_third_party_service_id",
                _text("parent_third_party_service_id", self.parent_third_party_service_id),
            )

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class NodeRef:
    entity_id: str
    kind: NodeKind
    node_id: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "entity_id", _text("entity_id", self.entity_id))
        object.__setattr__(self, "node_id", _text("node_id", self.node_id))


@dataclass(frozen=True, slots=True)
class DependencyEdge:
    entity_id: str
    edge_id: str
    source: NodeRef
    target: NodeRef
    relationship: DependencyRelationship
    rationale: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "entity_id", _text("entity_id", self.entity_id))
        object.__setattr__(self, "edge_id", _text("edge_id", self.edge_id))
        object.__setattr__(self, "rationale", _text("rationale", self.rationale))
        if self.source.entity_id != self.entity_id or self.target.entity_id != self.entity_id:
            raise GovernanceError("dependency edge endpoints must be in the same entity scope")
        if self.source == self.target:
            raise GovernanceError("dependency edge cannot self-reference the same node")

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


_NODE_ID_FIELDS: dict[NodeKind, str] = {
    NodeKind.BUSINESS_FUNCTION: "function_id",
    NodeKind.BUSINESS_PROCESS: "process_id",
    NodeKind.ICT_SERVICE: "service_id",
    NodeKind.INFORMATION_ASSET: "asset_id",
    NodeKind.ICT_ASSET: "asset_id",
    NodeKind.THIRD_PARTY_SERVICE: "third_party_service_id",
}

_NODE_TYPES: dict[NodeKind, type[Any]] = {
    NodeKind.BUSINESS_FUNCTION: BusinessFunction,
    NodeKind.BUSINESS_PROCESS: BusinessProcess,
    NodeKind.ICT_SERVICE: ICTService,
    NodeKind.INFORMATION_ASSET: InformationAsset,
    NodeKind.ICT_ASSET: ICTAsset,
    NodeKind.THIRD_PARTY_SERVICE: ThirdPartyService,
}


class InventoryRegistry:
    """Reference in-memory registry with immutable, entity-scoped graph semantics."""

    def __init__(self) -> None:
        self._entities: dict[str, FinancialEntity] = {}
        self._nodes: dict[tuple[str, NodeKind, str], Any] = {}
        self._providers: dict[tuple[str, str], ThirdPartyProvider] = {}
        self._edges: dict[tuple[str, str], DependencyEdge] = {}

    def register_entity(self, entity: FinancialEntity) -> str:
        existing = self._entities.get(entity.entity_id)
        if existing is not None and existing.evidence_digest != entity.evidence_digest:
            raise GovernanceError("entity_id is already registered with different content")
        self._entities.setdefault(entity.entity_id, entity)
        return entity.evidence_digest

    def register_provider(self, provider: ThirdPartyProvider) -> str:
        self._require_entity(provider.entity_id)
        key = (provider.entity_id, provider.provider_id)
        existing = self._providers.get(key)
        if existing is not None and existing.evidence_digest != provider.evidence_digest:
            raise GovernanceError("provider_id is already registered with different content")
        self._providers.setdefault(key, provider)
        return provider.evidence_digest

    def register_node(self, node: Any) -> str:
        kind = self._kind_for(node)
        self._require_entity(node.entity_id)
        node_id = getattr(node, _NODE_ID_FIELDS[kind])

        if isinstance(node, ThirdPartyService):
            if (node.entity_id, node.provider_id) not in self._providers:
                raise GovernanceError("third-party service references an unknown provider")
            if not node.direct_provider:
                parent_key = (
                    node.entity_id,
                    NodeKind.THIRD_PARTY_SERVICE,
                    node.parent_third_party_service_id,
                )
                parent = self._nodes.get(parent_key)
                if parent is None:
                    raise GovernanceError("subcontracted ICT service references an unknown parent service")
                if not isinstance(parent, ThirdPartyService):
                    raise GovernanceError("third-party parent reference is not an ICT third-party service")
                if parent.supply_chain_rank >= node.supply_chain_rank:
                    raise GovernanceError("subcontractor supply-chain rank must be greater than parent rank")

        key = (node.entity_id, kind, node_id)
        existing = self._nodes.get(key)
        if existing is not None and sha256_digest(existing) != sha256_digest(node):
            raise GovernanceError("node identity is already registered with different content")
        self._nodes.setdefault(key, node)
        return sha256_digest(node)

    def register_edge(self, edge: DependencyEdge) -> str:
        self._require_entity(edge.entity_id)
        self._require_node(edge.source)
        self._require_node(edge.target)
        key = (edge.entity_id, edge.edge_id)
        existing = self._edges.get(key)
        if existing is not None and existing.evidence_digest != edge.evidence_digest:
            raise GovernanceError("edge_id is already registered with different content")
        self._edges.setdefault(key, edge)
        return edge.evidence_digest

    def node(self, ref: NodeRef) -> Any:
        return self._require_node(ref)

    def snapshot_digest(self, entity_id: str) -> str:
        self._require_entity(entity_id)
        nodes = sorted(
            sha256_digest(node)
            for (scope, _, _), node in self._nodes.items()
            if scope == entity_id
        )
        providers = sorted(
            provider.evidence_digest
            for (scope, _), provider in self._providers.items()
            if scope == entity_id
        )
        edges = sorted(
            edge.evidence_digest
            for (scope, _), edge in self._edges.items()
            if scope == entity_id
        )
        return sha256_digest(
            {
                "entity": self._entities[entity_id].evidence_digest,
                "nodes": nodes,
                "providers": providers,
                "edges": edges,
            }
        )

    def _require_entity(self, entity_id: str) -> FinancialEntity:
        try:
            return self._entities[entity_id]
        except KeyError as exc:
            raise GovernanceError("unknown financial entity") from exc

    def _require_node(self, ref: NodeRef) -> Any:
        try:
            return self._nodes[(ref.entity_id, ref.kind, ref.node_id)]
        except KeyError as exc:
            raise GovernanceError("dependency references an unknown inventory node") from exc

    @staticmethod
    def _kind_for(node: Any) -> NodeKind:
        for kind, node_type in _NODE_TYPES.items():
            if isinstance(node, node_type):
                return kind
        raise GovernanceError("unsupported inventory node type")
