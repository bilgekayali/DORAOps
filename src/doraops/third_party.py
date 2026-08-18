from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import re
from typing import Iterable

from .canonical import sha256_digest
from .inventory import (
    BusinessFunction,
    FunctionClassification,
    GovernanceError,
    InventoryRegistry,
    NodeKind,
    NodeRef,
    ThirdPartyService,
)


class ProviderDesignation(str, Enum):
    UNASSESSED = "unassessed"
    NOT_DESIGNATED_CRITICAL = "not_designated_critical"
    DESIGNATED_CRITICAL = "designated_critical"


class SubstitutabilityAssessment(str, Enum):
    NOT_ASSESSED = "not_assessed"
    EASY = "easy"
    MODERATE = "moderate"
    DIFFICULT = "difficult"


class ConcentrationAssessment(str, Enum):
    NOT_ASSESSED = "not_assessed"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RegisterAssessmentState(str, Enum):
    COMPLETE = "complete"
    WITH_GAPS = "with_gaps"


class ThirdPartyGapCode(str, Enum):
    PROVIDER_DESIGNATION_UNASSESSED = "provider_designation_unassessed"
    MISSING_DATA_LOCATION = "missing_data_location"
    MISSING_SERVICE_LOCATION = "missing_service_location"
    MISSING_CONTRACT_EVIDENCE = "missing_contract_evidence"
    MISSING_CONTROL_REQUIREMENT_EVIDENCE = "missing_control_requirement_evidence"
    MISSING_DEPENDENCY_OBSERVATION = "missing_dependency_observation"
    STALE_DEPENDENCY_OBSERVATION = "stale_dependency_observation"
    SUBSTITUTABILITY_NOT_ASSESSED = "substitutability_not_assessed"
    CONCENTRATION_NOT_ASSESSED = "concentration_not_assessed"
    MISSING_EXIT_PLAN = "missing_exit_plan"


def _text(name: str, value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise GovernanceError(f"{name} must be a non-empty string")
    return value.strip()


def _digest(name: str, value: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(ch not in "0123456789abcdef" for ch in value)
    ):
        raise GovernanceError(f"{name} must be a lowercase SHA-256 digest")
    return value


def _timestamp(name: str, value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise GovernanceError(f"{name} must be a non-negative integer timestamp")
    return value


def _country(value: str) -> str:
    country = _text("country_code", value).upper()
    if not re.fullmatch(r"[A-Z]{2}", country):
        raise GovernanceError("country_code must be ISO-like alpha-2")
    return country


def _unique_texts(name: str, values: Iterable[str], *, required: bool = False) -> tuple[str, ...]:
    normalized = tuple(sorted(_text(name, value) for value in values))
    if required and not normalized:
        raise GovernanceError(f"{name}s must not be empty")
    if len(normalized) != len(set(normalized)):
        raise GovernanceError(f"{name}s must be unique")
    return normalized


def _unique_digests(name: str, values: Iterable[str]) -> tuple[str, ...]:
    normalized = tuple(sorted(_digest(name, value) for value in values))
    if len(normalized) != len(set(normalized)):
        raise GovernanceError(f"{name}s must be unique")
    return normalized


@dataclass(frozen=True, slots=True)
class GeographicLocation:
    country_code: str
    region: str | None = None
    description: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "country_code", _country(self.country_code))
        if self.region is not None:
            object.__setattr__(self, "region", _text("region", self.region))
        if self.description is not None:
            object.__setattr__(self, "description", _text("description", self.description))


@dataclass(frozen=True, slots=True)
class ThirdPartyArrangement:
    entity_id: str
    arrangement_id: str
    contract_reference: str
    direct_provider_id: str
    direct_service_ids: tuple[str, ...]
    subcontracted_service_ids: tuple[str, ...]
    supported_function_ids: tuple[str, ...]
    critical_or_important_function_ids: tuple[str, ...]
    provider_designation: ProviderDesignation
    provider_designation_owner: str
    provider_designation_rationale: str
    inventory_snapshot_digest: str
    data_locations: tuple[GeographicLocation, ...]
    service_locations: tuple[GeographicLocation, ...]
    contract_evidence_digests: tuple[str, ...]
    control_requirement_evidence_digests: tuple[str, ...]
    effective_from: int
    effective_to: int | None = None

    def __post_init__(self) -> None:
        for name in (
            "entity_id",
            "arrangement_id",
            "contract_reference",
            "direct_provider_id",
            "provider_designation_owner",
            "provider_designation_rationale",
        ):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        object.__setattr__(
            self,
            "direct_service_ids",
            _unique_texts("direct_service_id", self.direct_service_ids, required=True),
        )
        object.__setattr__(
            self,
            "subcontracted_service_ids",
            _unique_texts("subcontracted_service_id", self.subcontracted_service_ids),
        )
        if set(self.direct_service_ids) & set(self.subcontracted_service_ids):
            raise GovernanceError("direct and subcontracted service ids must not overlap")
        object.__setattr__(
            self,
            "supported_function_ids",
            _unique_texts("supported_function_id", self.supported_function_ids, required=True),
        )
        object.__setattr__(
            self,
            "critical_or_important_function_ids",
            _unique_texts(
                "critical_or_important_function_id",
                self.critical_or_important_function_ids,
            ),
        )
        if not set(self.critical_or_important_function_ids).issubset(self.supported_function_ids):
            raise GovernanceError("critical_or_important_function_ids must be supported functions")
        _digest("inventory_snapshot_digest", self.inventory_snapshot_digest)
        object.__setattr__(
            self,
            "data_locations",
            tuple(sorted(self.data_locations, key=lambda item: (item.country_code, item.region or "", item.description or ""))),
        )
        object.__setattr__(
            self,
            "service_locations",
            tuple(sorted(self.service_locations, key=lambda item: (item.country_code, item.region or "", item.description or ""))),
        )
        if len(self.data_locations) != len(set(self.data_locations)):
            raise GovernanceError("data_locations must be unique")
        if len(self.service_locations) != len(set(self.service_locations)):
            raise GovernanceError("service_locations must be unique")
        object.__setattr__(
            self,
            "contract_evidence_digests",
            _unique_digests("contract_evidence_digest", self.contract_evidence_digests),
        )
        object.__setattr__(
            self,
            "control_requirement_evidence_digests",
            _unique_digests(
                "control_requirement_evidence_digest",
                self.control_requirement_evidence_digests,
            ),
        )
        _timestamp("effective_from", self.effective_from)
        if self.effective_to is not None:
            _timestamp("effective_to", self.effective_to)
            if self.effective_to < self.effective_from:
                raise GovernanceError("effective_to cannot precede effective_from")

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class DependencyObservation:
    entity_id: str
    arrangement_id: str
    arrangement_digest: str
    observation_id: str
    observed_at: int
    substitutability: SubstitutabilityAssessment
    concentration: ConcentrationAssessment
    rationale: str
    evidence_digest: str

    def __post_init__(self) -> None:
        for name in ("entity_id", "arrangement_id", "observation_id", "rationale"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        _digest("arrangement_digest", self.arrangement_digest)
        _timestamp("observed_at", self.observed_at)
        object.__setattr__(self, "evidence_digest", _digest("dependency evidence_digest", self.evidence_digest))

    @property
    def governance_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class ExitTransitionPlan:
    entity_id: str
    arrangement_id: str
    arrangement_digest: str
    exit_plan_id: str
    owner_id: str
    updated_at: int
    trigger_conditions: tuple[str, ...]
    transition_steps: tuple[str, ...]
    evidence_digests: tuple[str, ...]
    alternate_provider_reference: str | None = None

    def __post_init__(self) -> None:
        for name in ("entity_id", "arrangement_id", "exit_plan_id", "owner_id"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        _digest("arrangement_digest", self.arrangement_digest)
        _timestamp("updated_at", self.updated_at)
        object.__setattr__(
            self,
            "trigger_conditions",
            _unique_texts("trigger_condition", self.trigger_conditions, required=True),
        )
        object.__setattr__(
            self,
            "transition_steps",
            _unique_texts("transition_step", self.transition_steps, required=True),
        )
        object.__setattr__(
            self,
            "evidence_digests",
            _unique_digests("exit_plan_evidence_digest", self.evidence_digests),
        )
        if not self.evidence_digests:
            raise GovernanceError("exit plan requires at least one evidence digest")
        if self.alternate_provider_reference is not None:
            object.__setattr__(
                self,
                "alternate_provider_reference",
                _text("alternate_provider_reference", self.alternate_provider_reference),
            )

    @property
    def governance_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class ThirdPartyGovernancePolicy:
    entity_id: str
    policy_id: str
    version: str
    require_provider_designation_assessed: bool = True
    require_data_location: bool = True
    require_service_location: bool = True
    require_contract_evidence: bool = True
    require_control_requirement_evidence: bool = True
    require_dependency_observation: bool = True
    max_observation_age: int | None = None
    require_exit_plan_for_critical_functions: bool = True
    require_exit_plan_for_high_concentration: bool = True
    require_exit_plan_for_difficult_substitutability: bool = True

    def __post_init__(self) -> None:
        for name in ("entity_id", "policy_id", "version"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        if self.max_observation_age is not None:
            _timestamp("max_observation_age", self.max_observation_age)

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class ThirdPartyGap:
    arrangement_id: str
    code: ThirdPartyGapCode
    detail: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "arrangement_id", _text("arrangement_id", self.arrangement_id))
        object.__setattr__(self, "detail", _text("gap detail", self.detail))


@dataclass(frozen=True, slots=True)
class ThirdPartyRegisterRow:
    arrangement_id: str
    arrangement_digest: str
    direct_provider_id: str
    service_id: str
    direct_service: bool
    supply_chain_rank: int
    parent_service_id: str | None
    supported_function_ids: tuple[str, ...]
    critical_or_important_function_ids: tuple[str, ...]
    provider_designation: ProviderDesignation
    data_country_codes: tuple[str, ...]
    service_country_codes: tuple[str, ...]

    def __post_init__(self) -> None:
        for name in ("arrangement_id", "direct_provider_id", "service_id"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        _digest("arrangement_digest", self.arrangement_digest)
        if (
            isinstance(self.supply_chain_rank, bool)
            or not isinstance(self.supply_chain_rank, int)
            or self.supply_chain_rank < 1
        ):
            raise GovernanceError("supply_chain_rank must be a positive integer")
        if self.parent_service_id is not None:
            object.__setattr__(self, "parent_service_id", _text("parent_service_id", self.parent_service_id))


@dataclass(frozen=True, slots=True)
class ThirdPartyRegisterSnapshot:
    entity_id: str
    inventory_snapshot_digest: str
    policy_digest: str
    as_of: int
    mapping_profile: str
    arrangement_digests: tuple[str, ...]
    observation_digests: tuple[str, ...]
    exit_plan_digests: tuple[str, ...]
    rows: tuple[ThirdPartyRegisterRow, ...]
    gaps: tuple[ThirdPartyGap, ...]
    state: RegisterAssessmentState

    def __post_init__(self) -> None:
        object.__setattr__(self, "entity_id", _text("entity_id", self.entity_id))
        _digest("inventory_snapshot_digest", self.inventory_snapshot_digest)
        _digest("policy_digest", self.policy_digest)
        _timestamp("as_of", self.as_of)
        object.__setattr__(self, "mapping_profile", _text("mapping_profile", self.mapping_profile))
        for name, values in (
            ("arrangement_digest", self.arrangement_digests),
            ("observation_digest", self.observation_digests),
            ("exit_plan_digest", self.exit_plan_digests),
        ):
            for value in values:
                _digest(name, value)
            if len(values) != len(set(values)):
                raise GovernanceError(f"{name}s must be unique")

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


class ThirdPartyRegister:
    """Immutable reference register bound to the governed inventory snapshot."""

    def __init__(self, inventory: InventoryRegistry) -> None:
        self.inventory = inventory
        self._arrangements: dict[tuple[str, str], ThirdPartyArrangement] = {}
        self._observations: dict[tuple[str, str, str], DependencyObservation] = {}
        self._exit_plans: dict[tuple[str, str, str], ExitTransitionPlan] = {}

    def register_arrangement(self, arrangement: ThirdPartyArrangement) -> str:
        self._validate_arrangement(arrangement)
        key = (arrangement.entity_id, arrangement.arrangement_id)
        existing = self._arrangements.get(key)
        if existing is not None and existing.evidence_digest != arrangement.evidence_digest:
            raise GovernanceError("arrangement_id is already registered with different content")
        self._arrangements.setdefault(key, arrangement)
        return arrangement.evidence_digest

    def register_observation(self, observation: DependencyObservation) -> str:
        arrangement = self._require_arrangement(observation.entity_id, observation.arrangement_id)
        if observation.arrangement_digest != arrangement.evidence_digest:
            raise GovernanceError("dependency observation is bound to a different arrangement snapshot")
        if observation.observed_at < arrangement.effective_from:
            raise GovernanceError("dependency observation cannot predate arrangement effectiveness")
        key = (observation.entity_id, observation.arrangement_id, observation.observation_id)
        existing = self._observations.get(key)
        if existing is not None and existing.governance_digest != observation.governance_digest:
            raise GovernanceError("observation_id is already registered with different content")
        self._observations.setdefault(key, observation)
        return observation.governance_digest

    def register_exit_plan(self, plan: ExitTransitionPlan) -> str:
        arrangement = self._require_arrangement(plan.entity_id, plan.arrangement_id)
        if plan.arrangement_digest != arrangement.evidence_digest:
            raise GovernanceError("exit plan is bound to a different arrangement snapshot")
        if plan.updated_at < arrangement.effective_from:
            raise GovernanceError("exit plan cannot predate arrangement effectiveness")
        key = (plan.entity_id, plan.arrangement_id, plan.exit_plan_id)
        existing = self._exit_plans.get(key)
        if existing is not None and existing.governance_digest != plan.governance_digest:
            raise GovernanceError("exit_plan_id is already registered with different content")
        self._exit_plans.setdefault(key, plan)
        return plan.governance_digest

    def arrangements(self, entity_id: str) -> tuple[ThirdPartyArrangement, ...]:
        return tuple(
            sorted(
                (
                    item
                    for (scope, _), item in self._arrangements.items()
                    if scope == entity_id
                ),
                key=lambda item: item.arrangement_id,
            )
        )

    def latest_observation(self, arrangement: ThirdPartyArrangement) -> DependencyObservation | None:
        candidates = [
            item
            for (scope, arrangement_id, _), item in self._observations.items()
            if scope == arrangement.entity_id and arrangement_id == arrangement.arrangement_id
        ]
        if not candidates:
            return None
        latest_at = max(item.observed_at for item in candidates)
        latest = [item for item in candidates if item.observed_at == latest_at]
        if len(latest) != 1:
            raise GovernanceError("conflicting latest dependency observations fail closed")
        return latest[0]

    def latest_exit_plan(self, arrangement: ThirdPartyArrangement) -> ExitTransitionPlan | None:
        candidates = [
            item
            for (scope, arrangement_id, _), item in self._exit_plans.items()
            if scope == arrangement.entity_id and arrangement_id == arrangement.arrangement_id
        ]
        if not candidates:
            return None
        latest_at = max(item.updated_at for item in candidates)
        latest = [item for item in candidates if item.updated_at == latest_at]
        if len(latest) != 1:
            raise GovernanceError("conflicting latest exit plans fail closed")
        return latest[0]

    def assert_current(self, arrangement: ThirdPartyArrangement) -> None:
        self._validate_arrangement(arrangement)

    def _require_arrangement(self, entity_id: str, arrangement_id: str) -> ThirdPartyArrangement:
        try:
            return self._arrangements[(entity_id, arrangement_id)]
        except KeyError as exc:
            raise GovernanceError("unknown third-party arrangement") from exc

    def _service(self, entity_id: str, service_id: str) -> ThirdPartyService:
        node = self.inventory.node(NodeRef(entity_id, NodeKind.THIRD_PARTY_SERVICE, service_id))
        if not isinstance(node, ThirdPartyService):
            raise GovernanceError("third-party service reference did not resolve to a service")
        return node

    def _function(self, entity_id: str, function_id: str) -> BusinessFunction:
        node = self.inventory.node(NodeRef(entity_id, NodeKind.BUSINESS_FUNCTION, function_id))
        if not isinstance(node, BusinessFunction):
            raise GovernanceError("supported function reference did not resolve to a business function")
        return node

    def _validate_arrangement(self, arrangement: ThirdPartyArrangement) -> None:
        current_inventory = self.inventory.snapshot_digest(arrangement.entity_id)
        if arrangement.inventory_snapshot_digest != current_inventory:
            raise GovernanceError("third-party arrangement is stale for current inventory snapshot")

        direct_services = tuple(
            self._service(arrangement.entity_id, service_id)
            for service_id in arrangement.direct_service_ids
        )
        for service in direct_services:
            if not service.direct_provider or service.supply_chain_rank != 1:
                raise GovernanceError("arrangement direct service must be a rank-1 direct provider service")
            if service.provider_id != arrangement.direct_provider_id:
                raise GovernanceError("arrangement direct service references a different provider")

        direct_ids = set(arrangement.direct_service_ids)
        for service_id in arrangement.subcontracted_service_ids:
            service = self._service(arrangement.entity_id, service_id)
            if service.direct_provider or service.supply_chain_rank <= 1:
                raise GovernanceError("arrangement subcontracted service must have supply-chain rank > 1")
            current = service
            visited: set[str] = set()
            while not current.direct_provider:
                if current.third_party_service_id in visited:
                    raise GovernanceError("third-party supply chain contains a cycle")
                visited.add(current.third_party_service_id)
                parent_id = current.parent_third_party_service_id
                if parent_id is None:
                    raise GovernanceError("subcontracted service is missing its parent service")
                current = self._service(arrangement.entity_id, parent_id)
            if current.third_party_service_id not in direct_ids:
                raise GovernanceError("subcontracted service does not descend from an arrangement direct service")

        functions = tuple(
            self._function(arrangement.entity_id, function_id)
            for function_id in arrangement.supported_function_ids
        )
        expected_critical = tuple(
            sorted(
                item.function_id
                for item in functions
                if item.classification is FunctionClassification.CRITICAL_OR_IMPORTANT
            )
        )
        if arrangement.critical_or_important_function_ids != expected_critical:
            raise GovernanceError(
                "explicit critical_or_important_function_ids do not match authoritative function classifications"
            )


def build_third_party_arrangement(
    inventory: InventoryRegistry,
    *,
    entity_id: str,
    arrangement_id: str,
    contract_reference: str,
    direct_provider_id: str,
    direct_service_ids: Iterable[str],
    subcontracted_service_ids: Iterable[str],
    supported_function_ids: Iterable[str],
    critical_or_important_function_ids: Iterable[str],
    provider_designation: ProviderDesignation,
    provider_designation_owner: str,
    provider_designation_rationale: str,
    data_locations: Iterable[GeographicLocation] = (),
    service_locations: Iterable[GeographicLocation] = (),
    contract_evidence_digests: Iterable[str] = (),
    control_requirement_evidence_digests: Iterable[str] = (),
    effective_from: int,
    effective_to: int | None = None,
) -> ThirdPartyArrangement:
    return ThirdPartyArrangement(
        entity_id=entity_id,
        arrangement_id=arrangement_id,
        contract_reference=contract_reference,
        direct_provider_id=direct_provider_id,
        direct_service_ids=tuple(direct_service_ids),
        subcontracted_service_ids=tuple(subcontracted_service_ids),
        supported_function_ids=tuple(supported_function_ids),
        critical_or_important_function_ids=tuple(critical_or_important_function_ids),
        provider_designation=provider_designation,
        provider_designation_owner=provider_designation_owner,
        provider_designation_rationale=provider_designation_rationale,
        inventory_snapshot_digest=inventory.snapshot_digest(entity_id),
        data_locations=tuple(data_locations),
        service_locations=tuple(service_locations),
        contract_evidence_digests=tuple(contract_evidence_digests),
        control_requirement_evidence_digests=tuple(control_requirement_evidence_digests),
        effective_from=effective_from,
        effective_to=effective_to,
    )


def _rows(register: ThirdPartyRegister, arrangement: ThirdPartyArrangement) -> tuple[ThirdPartyRegisterRow, ...]:
    rows: list[ThirdPartyRegisterRow] = []
    for service_id in arrangement.direct_service_ids + arrangement.subcontracted_service_ids:
        service = register._service(arrangement.entity_id, service_id)
        rows.append(
            ThirdPartyRegisterRow(
                arrangement_id=arrangement.arrangement_id,
                arrangement_digest=arrangement.evidence_digest,
                direct_provider_id=arrangement.direct_provider_id,
                service_id=service.third_party_service_id,
                direct_service=service.direct_provider,
                supply_chain_rank=service.supply_chain_rank,
                parent_service_id=service.parent_third_party_service_id,
                supported_function_ids=arrangement.supported_function_ids,
                critical_or_important_function_ids=arrangement.critical_or_important_function_ids,
                provider_designation=arrangement.provider_designation,
                data_country_codes=tuple(location.country_code for location in arrangement.data_locations),
                service_country_codes=tuple(location.country_code for location in arrangement.service_locations),
            )
        )
    return tuple(sorted(rows, key=lambda item: (item.arrangement_id, item.supply_chain_rank, item.service_id)))


def build_register_snapshot(
    register: ThirdPartyRegister,
    policy: ThirdPartyGovernancePolicy,
    *,
    as_of: int,
) -> ThirdPartyRegisterSnapshot:
    _timestamp("as_of", as_of)
    arrangements = register.arrangements(policy.entity_id)
    current_inventory = register.inventory.snapshot_digest(policy.entity_id)

    active_arrangements: list[ThirdPartyArrangement] = []
    rows: list[ThirdPartyRegisterRow] = []
    gaps: list[ThirdPartyGap] = []
    observation_digests: list[str] = []
    exit_plan_digests: list[str] = []

    for arrangement in arrangements:
        register.assert_current(arrangement)
        if arrangement.effective_from > as_of:
            continue
        if arrangement.effective_to is not None and arrangement.effective_to < as_of:
            continue
        active_arrangements.append(arrangement)
        rows.extend(_rows(register, arrangement))
        observation = register.latest_observation(arrangement)
        exit_plan = register.latest_exit_plan(arrangement)

        def gap(code: ThirdPartyGapCode, detail: str) -> None:
            gaps.append(ThirdPartyGap(arrangement.arrangement_id, code, detail))

        if (
            policy.require_provider_designation_assessed
            and arrangement.provider_designation is ProviderDesignation.UNASSESSED
        ):
            gap(
                ThirdPartyGapCode.PROVIDER_DESIGNATION_UNASSESSED,
                "provider designation remains explicitly unassessed",
            )
        if policy.require_data_location and not arrangement.data_locations:
            gap(ThirdPartyGapCode.MISSING_DATA_LOCATION, "no governed data location evidence")
        if policy.require_service_location and not arrangement.service_locations:
            gap(ThirdPartyGapCode.MISSING_SERVICE_LOCATION, "no governed service location evidence")
        if policy.require_contract_evidence and not arrangement.contract_evidence_digests:
            gap(ThirdPartyGapCode.MISSING_CONTRACT_EVIDENCE, "no contract evidence digest")
        if policy.require_control_requirement_evidence and not arrangement.control_requirement_evidence_digests:
            gap(
                ThirdPartyGapCode.MISSING_CONTROL_REQUIREMENT_EVIDENCE,
                "no contract/control requirement evidence digest",
            )

        if observation is None:
            if policy.require_dependency_observation:
                gap(
                    ThirdPartyGapCode.MISSING_DEPENDENCY_OBSERVATION,
                    "no substitutability/concentration observation",
                )
        else:
            observation_digests.append(observation.governance_digest)
            if observation.observed_at > as_of:
                raise GovernanceError("dependency observation cannot be from the future")
            if (
                policy.max_observation_age is not None
                and as_of - observation.observed_at > policy.max_observation_age
            ):
                gap(
                    ThirdPartyGapCode.STALE_DEPENDENCY_OBSERVATION,
                    "latest dependency observation exceeds policy freshness",
                )
            if observation.substitutability is SubstitutabilityAssessment.NOT_ASSESSED:
                gap(
                    ThirdPartyGapCode.SUBSTITUTABILITY_NOT_ASSESSED,
                    "substitutability remains explicitly unassessed",
                )
            if observation.concentration is ConcentrationAssessment.NOT_ASSESSED:
                gap(
                    ThirdPartyGapCode.CONCENTRATION_NOT_ASSESSED,
                    "concentration remains explicitly unassessed",
                )

        exit_required = (
            policy.require_exit_plan_for_critical_functions
            and bool(arrangement.critical_or_important_function_ids)
        )
        if observation is not None:
            if (
                policy.require_exit_plan_for_high_concentration
                and observation.concentration in {ConcentrationAssessment.HIGH, ConcentrationAssessment.CRITICAL}
            ):
                exit_required = True
            if (
                policy.require_exit_plan_for_difficult_substitutability
                and observation.substitutability is SubstitutabilityAssessment.DIFFICULT
            ):
                exit_required = True

        if exit_plan is None:
            if exit_required:
                gap(
                    ThirdPartyGapCode.MISSING_EXIT_PLAN,
                    "institution policy requires exit/transition evidence for this arrangement",
                )
        else:
            if exit_plan.updated_at > as_of:
                raise GovernanceError("exit plan cannot be from the future")
            exit_plan_digests.append(exit_plan.governance_digest)

    gaps_tuple = tuple(sorted(gaps, key=lambda item: (item.arrangement_id, item.code.value, item.detail)))
    rows_tuple = tuple(sorted(rows, key=lambda item: (item.arrangement_id, item.supply_chain_rank, item.service_id)))
    state = RegisterAssessmentState.WITH_GAPS if gaps_tuple else RegisterAssessmentState.COMPLETE

    return ThirdPartyRegisterSnapshot(
        entity_id=policy.entity_id,
        inventory_snapshot_digest=current_inventory,
        policy_digest=policy.evidence_digest,
        as_of=as_of,
        mapping_profile="EU-2024-2956-support-v1",
        arrangement_digests=tuple(item.evidence_digest for item in active_arrangements),
        observation_digests=tuple(sorted(observation_digests)),
        exit_plan_digests=tuple(sorted(exit_plan_digests)),
        rows=rows_tuple,
        gaps=gaps_tuple,
        state=state,
    )
