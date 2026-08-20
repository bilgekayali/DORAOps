from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import json
from typing import Any, Iterable

from .canonical import canonical_json, sha256_digest
from .dossier_verify_reporting import verify_dossier_document
from .inventory import GovernanceError


KNOWN_ASSURANCE_DOMAINS = (
    "ict_risk",
    "incident",
    "incident_reporting",
    "resilience_test",
    "continuity",
    "third_party",
)


class AssuranceState(str, Enum):
    HEALTHY = "healthy"
    ATTENTION = "attention"
    INCOMPLETE = "incomplete"
    BREACHED = "breached"
    REVALIDATION_REQUIRED = "revalidation_required"


_STATE_RANK = {
    AssuranceState.HEALTHY: 0,
    AssuranceState.ATTENTION: 1,
    AssuranceState.INCOMPLETE: 2,
    AssuranceState.BREACHED: 3,
    AssuranceState.REVALIDATION_REQUIRED: 4,
}


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


def _positive_int(name: str, value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise GovernanceError(f"{name} must be a positive integer")
    return value


def _sorted_unique_texts(name: str, values: Iterable[str], *, required: bool = False) -> tuple[str, ...]:
    result = tuple(sorted(_text(name, value) for value in values))
    if required and not result:
        raise GovernanceError(f"{name}s must not be empty")
    if len(result) != len(set(result)):
        raise GovernanceError(f"{name}s must be unique")
    return result


def _sorted_unique_digests(name: str, values: Iterable[str], *, required: bool = False) -> tuple[str, ...]:
    result = tuple(sorted(_digest(name, value) for value in values))
    if required and not result:
        raise GovernanceError(f"{name}s must not be empty")
    if len(result) != len(set(result)):
        raise GovernanceError(f"{name}s must be unique")
    return result


def _worst_state(values: Iterable[AssuranceState]) -> AssuranceState:
    states = tuple(values)
    if not states:
        return AssuranceState.HEALTHY
    return max(states, key=lambda item: _STATE_RANK[item])


@dataclass(frozen=True, slots=True)
class AssurancePolicy:
    portfolio_id: str
    policy_id: str
    version: int
    required_domains: tuple[str, ...]
    max_dossier_age_seconds: int
    provider_entity_concentration_threshold: int
    critical_function_concentration_threshold: int
    owner_id: str
    registered_at: int

    def __post_init__(self) -> None:
        for name in ("portfolio_id", "policy_id", "owner_id"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        _positive_int("policy version", self.version)
        domains = _sorted_unique_texts("required_domain", self.required_domains, required=True)
        unknown = tuple(domain for domain in domains if domain not in KNOWN_ASSURANCE_DOMAINS)
        if unknown:
            raise GovernanceError(f"unsupported assurance domain(s): {', '.join(unknown)}")
        object.__setattr__(self, "required_domains", domains)
        _positive_int("max_dossier_age_seconds", self.max_dossier_age_seconds)
        _positive_int(
            "provider_entity_concentration_threshold",
            self.provider_entity_concentration_threshold,
        )
        _positive_int(
            "critical_function_concentration_threshold",
            self.critical_function_concentration_threshold,
        )
        _timestamp("registered_at", self.registered_at)

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class DomainAssuranceSummary:
    domain: str
    artifact_count: int
    current_count: int
    gap_count: int
    revalidation_count: int
    state: AssuranceState
    findings: tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "domain", _text("domain", self.domain))
        if self.domain not in KNOWN_ASSURANCE_DOMAINS:
            raise GovernanceError("domain assurance summary uses an unsupported domain")
        for name in ("artifact_count", "current_count", "gap_count", "revalidation_count"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise GovernanceError(f"{name} must be a non-negative integer")
        if self.current_count + self.gap_count + self.revalidation_count != self.artifact_count:
            raise GovernanceError("domain assurance counts must sum to artifact_count")
        if not isinstance(self.state, AssuranceState):
            raise GovernanceError("domain assurance state must use a governed value")
        findings = _sorted_unique_texts("finding", self.findings)
        object.__setattr__(self, "findings", findings)
        if self.artifact_count == 0:
            if self.state is not AssuranceState.INCOMPLETE:
                raise GovernanceError("missing required domain must be incomplete")
            if not findings:
                raise GovernanceError("missing required domain must explain the gap")
        elif self.state is AssuranceState.HEALTHY and findings:
            raise GovernanceError("healthy domain cannot carry findings")
        elif self.state is not AssuranceState.HEALTHY and not findings:
            raise GovernanceError("non-healthy domain must explain its findings")

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class EntityProviderExposure:
    entity_id: str
    provider_id: str
    arrangement_ids: tuple[str, ...]
    supported_function_ids: tuple[str, ...]
    critical_function_ids: tuple[str, ...]
    high_or_critical_observation_count: int

    def __post_init__(self) -> None:
        for name in ("entity_id", "provider_id"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        object.__setattr__(
            self,
            "arrangement_ids",
            _sorted_unique_texts("arrangement_id", self.arrangement_ids, required=True),
        )
        object.__setattr__(
            self,
            "supported_function_ids",
            _sorted_unique_texts("supported_function_id", self.supported_function_ids),
        )
        object.__setattr__(
            self,
            "critical_function_ids",
            _sorted_unique_texts("critical_function_id", self.critical_function_ids),
        )
        if not set(self.critical_function_ids).issubset(self.supported_function_ids):
            raise GovernanceError("provider critical functions must be a subset of supported functions")
        if (
            isinstance(self.high_or_critical_observation_count, bool)
            or not isinstance(self.high_or_critical_observation_count, int)
            or self.high_or_critical_observation_count < 0
        ):
            raise GovernanceError("high_or_critical_observation_count must be a non-negative integer")

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class EntityAssurancePosition:
    entity_id: str
    dossier_digest: str
    dossier_generated_at: int
    source_revision: str
    policy_digest: str
    assessed_at: int
    freshness_state: AssuranceState
    domain_summaries: tuple[DomainAssuranceSummary, ...]
    provider_exposures: tuple[EntityProviderExposure, ...]
    critical_function_ids: tuple[str, ...]
    state: AssuranceState
    findings: tuple[str, ...]
    dora_compliance_determined: bool = False
    operational_resilience_determined: bool = False
    supervisory_acceptance_determined: bool = False
    requires_human_review: bool = True

    def __post_init__(self) -> None:
        object.__setattr__(self, "entity_id", _text("entity_id", self.entity_id))
        object.__setattr__(self, "source_revision", _text("source_revision", self.source_revision))
        _digest("dossier_digest", self.dossier_digest)
        _digest("policy_digest", self.policy_digest)
        _timestamp("dossier_generated_at", self.dossier_generated_at)
        _timestamp("assessed_at", self.assessed_at)
        if self.assessed_at < self.dossier_generated_at:
            raise GovernanceError("entity assurance assessment cannot predate dossier generation")
        if self.freshness_state not in {
            AssuranceState.HEALTHY,
            AssuranceState.REVALIDATION_REQUIRED,
        }:
            raise GovernanceError("entity dossier freshness state must be healthy or revalidation_required")
        summaries = tuple(sorted(self.domain_summaries, key=lambda item: item.domain))
        if len(summaries) != len({item.domain for item in summaries}):
            raise GovernanceError("entity assurance domain summaries must be unique")
        object.__setattr__(self, "domain_summaries", summaries)
        exposures = tuple(sorted(self.provider_exposures, key=lambda item: item.provider_id))
        if len(exposures) != len({item.provider_id for item in exposures}):
            raise GovernanceError("entity provider exposures must be unique per provider")
        if any(item.entity_id != self.entity_id for item in exposures):
            raise GovernanceError("entity provider exposure crosses entity scope")
        object.__setattr__(self, "provider_exposures", exposures)
        object.__setattr__(
            self,
            "critical_function_ids",
            _sorted_unique_texts("critical_function_id", self.critical_function_ids),
        )
        if not isinstance(self.state, AssuranceState):
            raise GovernanceError("entity assurance state must use a governed value")
        findings = _sorted_unique_texts("finding", self.findings)
        object.__setattr__(self, "findings", findings)
        expected = _worst_state(
            tuple(item.state for item in summaries) + (self.freshness_state,)
        )
        if self.state is not expected:
            raise GovernanceError("entity assurance state is inconsistent with domain summaries")
        if self.state is AssuranceState.HEALTHY and findings:
            raise GovernanceError("healthy entity assurance position cannot carry findings")
        if self.state is not AssuranceState.HEALTHY and not findings:
            raise GovernanceError("non-healthy entity assurance position must carry findings")
        if self.dora_compliance_determined is not False:
            raise GovernanceError("entity assurance must not determine DORA compliance")
        if self.operational_resilience_determined is not False:
            raise GovernanceError("entity assurance must not determine operational resilience")
        if self.supervisory_acceptance_determined is not False:
            raise GovernanceError("entity assurance must not determine supervisory acceptance")
        if self.requires_human_review is not True:
            raise GovernanceError("entity assurance requires human review")

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class ProviderPortfolioExposure:
    provider_id: str
    entity_ids: tuple[str, ...]
    arrangement_count: int
    critical_function_refs: tuple[str, ...]
    high_or_critical_observation_count: int
    entity_concentration_threshold_reached: bool
    critical_function_concentration_threshold_reached: bool
    legal_concentration_risk_determined: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "provider_id", _text("provider_id", self.provider_id))
        object.__setattr__(
            self,
            "entity_ids",
            _sorted_unique_texts("entity_id", self.entity_ids, required=True),
        )
        object.__setattr__(
            self,
            "critical_function_refs",
            _sorted_unique_texts("critical_function_ref", self.critical_function_refs),
        )
        _positive_int("arrangement_count", self.arrangement_count)
        if (
            isinstance(self.high_or_critical_observation_count, bool)
            or not isinstance(self.high_or_critical_observation_count, int)
            or self.high_or_critical_observation_count < 0
        ):
            raise GovernanceError("high_or_critical_observation_count must be a non-negative integer")
        if type(self.entity_concentration_threshold_reached) is not bool:
            raise GovernanceError("entity_concentration_threshold_reached must be boolean")
        if type(self.critical_function_concentration_threshold_reached) is not bool:
            raise GovernanceError("critical_function_concentration_threshold_reached must be boolean")
        if self.legal_concentration_risk_determined is not False:
            raise GovernanceError("portfolio exposure must not determine legal concentration risk")

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class PortfolioAssuranceSnapshot:
    portfolio_id: str
    snapshot_id: str
    sequence: int
    policy_digest: str
    positions: tuple[EntityAssurancePosition, ...]
    provider_exposures: tuple[ProviderPortfolioExposure, ...]
    state: AssuranceState
    findings: tuple[str, ...]
    assembled_at: int
    dora_compliance_determined: bool = False
    operational_resilience_determined: bool = False
    supervisory_acceptance_determined: bool = False
    legal_concentration_risk_determined: bool = False
    requires_human_review: bool = True

    def __post_init__(self) -> None:
        for name in ("portfolio_id", "snapshot_id"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        _positive_int("snapshot sequence", self.sequence)
        _digest("policy_digest", self.policy_digest)
        _timestamp("assembled_at", self.assembled_at)
        positions = tuple(sorted(self.positions, key=lambda item: item.entity_id))
        if not positions:
            raise GovernanceError("portfolio assurance snapshot requires at least one entity position")
        if len(positions) != len({item.entity_id for item in positions}):
            raise GovernanceError("portfolio assurance positions must be unique per entity")
        if any(item.policy_digest != self.policy_digest for item in positions):
            raise GovernanceError("portfolio assurance positions must use the exact policy digest")
        if any(item.assessed_at != self.assembled_at for item in positions):
            raise GovernanceError("portfolio positions must be assessed at snapshot assembly time")
        object.__setattr__(self, "positions", positions)
        exposures = tuple(sorted(self.provider_exposures, key=lambda item: item.provider_id))
        if len(exposures) != len({item.provider_id for item in exposures}):
            raise GovernanceError("portfolio provider exposures must be unique")
        object.__setattr__(self, "provider_exposures", exposures)
        if not isinstance(self.state, AssuranceState):
            raise GovernanceError("portfolio assurance state must use a governed value")
        findings = _sorted_unique_texts("finding", self.findings)
        object.__setattr__(self, "findings", findings)
        if self.state is AssuranceState.HEALTHY and findings:
            raise GovernanceError("healthy portfolio assurance snapshot cannot carry findings")
        if self.state is not AssuranceState.HEALTHY and not findings:
            raise GovernanceError("non-healthy portfolio assurance snapshot must carry findings")
        if self.dora_compliance_determined is not False:
            raise GovernanceError("portfolio assurance must not determine DORA compliance")
        if self.operational_resilience_determined is not False:
            raise GovernanceError("portfolio assurance must not determine operational resilience")
        if self.supervisory_acceptance_determined is not False:
            raise GovernanceError("portfolio assurance must not determine supervisory acceptance")
        if self.legal_concentration_risk_determined is not False:
            raise GovernanceError("portfolio assurance must not determine legal concentration risk")
        if self.requires_human_review is not True:
            raise GovernanceError("portfolio assurance requires human review")

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


def _artifact_state(value: Any) -> str:
    if value not in {"current", "with_gaps", "revalidation_required"}:
        raise GovernanceError("dossier assurance encountered unsupported artifact state")
    return value


def _semantic_state(domain: str, artifacts: tuple[dict[str, Any], ...]) -> tuple[AssuranceState, tuple[str, ...]]:
    state = AssuranceState.HEALTHY
    findings: list[str] = []

    for artifact in artifacts:
        artifact_type = artifact["artifact_type"]
        payload = artifact["payload"]
        if not isinstance(payload, dict):
            raise GovernanceError("dossier assurance artifact payload must be an object")

        candidate = AssuranceState.HEALTHY
        marker: str | None = None

        if domain == "ict_risk" and artifact_type == "risk_decision":
            residual_level = payload.get("residual_level")
            if residual_level in {"high", "critical"}:
                candidate = AssuranceState.ATTENTION
                marker = f"high_residual_ict_risk:{artifact['artifact_id']}:{residual_level}"
            if payload.get("remediation_required") is True:
                candidate = _worst_state((candidate, AssuranceState.ATTENTION))
                marker = marker or f"ict_risk_remediation_required:{artifact['artifact_id']}"
            if payload.get("risk_acceptance_required") is True:
                candidate = _worst_state((candidate, AssuranceState.ATTENTION))
                marker = marker or f"ict_risk_acceptance_required:{artifact['artifact_id']}"

        elif domain == "incident" and artifact_type == "classification_review":
            if payload.get("decision") == "major":
                candidate = AssuranceState.ATTENTION
                marker = f"major_incident:{artifact['artifact_id']}"

        elif domain == "incident_reporting" and artifact_type == "workflow_assessment":
            workflow_state = payload.get("state")
            if workflow_state == "revalidation_required":
                candidate = AssuranceState.REVALIDATION_REQUIRED
            elif workflow_state == "breached":
                candidate = AssuranceState.BREACHED
            elif workflow_state == "incomplete":
                candidate = AssuranceState.INCOMPLETE
            elif workflow_state == "pending":
                candidate = AssuranceState.ATTENTION
            if candidate is not AssuranceState.HEALTHY:
                marker = f"incident_reporting:{artifact['artifact_id']}:{workflow_state}"

        elif domain == "continuity" and artifact_type == "recovery_assessment":
            recovery_state = payload.get("state")
            if recovery_state == "breached":
                candidate = AssuranceState.BREACHED
            elif recovery_state == "incomplete":
                candidate = AssuranceState.INCOMPLETE
            if candidate is not AssuranceState.HEALTHY:
                marker = f"continuity_recovery:{artifact['artifact_id']}:{recovery_state}"

        elif domain == "continuity" and artifact_type == "continuity_resolution":
            resolution_state = payload.get("state")
            if resolution_state == "blocked":
                candidate = AssuranceState.BREACHED
            elif resolution_state == "incomplete":
                candidate = AssuranceState.INCOMPLETE
            if candidate is not AssuranceState.HEALTHY:
                marker = f"continuity_resolution:{artifact['artifact_id']}:{resolution_state}"

        elif domain == "resilience_test" and artifact_type == "test_resolution":
            resolution_state = payload.get("state")
            if resolution_state == "blocked":
                candidate = AssuranceState.BREACHED
            elif resolution_state == "incomplete":
                candidate = AssuranceState.INCOMPLETE
            if candidate is not AssuranceState.HEALTHY:
                marker = f"resilience_test:{artifact['artifact_id']}:{resolution_state}"

        elif domain == "third_party" and artifact_type == "dependency_observation":
            concentration = payload.get("concentration")
            if concentration in {"high", "critical"}:
                candidate = AssuranceState.ATTENTION
                marker = f"third_party_concentration:{artifact['artifact_id']}:{concentration}"
            substitutability = payload.get("substitutability")
            if substitutability == "difficult":
                candidate = _worst_state((candidate, AssuranceState.ATTENTION))
                marker = marker or f"third_party_substitutability:{artifact['artifact_id']}:difficult"

        if _STATE_RANK[candidate] > _STATE_RANK[state]:
            state = candidate
        if marker is not None:
            findings.append(marker)

    return state, tuple(sorted(set(findings)))


def _domain_summary(
    domain: str,
    artifacts: tuple[dict[str, Any], ...],
    *,
    required: bool,
) -> DomainAssuranceSummary | None:
    if not artifacts:
        if not required:
            return None
        return DomainAssuranceSummary(
            domain=domain,
            artifact_count=0,
            current_count=0,
            gap_count=0,
            revalidation_count=0,
            state=AssuranceState.INCOMPLETE,
            findings=(f"required_domain_missing:{domain}",),
        )

    states = tuple(_artifact_state(item["state"]) for item in artifacts)
    current_count = states.count("current")
    gap_count = states.count("with_gaps")
    revalidation_count = states.count("revalidation_required")

    artifact_findings = {
        f"{item['artifact_type']}:{item['artifact_id']}:{finding}"
        for item in artifacts
        for finding in item.get("findings", ())
    }
    semantic_state, semantic_findings = _semantic_state(domain, artifacts)

    if revalidation_count:
        state = AssuranceState.REVALIDATION_REQUIRED
    elif semantic_state is not AssuranceState.HEALTHY:
        state = semantic_state
    elif gap_count:
        state = AssuranceState.ATTENTION
    else:
        state = AssuranceState.HEALTHY

    findings = tuple(sorted(artifact_findings | set(semantic_findings)))
    if state is not AssuranceState.HEALTHY and not findings:
        findings = (f"domain_state:{domain}:{state.value}",)

    return DomainAssuranceSummary(
        domain=domain,
        artifact_count=len(artifacts),
        current_count=current_count,
        gap_count=gap_count,
        revalidation_count=revalidation_count,
        state=state,
        findings=findings,
    )


def _critical_functions(artifacts: tuple[dict[str, Any], ...]) -> tuple[str, ...]:
    result: set[str] = set()
    for item in artifacts:
        if item["domain"] != "inventory" or item["artifact_type"] != "BusinessFunction":
            continue
        payload = item["payload"]
        if payload.get("classification") == "critical_or_important":
            function_id = payload.get("function_id")
            if not isinstance(function_id, str) or not function_id.strip():
                raise GovernanceError("critical business-function artifact lacks function_id")
            result.add(function_id.strip())
    return tuple(sorted(result))


def _entity_provider_exposures(
    entity_id: str,
    artifacts: tuple[dict[str, Any], ...],
    critical_function_ids: tuple[str, ...],
) -> tuple[EntityProviderExposure, ...]:
    known_providers = {
        item["payload"].get("provider_id")
        for item in artifacts
        if item["domain"] == "inventory" and item["artifact_type"] == "third_party_provider"
    }
    known_providers = {item for item in known_providers if isinstance(item, str) and item.strip()}

    arrangements: dict[str, dict[str, Any]] = {}
    provider_accumulator: dict[str, dict[str, Any]] = {}

    for item in artifacts:
        if item["domain"] != "third_party" or item["artifact_type"] != "arrangement":
            continue
        payload = item["payload"]
        arrangement_id = payload.get("arrangement_id")
        provider_id = payload.get("direct_provider_id")
        if not isinstance(arrangement_id, str) or not arrangement_id.strip():
            raise GovernanceError("third-party arrangement lacks arrangement_id")
        if not isinstance(provider_id, str) or not provider_id.strip():
            raise GovernanceError("third-party arrangement lacks direct_provider_id")
        arrangement_id = arrangement_id.strip()
        provider_id = provider_id.strip()
        if known_providers and provider_id not in known_providers:
            raise GovernanceError("third-party arrangement provider is absent from dossier inventory")
        if arrangement_id in arrangements:
            raise GovernanceError("duplicate third-party arrangement identity in assurance input")
        arrangements[arrangement_id] = payload
        supported = payload.get("supported_function_ids", [])
        critical = payload.get("critical_or_important_function_ids", [])
        if not isinstance(supported, list) or not all(isinstance(value, str) and value.strip() for value in supported):
            raise GovernanceError("third-party arrangement supported functions must be strings")
        if not isinstance(critical, list) or not all(isinstance(value, str) and value.strip() for value in critical):
            raise GovernanceError("third-party arrangement critical functions must be strings")
        if not set(critical).issubset(set(critical_function_ids)):
            raise GovernanceError("third-party arrangement critical functions differ from dossier critical-function inventory")
        bucket = provider_accumulator.setdefault(
            provider_id,
            {
                "arrangement_ids": set(),
                "supported": set(),
                "critical": set(),
                "high_count": 0,
            },
        )
        bucket["arrangement_ids"].add(arrangement_id)
        bucket["supported"].update(value.strip() for value in supported)
        bucket["critical"].update(value.strip() for value in critical)

    for item in artifacts:
        if item["domain"] != "third_party" or item["artifact_type"] != "dependency_observation":
            continue
        payload = item["payload"]
        arrangement_id = payload.get("arrangement_id")
        if not isinstance(arrangement_id, str) or arrangement_id not in arrangements:
            raise GovernanceError("dependency observation does not resolve to a dossier arrangement")
        provider_id = arrangements[arrangement_id]["direct_provider_id"]
        concentration = payload.get("concentration")
        if concentration in {"high", "critical"}:
            provider_accumulator[provider_id]["high_count"] += 1

    result = []
    for provider_id, values in sorted(provider_accumulator.items()):
        result.append(
            EntityProviderExposure(
                entity_id=entity_id,
                provider_id=provider_id,
                arrangement_ids=tuple(values["arrangement_ids"]),
                supported_function_ids=tuple(values["supported"]),
                critical_function_ids=tuple(values["critical"]),
                high_or_critical_observation_count=values["high_count"],
            )
        )
    return tuple(result)


def _entity_position(
    document: dict[str, Any],
    policy: AssurancePolicy,
    *,
    assessed_at: int,
) -> EntityAssurancePosition:
    dossier_digest = verify_dossier_document(document)
    dossier = document["dossier"]
    entity_id = _text("entity_id", dossier.get("entity_id"))
    generated_at = dossier.get("generated_at")
    _timestamp("dossier generated_at", generated_at)
    source_revision = _text("source_revision", dossier.get("source_revision"))
    _timestamp("assessed_at", assessed_at)
    if assessed_at < generated_at:
        raise GovernanceError("assurance assessment cannot predate dossier generation")
    if assessed_at < policy.registered_at:
        raise GovernanceError("assurance assessment cannot predate policy registration")

    raw_artifacts = dossier.get("artifacts")
    if not isinstance(raw_artifacts, list) or not raw_artifacts:
        raise GovernanceError("verified dossier lacks artifacts")
    artifacts = tuple(raw_artifacts)

    observed_domains = {
        item.get("domain")
        for item in artifacts
        if item.get("domain") in KNOWN_ASSURANCE_DOMAINS
    }
    domains = tuple(sorted(set(policy.required_domains) | observed_domains))
    summaries: list[DomainAssuranceSummary] = []
    for domain in domains:
        items = tuple(item for item in artifacts if item.get("domain") == domain)
        summary = _domain_summary(domain, items, required=domain in policy.required_domains)
        if summary is not None:
            summaries.append(summary)

    critical_functions = _critical_functions(artifacts)
    provider_exposures = _entity_provider_exposures(entity_id, artifacts, critical_functions)

    freshness_state = AssuranceState.HEALTHY
    freshness_findings: tuple[str, ...] = ()
    if assessed_at - generated_at > policy.max_dossier_age_seconds:
        freshness_state = AssuranceState.REVALIDATION_REQUIRED
        freshness_findings = ("dossier_age_exceeds_policy",)

    state = _worst_state(
        tuple(item.state for item in summaries) + (freshness_state,)
    )
    findings = tuple(
        sorted(
            {
                f"{item.domain}:{finding}"
                for item in summaries
                for finding in item.findings
            }
            | set(freshness_findings)
        )
    )

    return EntityAssurancePosition(
        entity_id=entity_id,
        dossier_digest=dossier_digest,
        dossier_generated_at=generated_at,
        source_revision=source_revision,
        policy_digest=policy.evidence_digest,
        assessed_at=assessed_at,
        freshness_state=freshness_state,
        domain_summaries=tuple(summaries),
        provider_exposures=provider_exposures,
        critical_function_ids=critical_functions,
        state=state,
        findings=findings,
    )


def _portfolio_exposures(
    positions: tuple[EntityAssurancePosition, ...],
    policy: AssurancePolicy,
) -> tuple[ProviderPortfolioExposure, ...]:
    accumulator: dict[str, dict[str, Any]] = {}
    for position in positions:
        for exposure in position.provider_exposures:
            bucket = accumulator.setdefault(
                exposure.provider_id,
                {
                    "entity_ids": set(),
                    "arrangement_count": 0,
                    "critical_refs": set(),
                    "high_count": 0,
                },
            )
            bucket["entity_ids"].add(position.entity_id)
            bucket["arrangement_count"] += len(exposure.arrangement_ids)
            bucket["critical_refs"].update(
                f"{position.entity_id}:{function_id}"
                for function_id in exposure.critical_function_ids
            )
            bucket["high_count"] += exposure.high_or_critical_observation_count

    result = []
    for provider_id, values in sorted(accumulator.items()):
        entity_ids = tuple(values["entity_ids"])
        critical_refs = tuple(values["critical_refs"])
        result.append(
            ProviderPortfolioExposure(
                provider_id=provider_id,
                entity_ids=entity_ids,
                arrangement_count=values["arrangement_count"],
                critical_function_refs=critical_refs,
                high_or_critical_observation_count=values["high_count"],
                entity_concentration_threshold_reached=(
                    len(entity_ids) >= policy.provider_entity_concentration_threshold
                ),
                critical_function_concentration_threshold_reached=(
                    len(critical_refs) >= policy.critical_function_concentration_threshold
                ),
            )
        )
    return tuple(result)


def verify_portfolio_snapshot(snapshot: PortfolioAssuranceSnapshot) -> str:
    if not isinstance(snapshot, PortfolioAssuranceSnapshot):
        raise GovernanceError("portfolio snapshot verification requires PortfolioAssuranceSnapshot")
    expected_exposure_keys = {item.provider_id for item in snapshot.provider_exposures}
    if len(expected_exposure_keys) != len(snapshot.provider_exposures):
        raise GovernanceError("portfolio provider exposure identities are not unique")

    position_state = _worst_state(position.state for position in snapshot.positions)
    threshold_attention = any(
        item.entity_concentration_threshold_reached
        or item.critical_function_concentration_threshold_reached
        or item.high_or_critical_observation_count > 0
        for item in snapshot.provider_exposures
    )
    expected_state = position_state
    if threshold_attention and _STATE_RANK[expected_state] < _STATE_RANK[AssuranceState.ATTENTION]:
        expected_state = AssuranceState.ATTENTION
    if snapshot.state is not expected_state:
        raise GovernanceError("portfolio assurance state is inconsistent with entity/provider evidence")
    return snapshot.evidence_digest


class PortfolioAssuranceRegistry:
    """Append-only registry for verified dossier-based executive assurance views."""

    def __init__(self) -> None:
        self._policies: dict[tuple[str, str, int], AssurancePolicy] = {}
        self._policy_latest: dict[tuple[str, str], AssurancePolicy] = {}
        self._dossiers: dict[tuple[str, str], dict[str, Any]] = {}
        self._latest_dossier: dict[str, dict[str, Any]] = {}
        self._snapshots: dict[tuple[str, str, int], PortfolioAssuranceSnapshot] = {}
        self._snapshot_latest: dict[tuple[str, str], PortfolioAssuranceSnapshot] = {}

    def register_policy(self, policy: AssurancePolicy) -> str:
        if not isinstance(policy, AssurancePolicy):
            raise GovernanceError("assurance registry requires AssurancePolicy")
        key = (policy.portfolio_id, policy.policy_id, policy.version)
        existing = self._policies.get(key)
        if existing is not None:
            if existing != policy:
                raise GovernanceError("assurance policy identity is immutable")
            return existing.evidence_digest

        latest_key = (policy.portfolio_id, policy.policy_id)
        latest = self._policy_latest.get(latest_key)
        expected_version = 1 if latest is None else latest.version + 1
        if policy.version != expected_version:
            raise GovernanceError("assurance policy versions must be contiguous")
        if latest is not None and policy.registered_at < latest.registered_at:
            raise GovernanceError("assurance policy history cannot be backdated")

        self._policies[key] = policy
        self._policy_latest[latest_key] = policy
        return policy.evidence_digest

    def assert_policy_current(self, policy: AssurancePolicy) -> None:
        latest = self._policy_latest.get((policy.portfolio_id, policy.policy_id))
        if latest is None or latest.evidence_digest != policy.evidence_digest:
            raise GovernanceError("assurance policy is not current")

    def register_dossier(self, document: dict[str, Any]) -> str:
        if not isinstance(document, dict):
            raise GovernanceError("assurance dossier input must be an object")
        digest = verify_dossier_document(document)
        normalized = json.loads(canonical_json(document))
        dossier = normalized["dossier"]
        entity_id = _text("entity_id", dossier.get("entity_id"))
        generated_at = dossier.get("generated_at")
        _timestamp("dossier generated_at", generated_at)
        key = (entity_id, digest)

        existing = self._dossiers.get(key)
        if existing is not None:
            if existing != normalized:
                raise GovernanceError("dossier digest identity is immutable")
            return digest

        latest = self._latest_dossier.get(entity_id)
        if latest is not None:
            latest_generated = latest["dossier"]["generated_at"]
            latest_digest = latest["dossier_digest"]
            if generated_at < latest_generated:
                raise GovernanceError("assurance dossier history cannot be backdated")
            if generated_at == latest_generated and digest != latest_digest:
                raise GovernanceError("same generated_at cannot identify different dossier content")

        self._dossiers[key] = normalized
        self._latest_dossier[entity_id] = normalized
        return digest

    def latest_dossier_digest(self, entity_id: str) -> str:
        entity_id = _text("entity_id", entity_id)
        latest = self._latest_dossier.get(entity_id)
        if latest is None:
            raise GovernanceError("no assurance dossier is registered for entity")
        return latest["dossier_digest"]

    def build_entity_position(
        self,
        policy: AssurancePolicy,
        *,
        entity_id: str,
        assessed_at: int,
    ) -> EntityAssurancePosition:
        self.assert_policy_current(policy)
        entity_id = _text("entity_id", entity_id)
        latest = self._latest_dossier.get(entity_id)
        if latest is None:
            raise GovernanceError("no assurance dossier is registered for entity")
        return _entity_position(latest, policy, assessed_at=assessed_at)

    def build_snapshot(
        self,
        policy: AssurancePolicy,
        *,
        snapshot_id: str,
        sequence: int,
        entity_ids: Iterable[str],
        assembled_at: int,
    ) -> PortfolioAssuranceSnapshot:
        self.assert_policy_current(policy)
        snapshot_id = _text("snapshot_id", snapshot_id)
        _positive_int("snapshot sequence", sequence)
        _timestamp("assembled_at", assembled_at)
        normalized_entity_ids = _sorted_unique_texts("entity_id", entity_ids, required=True)
        positions = tuple(
            self.build_entity_position(
                policy,
                entity_id=entity_id,
                assessed_at=assembled_at,
            )
            for entity_id in normalized_entity_ids
        )
        exposures = _portfolio_exposures(positions, policy)

        state = _worst_state(position.state for position in positions)
        findings: set[str] = {
            f"entity:{position.entity_id}:{position.state.value}"
            for position in positions
            if position.state is not AssuranceState.HEALTHY
        }
        for exposure in exposures:
            if exposure.high_or_critical_observation_count:
                findings.add(
                    f"provider:{exposure.provider_id}:represented_high_or_critical_concentration:"
                    f"{exposure.high_or_critical_observation_count}"
                )
            if exposure.entity_concentration_threshold_reached:
                findings.add(
                    f"provider:{exposure.provider_id}:entity_concentration_threshold_reached:"
                    f"{len(exposure.entity_ids)}"
                )
            if exposure.critical_function_concentration_threshold_reached:
                findings.add(
                    f"provider:{exposure.provider_id}:critical_function_concentration_threshold_reached:"
                    f"{len(exposure.critical_function_refs)}"
                )
        if findings and _STATE_RANK[state] < _STATE_RANK[AssuranceState.ATTENTION]:
            state = AssuranceState.ATTENTION

        return PortfolioAssuranceSnapshot(
            portfolio_id=policy.portfolio_id,
            snapshot_id=snapshot_id,
            sequence=sequence,
            policy_digest=policy.evidence_digest,
            positions=positions,
            provider_exposures=exposures,
            state=state,
            findings=tuple(findings),
            assembled_at=assembled_at,
        )

    def register_snapshot(
        self,
        snapshot: PortfolioAssuranceSnapshot,
        policy: AssurancePolicy,
    ) -> str:
        if not isinstance(snapshot, PortfolioAssuranceSnapshot):
            raise GovernanceError("assurance registry requires PortfolioAssuranceSnapshot")
        verify_portfolio_snapshot(snapshot)
        key = (snapshot.portfolio_id, snapshot.snapshot_id, snapshot.sequence)
        existing = self._snapshots.get(key)
        if existing is not None:
            if existing != snapshot:
                raise GovernanceError("portfolio assurance snapshot identity is immutable")
            return existing.evidence_digest

        self.assert_policy_current(policy)
        if snapshot.policy_digest != policy.evidence_digest:
            raise GovernanceError("portfolio snapshot does not bind the supplied current policy")
        if snapshot.portfolio_id != policy.portfolio_id:
            raise GovernanceError("portfolio snapshot crosses policy portfolio scope")

        latest_key = (snapshot.portfolio_id, snapshot.snapshot_id)
        latest = self._snapshot_latest.get(latest_key)
        expected_sequence = 1 if latest is None else latest.sequence + 1
        if snapshot.sequence != expected_sequence:
            raise GovernanceError("portfolio assurance snapshot sequences must be contiguous")
        if latest is not None and snapshot.assembled_at < latest.assembled_at:
            raise GovernanceError("portfolio assurance snapshot history cannot be backdated")

        for position in snapshot.positions:
            latest_document = self._latest_dossier.get(position.entity_id)
            if latest_document is None:
                raise GovernanceError("portfolio snapshot references an unregistered entity dossier")
            if latest_document["dossier_digest"] != position.dossier_digest:
                raise GovernanceError("portfolio snapshot position is stale for latest registered dossier")
            rebuilt = _entity_position(
                latest_document,
                policy,
                assessed_at=snapshot.assembled_at,
            )
            if rebuilt.evidence_digest != position.evidence_digest:
                raise GovernanceError("portfolio snapshot position does not reproduce current evidence")

        rebuilt_exposures = _portfolio_exposures(snapshot.positions, policy)
        if tuple(item.evidence_digest for item in rebuilt_exposures) != tuple(
            item.evidence_digest for item in snapshot.provider_exposures
        ):
            raise GovernanceError("portfolio provider exposures do not reproduce entity evidence")

        self._snapshots[key] = snapshot
        self._snapshot_latest[latest_key] = snapshot
        return snapshot.evidence_digest

    def verify_snapshot(self, snapshot: PortfolioAssuranceSnapshot) -> str:
        key = (snapshot.portfolio_id, snapshot.snapshot_id, snapshot.sequence)
        registered = self._snapshots.get(key)
        if registered is None or registered.evidence_digest != snapshot.evidence_digest:
            raise GovernanceError("portfolio assurance snapshot is not registered")
        return verify_portfolio_snapshot(snapshot)

    def assert_snapshot_current(
        self,
        snapshot: PortfolioAssuranceSnapshot,
        policy: AssurancePolicy,
    ) -> None:
        self.verify_snapshot(snapshot)
        self.assert_policy_current(policy)
        if snapshot.policy_digest != policy.evidence_digest:
            raise GovernanceError("portfolio assurance snapshot uses a stale policy")
        latest = self._snapshot_latest.get((snapshot.portfolio_id, snapshot.snapshot_id))
        if latest is None or latest.evidence_digest != snapshot.evidence_digest:
            raise GovernanceError("portfolio assurance snapshot is not the latest sequence")
        for position in snapshot.positions:
            if self.latest_dossier_digest(position.entity_id) != position.dossier_digest:
                raise GovernanceError("portfolio assurance snapshot is stale for current entity dossier")


__all__ = [
    "KNOWN_ASSURANCE_DOMAINS",
    "AssurancePolicy",
    "AssuranceState",
    "DomainAssuranceSummary",
    "EntityAssurancePosition",
    "EntityProviderExposure",
    "PortfolioAssuranceRegistry",
    "PortfolioAssuranceSnapshot",
    "ProviderPortfolioExposure",
    "verify_portfolio_snapshot",
]
