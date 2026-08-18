from __future__ import annotations

from typing import Any

from .inventory import GovernanceError
from .third_party import (
    ConcentrationAssessment,
    DependencyObservation,
    ExitTransitionPlan,
    GeographicLocation,
    ProviderDesignation,
    RegisterAssessmentState,
    SubstitutabilityAssessment,
    ThirdPartyArrangement,
    ThirdPartyGap,
    ThirdPartyGapCode,
    ThirdPartyGovernancePolicy,
    ThirdPartyRegister as _ThirdPartyRegister,
    ThirdPartyRegisterRow,
    ThirdPartyRegisterSnapshot,
    build_register_snapshot as _build_register_snapshot,
    build_third_party_arrangement as _build_third_party_arrangement,
)


def _require_enum(name: str, value: Any, enum_type: type) -> None:
    if not isinstance(value, enum_type):
        raise GovernanceError(f"{name} must use the governed enum type")


def _require_policy_booleans(policy: ThirdPartyGovernancePolicy) -> None:
    fields = (
        "require_provider_designation_assessed",
        "require_data_location",
        "require_service_location",
        "require_contract_evidence",
        "require_control_requirement_evidence",
        "require_dependency_observation",
        "require_exit_plan_for_critical_functions",
        "require_exit_plan_for_high_concentration",
        "require_exit_plan_for_difficult_substitutability",
    )
    for name in fields:
        if type(getattr(policy, name)) is not bool:
            raise GovernanceError(f"{name} must be a boolean")


class ThirdPartyRegister(_ThirdPartyRegister):
    """Strict public register that validates governed enum inputs at runtime."""

    def register_arrangement(self, arrangement: ThirdPartyArrangement) -> str:
        _require_enum(
            "provider_designation",
            arrangement.provider_designation,
            ProviderDesignation,
        )
        return super().register_arrangement(arrangement)

    def register_observation(self, observation: DependencyObservation) -> str:
        _require_enum(
            "substitutability",
            observation.substitutability,
            SubstitutabilityAssessment,
        )
        _require_enum(
            "concentration",
            observation.concentration,
            ConcentrationAssessment,
        )
        return super().register_observation(observation)


def build_third_party_arrangement(*args: Any, **kwargs: Any) -> ThirdPartyArrangement:
    designation = kwargs.get("provider_designation")
    _require_enum("provider_designation", designation, ProviderDesignation)
    return _build_third_party_arrangement(*args, **kwargs)


def build_register_snapshot(
    register: ThirdPartyRegister,
    policy: ThirdPartyGovernancePolicy,
    *,
    as_of: int,
) -> ThirdPartyRegisterSnapshot:
    _require_policy_booleans(policy)
    return _build_register_snapshot(register, policy, as_of=as_of)


__all__ = [
    "ConcentrationAssessment",
    "DependencyObservation",
    "ExitTransitionPlan",
    "GeographicLocation",
    "ProviderDesignation",
    "RegisterAssessmentState",
    "SubstitutabilityAssessment",
    "ThirdPartyArrangement",
    "ThirdPartyGap",
    "ThirdPartyGapCode",
    "ThirdPartyGovernancePolicy",
    "ThirdPartyRegister",
    "ThirdPartyRegisterRow",
    "ThirdPartyRegisterSnapshot",
    "build_register_snapshot",
    "build_third_party_arrangement",
]
