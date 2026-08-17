from __future__ import annotations

from dataclasses import asdict, dataclass, is_dataclass
from datetime import datetime
from enum import Enum
import hashlib
import json
from typing import Any


def _canonical(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value):
        return _canonical(asdict(value))
    if isinstance(value, dict):
        return {str(k): _canonical(v) for k, v in sorted(value.items(), key=lambda item: str(item[0]))}
    if isinstance(value, (list, tuple)):
        return [_canonical(v) for v in value]
    return value


def canonical_json(value: Any) -> str:
    return json.dumps(_canonical(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest_artifact(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _text(name: str, value: str, *, limit: int = 256) -> None:
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise ValueError(f"{name} must be non-empty bounded text")


def _timestamp(name: str, value: str) -> None:
    _text(name, value, limit=64)
    if not value.endswith("Z"):
        raise ValueError(f"{name} must be RFC3339 UTC")
    datetime.fromisoformat(value[:-1] + "+00:00")


def _country(code: str) -> None:
    if not isinstance(code, str) or len(code) != 2 or not code.isalpha() or code.upper() != code:
        raise ValueError("country codes must be two-letter uppercase ISO-style codes")


@dataclass(frozen=True, slots=True)
class ICTProvider:
    institution_id: str
    provider_id: str
    legal_name: str
    country_code: str
    direct_provider: bool = True
    schema_version: str = "doraops.ict-provider.v1"

    def __post_init__(self) -> None:
        for field in ("institution_id", "provider_id", "legal_name", "schema_version"):
            _text(field, getattr(self, field))
        _country(self.country_code)

    @property
    def artifact_digest(self) -> str:
        return digest_artifact(self)


@dataclass(frozen=True, slots=True)
class BusinessFunction:
    institution_id: str
    function_id: str
    name: str
    critical_or_important: bool
    owner_id: str
    schema_version: str = "doraops.business-function.v1"

    def __post_init__(self) -> None:
        for field in ("institution_id", "function_id", "name", "owner_id", "schema_version"):
            _text(field, getattr(self, field))

    @property
    def artifact_digest(self) -> str:
        return digest_artifact(self)


@dataclass(frozen=True, slots=True)
class ICTArrangement:
    institution_id: str
    arrangement_id: str
    provider_id: str
    function_id: str
    service_type: str
    contract_reference_digest: str
    supports_critical_or_important_function: bool
    exit_plan_documented: bool
    substitutability_assessed: bool
    subcontracting_allowed: bool
    data_location_countries: tuple[str, ...]
    registered_at: str
    schema_version: str = "doraops.ict-arrangement.v1"

    def __post_init__(self) -> None:
        for field in ("institution_id", "arrangement_id", "provider_id", "function_id", "service_type", "schema_version"):
            _text(field, getattr(self, field), limit=512 if field == "service_type" else 256)
        if len(self.contract_reference_digest) != 64 or any(ch not in "0123456789abcdef" for ch in self.contract_reference_digest):
            raise ValueError("contract_reference_digest must be lowercase SHA-256")
        if not self.data_location_countries or len(set(self.data_location_countries)) != len(self.data_location_countries):
            raise ValueError("data_location_countries must be non-empty and unique")
        for country in self.data_location_countries:
            _country(country)
        _timestamp("registered_at", self.registered_at)

    @property
    def artifact_digest(self) -> str:
        return digest_artifact(self)


@dataclass(frozen=True, slots=True)
class RegisterBundle:
    institution_id: str
    providers: tuple[ICTProvider, ...]
    functions: tuple[BusinessFunction, ...]
    arrangements: tuple[ICTArrangement, ...]
    schema_version: str = "doraops.register-bundle.v1"

    def __post_init__(self) -> None:
        _text("institution_id", self.institution_id)
        if not self.providers or not self.functions:
            raise ValueError("register bundle requires providers and functions")
        for collection in (self.providers, self.functions, self.arrangements):
            if any(item.institution_id != self.institution_id for item in collection):
                raise ValueError("register bundle cannot mix institutions")

    @property
    def artifact_digest(self) -> str:
        return digest_artifact(self)


@dataclass(frozen=True, slots=True)
class RegisterValidationReport:
    institution_id: str
    register_digest: str
    structurally_complete: bool
    error_codes: tuple[str, ...]
    warning_codes: tuple[str, ...]
    validated_at: str
    regulatory_compliance_determined: bool = False
    schema_version: str = "doraops.register-validation-report.v1"

    def __post_init__(self) -> None:
        _text("institution_id", self.institution_id)
        if len(self.register_digest) != 64:
            raise ValueError("register_digest must be SHA-256")
        if len(set(self.error_codes)) != len(self.error_codes) or len(set(self.warning_codes)) != len(self.warning_codes):
            raise ValueError("validation codes must be unique")
        _timestamp("validated_at", self.validated_at)
        if self.regulatory_compliance_determined:
            raise ValueError("v0.1 cannot determine DORA regulatory compliance")

    @property
    def artifact_digest(self) -> str:
        return digest_artifact(self)
