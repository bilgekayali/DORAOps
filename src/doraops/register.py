from __future__ import annotations

from .models import RegisterBundle, RegisterValidationReport


class RegisterValidator:
    def validate(self, bundle: RegisterBundle, *, validated_at: str) -> RegisterValidationReport:
        errors: set[str] = set()
        warnings: set[str] = set()

        provider_ids = [item.provider_id for item in bundle.providers]
        function_ids = [item.function_id for item in bundle.functions]
        arrangement_ids = [item.arrangement_id for item in bundle.arrangements]
        if len(provider_ids) != len(set(provider_ids)):
            errors.add("duplicate_provider_id")
        if len(function_ids) != len(set(function_ids)):
            errors.add("duplicate_function_id")
        if len(arrangement_ids) != len(set(arrangement_ids)):
            errors.add("duplicate_arrangement_id")

        providers = {item.provider_id: item for item in bundle.providers}
        functions = {item.function_id: item for item in bundle.functions}

        for arrangement in bundle.arrangements:
            if arrangement.provider_id not in providers:
                errors.add("arrangement_provider_reference_missing")
            function = functions.get(arrangement.function_id)
            if function is None:
                errors.add("arrangement_function_reference_missing")
                continue
            if arrangement.supports_critical_or_important_function != function.critical_or_important:
                errors.add("critical_function_binding_mismatch")
            if function.critical_or_important:
                if not arrangement.exit_plan_documented:
                    errors.add("critical_arrangement_exit_plan_missing")
                if not arrangement.substitutability_assessed:
                    errors.add("critical_arrangement_substitutability_not_assessed")
            if arrangement.subcontracting_allowed:
                warnings.add("subcontracting_dependency_requires_later_chain_analysis")

        if not bundle.arrangements:
            warnings.add("no_ict_arrangements_registered")

        return RegisterValidationReport(
            institution_id=bundle.institution_id,
            register_digest=bundle.artifact_digest,
            structurally_complete=not errors,
            error_codes=tuple(sorted(errors)),
            warning_codes=tuple(sorted(warnings)),
            validated_at=validated_at,
        )
