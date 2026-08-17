import hashlib
import unittest

from doraops.models import BusinessFunction, ICTArrangement, ICTProvider, RegisterBundle
from doraops.register import RegisterValidator


class DORAOpsCoreTests(unittest.TestCase):
    def arrangement(self, critical=True, exit_plan=True, substitutability=True):
        return ICTArrangement(
            institution_id="bank-a",
            arrangement_id="arr-1",
            provider_id="provider-1",
            function_id="payments",
            service_type="managed cloud database",
            contract_reference_digest=hashlib.sha256(b"contract-1").hexdigest(),
            supports_critical_or_important_function=critical,
            exit_plan_documented=exit_plan,
            substitutability_assessed=substitutability,
            subcontracting_allowed=True,
            data_location_countries=("DE", "IE"),
            registered_at="2026-08-17T12:00:00Z",
        )

    def bundle(self, arrangement=None):
        return RegisterBundle(
            institution_id="bank-a",
            providers=(ICTProvider("bank-a", "provider-1", "Example Cloud", "IE"),),
            functions=(BusinessFunction("bank-a", "payments", "Payments", True, "owner-1"),),
            arrangements=(arrangement or self.arrangement(),),
        )

    def test_complete_critical_arrangement(self):
        report = RegisterValidator().validate(self.bundle(), validated_at="2026-08-17T12:01:00Z")
        self.assertTrue(report.structurally_complete)
        self.assertFalse(report.regulatory_compliance_determined)
        self.assertIn("subcontracting_dependency_requires_later_chain_analysis", report.warning_codes)

    def test_missing_exit_plan_fails_structural_completeness(self):
        report = RegisterValidator().validate(self.bundle(self.arrangement(exit_plan=False)), validated_at="2026-08-17T12:01:00Z")
        self.assertFalse(report.structurally_complete)
        self.assertIn("critical_arrangement_exit_plan_missing", report.error_codes)

    def test_missing_provider_reference_fails(self):
        bad = ICTArrangement(
            institution_id="bank-a", arrangement_id="arr-x", provider_id="missing", function_id="payments", service_type="service",
            contract_reference_digest=hashlib.sha256(b"x").hexdigest(), supports_critical_or_important_function=True,
            exit_plan_documented=True, substitutability_assessed=True, subcontracting_allowed=False,
            data_location_countries=("DE",), registered_at="2026-08-17T12:00:00Z")
        report = RegisterValidator().validate(self.bundle(bad), validated_at="2026-08-17T12:01:00Z")
        self.assertIn("arrangement_provider_reference_missing", report.error_codes)


if __name__ == "__main__":
    unittest.main()
