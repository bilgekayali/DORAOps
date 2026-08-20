from __future__ import annotations

from .dossier import DossierArtifactState, GovernanceDossier
from .dossier_strict import GovernanceDossierBuilder as _GovernanceDossierBuilder
from .incidents import IncidentClassificationReview
from .inventory import GovernanceError
from .reporting import (
    IncidentReportingRegistry,
    IncidentReportingRoute,
    ReportingApplicabilityDecision,
    ReportingWorkflowAssessment,
    ReportingWorkflowState,
    assess_reporting_workflow,
)
from .reporting_audit import (
    applicability_history,
    authority_acknowledgements,
    deadline_adjustment_history,
    delay_notification_history,
    package_history,
    reporting_routes,
    submission_receipts,
)


class GovernanceDossierBuilder(_GovernanceDossierBuilder):
    """Strict dossier builder extended with v0.3 incident-reporting evidence."""

    def add_incident_reporting(
        self,
        registry: IncidentReportingRegistry,
        *,
        decision: ReportingApplicabilityDecision,
        review: IncidentClassificationReview,
        route: IncidentReportingRoute | None,
        assessment: ReportingWorkflowAssessment,
    ) -> None:
        if not isinstance(registry, IncidentReportingRegistry):
            raise GovernanceError("dossier incident reporting requires IncidentReportingRegistry")
        if decision.entity_id != self.entity_id or review.entity_id != self.entity_id:
            raise GovernanceError("incident reporting evidence is outside dossier entity scope")
        if decision.incident_id != review.incident_id or decision.incident_id != assessment.incident_id:
            raise GovernanceError("incident reporting evidence crosses incident scope")
        if assessment.entity_id != self.entity_id:
            raise GovernanceError("incident reporting assessment is outside dossier entity scope")
        if route is not None and route.entity_id != self.entity_id:
            raise GovernanceError("incident reporting route is outside dossier entity scope")

        incident_review_key = ("incident", "classification_review", decision.incident_id)
        incident_review = self._artifacts.get(incident_review_key)
        if incident_review is None:
            raise GovernanceError("add_incident must add the exact classification review before incident reporting")
        if incident_review.digest != review.evidence_digest:
            raise GovernanceError("dossier classification review differs from incident reporting review")

        decision_history = applicability_history(
            registry,
            decision.entity_id,
            decision.incident_id,
        )
        if not decision_history:
            raise GovernanceError("incident reporting applicability history is missing")
        for item in decision_history:
            self._add(
                "incident_reporting",
                "applicability_decision",
                f"{item.decision_id}:v{item.decision_version}",
                item,
            )

        routes = reporting_routes(registry, self.entity_id)
        if route is not None and not routes:
            raise GovernanceError("incident reporting route history is missing")
        for item in routes:
            self._add(
                "incident_reporting",
                "reporting_route",
                f"{item.route_id}:v{item.version}",
                item,
            )

        for item in package_history(registry, decision.entity_id, decision.incident_id):
            self._add(
                "incident_reporting",
                "report_package",
                f"{item.report_type.value}:{item.sequence}:r{item.revision}",
                item,
            )
        for item in submission_receipts(registry, decision.entity_id, decision.incident_id):
            self._add(
                "incident_reporting",
                "submission_receipt",
                item.package_digest,
                item,
            )
        for item in authority_acknowledgements(registry, decision.entity_id, decision.incident_id):
            self._add(
                "incident_reporting",
                "authority_acknowledgement",
                item.receipt_digest,
                item,
            )
        for item in deadline_adjustment_history(registry, decision.entity_id, decision.incident_id):
            self._add(
                "incident_reporting",
                "deadline_adjustment",
                f"{item.report_type.value}:{item.sequence}",
                item,
            )
        for item in delay_notification_history(registry, decision.entity_id, decision.incident_id):
            self._add(
                "incident_reporting",
                "delay_notification",
                f"{item.report_type.value}:{item.sequence}",
                item,
            )

        assessment_state = DossierArtifactState.CURRENT
        assessment_findings: list[str] = []
        try:
            current = assess_reporting_workflow(
                registry,
                decision=decision,
                review=review,
                route=route,
                assessed_at=assessment.assessed_at,
            )
            if current.evidence_digest != assessment.evidence_digest:
                raise GovernanceError("incident reporting assessment is stale for current workflow evidence")
        except GovernanceError as exc:
            assessment_state = DossierArtifactState.REVALIDATION_REQUIRED
            assessment_findings.append(str(exc))
        else:
            if assessment.state in {
                ReportingWorkflowState.PENDING,
                ReportingWorkflowState.INCOMPLETE,
                ReportingWorkflowState.BREACHED,
            }:
                assessment_state = DossierArtifactState.WITH_GAPS
                assessment_findings.extend(
                    assessment.findings
                    or (f"reporting_workflow:{assessment.state.value}",)
                )
            elif assessment.state is ReportingWorkflowState.REVALIDATION_REQUIRED:
                assessment_state = DossierArtifactState.REVALIDATION_REQUIRED
                assessment_findings.extend(
                    assessment.findings
                    or ("incident_reporting_revalidation_required",)
                )

        self._add(
            "incident_reporting",
            "workflow_assessment",
            assessment.incident_id,
            assessment,
            state=assessment_state,
            findings=assessment_findings,
        )

    def build(self) -> GovernanceDossier:
        return super().build()
