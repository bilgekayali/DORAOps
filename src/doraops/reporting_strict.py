from __future__ import annotations

from .inventory import GovernanceError
from .reporting import (
    IncidentReportingRegistry as _IncidentReportingRegistry,
    ReportingApplicabilityDecision,
)
from .incidents import IncidentClassificationReview


class IncidentReportingRegistry(_IncidentReportingRegistry):
    """Strict public registry preserving applicability identity across versions."""

    def register_applicability(
        self,
        decision: ReportingApplicabilityDecision,
        review: IncidentClassificationReview,
    ) -> str:
        history = self._decisions.get((decision.entity_id, decision.incident_id), [])
        if history and decision.decision_id != history[0].decision_id:
            raise GovernanceError("reporting applicability decision_id must remain stable across versions")
        return super().register_applicability(decision, review)
