from __future__ import annotations

from typing import Iterable

from .continuity import (
    ContinuityAssessment,
    ContinuityExercisePlan,
    ContinuityFinding,
    ContinuityRemediationEvidence,
    ContinuityResolution,
    ContinuityRetestEvidence,
    RecoveryAssessmentState,
    resolve_continuity as _resolve_continuity,
)
from .inventory import GovernanceError


def resolve_continuity(
    plan: ContinuityExercisePlan,
    assessment: ContinuityAssessment,
    findings: Iterable[ContinuityFinding] = (),
    remediations: Iterable[ContinuityRemediationEvidence] = (),
    retests: Iterable[ContinuityRetestEvidence] = (),
) -> ContinuityResolution:
    """Resolve continuity lifecycle evidence with strict assessment/finding consistency."""
    finding_tuple = tuple(findings)
    remediation_tuple = tuple(remediations)
    retest_tuple = tuple(retests)
    if assessment.state is RecoveryAssessmentState.MET and finding_tuple:
        raise GovernanceError("met continuity assessment cannot carry continuity findings")
    return _resolve_continuity(
        plan,
        assessment,
        finding_tuple,
        remediation_tuple,
        retest_tuple,
    )
