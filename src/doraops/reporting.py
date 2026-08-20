from __future__ import annotations

from calendar import monthrange
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Iterable

from .canonical import sha256_digest
from .incidents import (
    HumanClassificationDecision,
    IncidentClassificationReview,
    IncidentEventType,
    IncidentRegistry,
)
from .inventory import GovernanceError

RTS_CONTENT_PROFILE = "EU-2025-301@2025-02-20"
ITS_TEMPLATE_PROFILE = "EU-2025-302-ANNEX-I@2025-02-20"
_INITIAL_CLASSIFICATION_SECONDS = 4 * 60 * 60
_INITIAL_AWARENESS_SECONDS = 24 * 60 * 60
_INTERMEDIATE_SECONDS = 72 * 60 * 60


class ReportingApplicability(str, Enum):
    APPLICABLE = "applicable"
    NOT_APPLICABLE = "not_applicable"


class SubmissionMode(str, Enum):
    DIRECT = "direct"
    OUTSOURCED = "outsourced"
    AGGREGATED = "aggregated"


class IncidentReportType(str, Enum):
    INITIAL = "initial_notification"
    INTERMEDIATE = "intermediate_report"
    FINAL = "final_report"
    RECLASSIFICATION = "reclassification_notification"


class SubmissionChannel(str, Enum):
    PORTAL = "portal"
    API = "api"
    EMAIL = "email"
    ALTERNATIVE = "alternative"
    OTHER = "other"


class AcknowledgementStatus(str, Enum):
    RECEIVED = "received"
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    TECHNICAL_ERROR = "technical_error"


class DeadlineBasis(str, Enum):
    INITIAL_CLASSIFICATION_4H = "initial_classification_4h"
    INITIAL_AWARENESS_24H = "initial_awareness_24h"
    INTERMEDIATE_72H = "intermediate_72h"
    RECOVERY_UPDATE_WITHOUT_UNDUE_DELAY = "recovery_update_without_undue_delay"
    FINAL_ONE_CALENDAR_MONTH = "final_one_calendar_month"


class ReportingWorkflowState(str, Enum):
    NOT_REQUIRED = "not_required"
    INCOMPLETE = "incomplete"
    PENDING = "pending"
    BREACHED = "breached"
    COMPLETE = "complete"
    REVALIDATION_REQUIRED = "revalidation_required"


def _text(name: str, value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise GovernanceError(f"{name} must be a non-empty string")
    return value.strip()


def _optional_text(name: str, value: str | None) -> str | None:
    if value is None:
        return None
    return _text(name, value)


def _digest(name: str, value: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(ch not in "0123456789abcdef" for ch in value)
    ):
        raise GovernanceError(f"{name} must be a lowercase SHA-256 digest")
    return value


def _optional_digest(name: str, value: str | None) -> str | None:
    if value is None:
        return None
    return _digest(name, value)


def _timestamp(name: str, value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise GovernanceError(f"{name} must be a non-negative integer timestamp")
    return value


def _positive_int(name: str, value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise GovernanceError(f"{name} must be a positive integer")
    return value


def _sorted_unique(values: Iterable[str]) -> tuple[str, ...]:
    result = tuple(sorted({_text("value", value) for value in values}))
    return result


def _add_calendar_month(timestamp: int) -> int:
    source = datetime.fromtimestamp(_timestamp("timestamp", timestamp), tz=timezone.utc)
    if source.month == 12:
        year, month = source.year + 1, 1
    else:
        year, month = source.year, source.month + 1
    day = min(source.day, monthrange(year, month)[1])
    target = source.replace(year=year, month=month, day=day)
    return int(target.timestamp())


@dataclass(frozen=True, slots=True)
class ReportingApplicabilityDecision:
    entity_id: str
    incident_id: str
    decision_id: str
    decision_version: int
    incident_evidence_snapshot_digest: str
    classification_review_digest: str
    applicability: ReportingApplicability
    decision_owner_id: str
    rationale_digest: str
    applicability_evidence_digest: str
    decided_at: int

    def __post_init__(self) -> None:
        for name in ("entity_id", "incident_id", "decision_id", "decision_owner_id"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        _positive_int("decision_version", self.decision_version)
        for name in (
            "incident_evidence_snapshot_digest",
            "classification_review_digest",
            "rationale_digest",
            "applicability_evidence_digest",
        ):
            _digest(name, getattr(self, name))
        if not isinstance(self.applicability, ReportingApplicability):
            raise GovernanceError("reporting applicability must use a governed value")
        _timestamp("decided_at", self.decided_at)

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class IncidentReportingRoute:
    entity_id: str
    route_id: str
    version: int
    competent_authority_id: str
    member_state: str
    submission_mode: SubmissionMode
    submitter_id: str
    contact_evidence_digest: str
    outsourcing_evidence_digest: str | None
    authority_permission_evidence_digest: str | None
    aggregation_scope_evidence_digest: str | None
    registered_at: int

    def __post_init__(self) -> None:
        for name in (
            "entity_id",
            "route_id",
            "competent_authority_id",
            "member_state",
            "submitter_id",
        ):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        _positive_int("route version", self.version)
        _digest("contact_evidence_digest", self.contact_evidence_digest)
        _optional_digest("outsourcing_evidence_digest", self.outsourcing_evidence_digest)
        _optional_digest("authority_permission_evidence_digest", self.authority_permission_evidence_digest)
        _optional_digest("aggregation_scope_evidence_digest", self.aggregation_scope_evidence_digest)
        _timestamp("registered_at", self.registered_at)
        if not isinstance(self.submission_mode, SubmissionMode):
            raise GovernanceError("submission mode must use a governed value")
        if self.submission_mode is SubmissionMode.DIRECT:
            if self.submitter_id != self.entity_id:
                raise GovernanceError("direct reporting submitter must be the governed entity")
            if any(
                value is not None
                for value in (
                    self.outsourcing_evidence_digest,
                    self.authority_permission_evidence_digest,
                    self.aggregation_scope_evidence_digest,
                )
            ):
                raise GovernanceError("direct reporting route must not carry outsourcing or aggregation evidence")
        elif self.submission_mode is SubmissionMode.OUTSOURCED:
            if self.submitter_id == self.entity_id:
                raise GovernanceError("outsourced reporting must identify a distinct submitter")
            if self.outsourcing_evidence_digest is None:
                raise GovernanceError("outsourced reporting requires outsourcing evidence")
            if self.authority_permission_evidence_digest is not None or self.aggregation_scope_evidence_digest is not None:
                raise GovernanceError("non-aggregated outsourced route must not carry aggregation evidence")
        else:
            if self.submitter_id == self.entity_id:
                raise GovernanceError("aggregated reporting must identify a distinct third-party submitter")
            if self.outsourcing_evidence_digest is None:
                raise GovernanceError("aggregated reporting requires outsourcing evidence")
            if self.authority_permission_evidence_digest is None:
                raise GovernanceError("aggregated reporting requires competent-authority permission evidence")
            if self.aggregation_scope_evidence_digest is None:
                raise GovernanceError("aggregated reporting requires aggregation-scope evidence")

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class IncidentReportPackage:
    entity_id: str
    incident_id: str
    report_type: IncidentReportType
    sequence: int
    revision: int
    incident_evidence_snapshot_digest: str
    classification_review_digest: str
    applicability_decision_digest: str
    route_digest: str
    rts_content_profile: str
    its_template_profile: str
    required_content_evidence_digest: str
    report_payload_digest: str
    prepared_by_id: str
    prepared_at: int
    supersedes_package_digest: str | None = None

    def __post_init__(self) -> None:
        for name in ("entity_id", "incident_id", "prepared_by_id"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        if not isinstance(self.report_type, IncidentReportType):
            raise GovernanceError("report type must use a governed value")
        _positive_int("report sequence", self.sequence)
        _positive_int("report revision", self.revision)
        if self.report_type is not IncidentReportType.INTERMEDIATE and self.sequence != 1:
            raise GovernanceError("only intermediate reports may use a sequence greater than one")
        for name in (
            "incident_evidence_snapshot_digest",
            "classification_review_digest",
            "applicability_decision_digest",
            "route_digest",
            "required_content_evidence_digest",
            "report_payload_digest",
        ):
            _digest(name, getattr(self, name))
        if self.rts_content_profile != RTS_CONTENT_PROFILE:
            raise GovernanceError("incident report package must use the pinned v0.3 RTS content profile")
        if self.its_template_profile != ITS_TEMPLATE_PROFILE:
            raise GovernanceError("incident report package must use the pinned v0.3 ITS template profile")
        _timestamp("prepared_at", self.prepared_at)
        if self.revision == 1:
            if self.supersedes_package_digest is not None:
                raise GovernanceError("first report revision must not supersede another package")
        else:
            _digest("supersedes_package_digest", self.supersedes_package_digest or "")

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class SubmissionReceiptEvidence:
    entity_id: str
    incident_id: str
    report_type: IncidentReportType
    sequence: int
    package_digest: str
    submitted_at: int
    channel: SubmissionChannel
    external_submission_evidence_digest: str
    authority_reference: str | None = None
    technical_impossibility_evidence_digest: str | None = None

    def __post_init__(self) -> None:
        for name in ("entity_id", "incident_id"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        if not isinstance(self.report_type, IncidentReportType):
            raise GovernanceError("receipt report type must use a governed value")
        _positive_int("receipt sequence", self.sequence)
        _digest("package_digest", self.package_digest)
        _timestamp("submitted_at", self.submitted_at)
        if not isinstance(self.channel, SubmissionChannel):
            raise GovernanceError("submission channel must use a governed value")
        _digest("external_submission_evidence_digest", self.external_submission_evidence_digest)
        object.__setattr__(self, "authority_reference", _optional_text("authority_reference", self.authority_reference))
        _optional_digest("technical_impossibility_evidence_digest", self.technical_impossibility_evidence_digest)
        if self.channel is SubmissionChannel.ALTERNATIVE:
            if self.technical_impossibility_evidence_digest is None:
                raise GovernanceError("alternative submission requires technical-impossibility evidence")
        elif self.technical_impossibility_evidence_digest is not None:
            raise GovernanceError("technical-impossibility evidence is only valid for alternative submission")

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class AuthorityAcknowledgementEvidence:
    entity_id: str
    incident_id: str
    receipt_digest: str
    status: AcknowledgementStatus
    acknowledged_at: int
    authority_reference: str
    acknowledgement_evidence_digest: str

    def __post_init__(self) -> None:
        for name in ("entity_id", "incident_id", "authority_reference"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        _digest("receipt_digest", self.receipt_digest)
        if not isinstance(self.status, AcknowledgementStatus):
            raise GovernanceError("acknowledgement status must use a governed value")
        _timestamp("acknowledged_at", self.acknowledged_at)
        _digest("acknowledgement_evidence_digest", self.acknowledgement_evidence_digest)

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class DeadlineAdjustmentEvidence:
    entity_id: str
    incident_id: str
    report_type: IncidentReportType
    sequence: int
    original_due_at: int
    adjusted_due_at: int
    reason: str
    approved_by_id: str
    calendar_evidence_digest: str

    def __post_init__(self) -> None:
        for name in ("entity_id", "incident_id", "approved_by_id"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        if not isinstance(self.report_type, IncidentReportType):
            raise GovernanceError("deadline adjustment report type must use a governed value")
        _positive_int("deadline adjustment sequence", self.sequence)
        _timestamp("original_due_at", self.original_due_at)
        _timestamp("adjusted_due_at", self.adjusted_due_at)
        if self.adjusted_due_at <= self.original_due_at:
            raise GovernanceError("adjusted deadline must be later than original deadline")
        if self.reason != "weekend_or_bank_holiday":
            raise GovernanceError("v0.3 deadline adjustment supports only weekend_or_bank_holiday evidence")
        _digest("calendar_evidence_digest", self.calendar_evidence_digest)

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class DelayNotificationEvidence:
    entity_id: str
    incident_id: str
    report_type: IncidentReportType
    sequence: int
    due_at: int
    notified_at: int
    reason_evidence_digest: str
    authority_notification_evidence_digest: str

    def __post_init__(self) -> None:
        for name in ("entity_id", "incident_id"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        if not isinstance(self.report_type, IncidentReportType):
            raise GovernanceError("delay notification report type must use a governed value")
        _positive_int("delay notification sequence", self.sequence)
        _timestamp("due_at", self.due_at)
        _timestamp("notified_at", self.notified_at)
        if self.notified_at > self.due_at:
            raise GovernanceError("delay notification must be recorded no later than the represented report deadline")
        _digest("reason_evidence_digest", self.reason_evidence_digest)
        _digest("authority_notification_evidence_digest", self.authority_notification_evidence_digest)

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class ReportingDeadline:
    entity_id: str
    incident_id: str
    report_type: IncidentReportType
    sequence: int
    basis: DeadlineBasis
    triggered_at: int
    statutory_due_at: int | None
    effective_due_at: int | None
    adjustment_digest: str | None

    def __post_init__(self) -> None:
        for name in ("entity_id", "incident_id"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        if not isinstance(self.report_type, IncidentReportType):
            raise GovernanceError("deadline report type must use a governed value")
        _positive_int("deadline sequence", self.sequence)
        if not isinstance(self.basis, DeadlineBasis):
            raise GovernanceError("deadline basis must use a governed value")
        _timestamp("triggered_at", self.triggered_at)
        if self.basis is DeadlineBasis.RECOVERY_UPDATE_WITHOUT_UNDUE_DELAY:
            if self.statutory_due_at is not None or self.effective_due_at is not None or self.adjustment_digest is not None:
                raise GovernanceError("without-undue-delay requirement must not fabricate a numeric due time")
        else:
            _timestamp("statutory_due_at", self.statutory_due_at if self.statutory_due_at is not None else -1)
            _timestamp("effective_due_at", self.effective_due_at if self.effective_due_at is not None else -1)
            if self.effective_due_at is not None and self.statutory_due_at is not None and self.effective_due_at < self.statutory_due_at:
                raise GovernanceError("effective deadline cannot precede statutory deadline")
            if self.adjustment_digest is None:
                if self.effective_due_at != self.statutory_due_at:
                    raise GovernanceError("unadjusted deadline effective time must equal statutory time")
            else:
                _digest("adjustment_digest", self.adjustment_digest)

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


@dataclass(frozen=True, slots=True)
class ReportingWorkflowAssessment:
    entity_id: str
    incident_id: str
    incident_evidence_snapshot_digest: str
    classification_review_digest: str
    applicability_decision_digest: str
    route_digest: str | None
    assessed_at: int
    state: ReportingWorkflowState
    deadlines: tuple[ReportingDeadline, ...]
    latest_package_digests: tuple[str, ...]
    latest_receipt_digests: tuple[str, ...]
    findings: tuple[str, ...]
    regulatory_compliance_determined: bool = False
    authority_acceptance_determined: bool = False

    def __post_init__(self) -> None:
        for name in ("entity_id", "incident_id"):
            object.__setattr__(self, name, _text(name, getattr(self, name)))
        for name in (
            "incident_evidence_snapshot_digest",
            "classification_review_digest",
            "applicability_decision_digest",
        ):
            _digest(name, getattr(self, name))
        _optional_digest("route_digest", self.route_digest)
        _timestamp("assessed_at", self.assessed_at)
        if not isinstance(self.state, ReportingWorkflowState):
            raise GovernanceError("reporting workflow state must use a governed value")
        package_digests = tuple(self.latest_package_digests)
        receipt_digests = tuple(self.latest_receipt_digests)
        for value in package_digests:
            _digest("latest_package_digest", value)
        for value in receipt_digests:
            _digest("latest_receipt_digest", value)
        if len(package_digests) != len(set(package_digests)):
            raise GovernanceError("latest package digests must be unique")
        if len(receipt_digests) != len(set(receipt_digests)):
            raise GovernanceError("latest receipt digests must be unique")
        object.__setattr__(self, "findings", _sorted_unique(self.findings))
        if self.regulatory_compliance_determined is not False:
            raise GovernanceError("reporting workflow assessment cannot determine regulatory compliance")
        if self.authority_acceptance_determined is not False:
            raise GovernanceError("reporting workflow assessment cannot determine competent-authority acceptance")

    @property
    def evidence_digest(self) -> str:
        return sha256_digest(self)


class IncidentReportingRegistry:
    """Offline append-only incident-reporting evidence registry; it performs no external submission."""

    def __init__(self, incidents: IncidentRegistry) -> None:
        if not isinstance(incidents, IncidentRegistry):
            raise GovernanceError("incident reporting registry requires IncidentRegistry")
        self._incidents = incidents
        self._decisions: dict[tuple[str, str], list[ReportingApplicabilityDecision]] = {}
        self._routes: dict[tuple[str, str], list[IncidentReportingRoute]] = {}
        self._packages: dict[
            tuple[str, str, IncidentReportType, int], list[IncidentReportPackage]
        ] = {}
        self._receipts: dict[str, SubmissionReceiptEvidence] = {}
        self._acknowledgements: dict[str, AuthorityAcknowledgementEvidence] = {}
        self._adjustments: dict[
            tuple[str, str, IncidentReportType, int], DeadlineAdjustmentEvidence
        ] = {}
        self._delay_notifications: dict[
            tuple[str, str, IncidentReportType, int], DelayNotificationEvidence
        ] = {}

    def register_applicability(
        self,
        decision: ReportingApplicabilityDecision,
        review: IncidentClassificationReview,
    ) -> str:
        key = (decision.entity_id, decision.incident_id)
        history = self._decisions.setdefault(key, [])
        for existing in history:
            if existing.decision_version == decision.decision_version:
                if existing.evidence_digest != decision.evidence_digest:
                    raise GovernanceError("reporting applicability decision version is immutable")
                return existing.evidence_digest
        incident = self._incidents.incident(*key)
        current_snapshot = self._incidents.evidence_snapshot_digest(*key)
        if review.entity_id != decision.entity_id or review.incident_id != decision.incident_id:
            raise GovernanceError("reporting applicability review is outside incident scope")
        if review.evidence_digest != decision.classification_review_digest:
            raise GovernanceError("reporting applicability does not bind exact classification review")
        if review.incident_evidence_snapshot_digest != decision.incident_evidence_snapshot_digest:
            raise GovernanceError("reporting applicability review/snapshot binding disagrees")
        if decision.incident_evidence_snapshot_digest != current_snapshot:
            raise GovernanceError("reporting applicability is stale for current incident evidence")
        if decision.decided_at < review.reviewed_at or decision.decided_at < incident.detected_at:
            raise GovernanceError("reporting applicability decision chronology is invalid")
        expected_version = len(history) + 1
        if decision.decision_version != expected_version:
            raise GovernanceError("reporting applicability versions must be contiguous")
        if history and decision.decided_at <= history[-1].decided_at:
            raise GovernanceError("new reporting applicability decision must advance decided_at")
        history.append(decision)
        return decision.evidence_digest

    def register_route(self, route: IncidentReportingRoute) -> str:
        key = (route.entity_id, route.route_id)
        history = self._routes.setdefault(key, [])
        for existing in history:
            if existing.version == route.version:
                if existing.evidence_digest != route.evidence_digest:
                    raise GovernanceError("incident reporting route version is immutable")
                return existing.evidence_digest
        expected = len(history) + 1
        if route.version != expected:
            raise GovernanceError("incident reporting route versions must be contiguous")
        if history and route.registered_at <= history[-1].registered_at:
            raise GovernanceError("new incident reporting route must advance registered_at")
        history.append(route)
        return route.evidence_digest

    def current_applicability(self, entity_id: str, incident_id: str) -> ReportingApplicabilityDecision:
        history = self._decisions.get((entity_id, incident_id), [])
        if not history:
            raise GovernanceError("no reporting applicability decision is registered")
        return history[-1]

    def current_route(self, entity_id: str, route_id: str) -> IncidentReportingRoute:
        history = self._routes.get((entity_id, route_id), [])
        if not history:
            raise GovernanceError("unknown incident reporting route")
        return history[-1]

    def assert_applicability_current(
        self,
        decision: ReportingApplicabilityDecision,
        review: IncidentClassificationReview,
    ) -> None:
        if self.current_applicability(decision.entity_id, decision.incident_id).evidence_digest != decision.evidence_digest:
            raise GovernanceError("reporting applicability decision is not current")
        current_snapshot = self._incidents.evidence_snapshot_digest(decision.entity_id, decision.incident_id)
        if decision.incident_evidence_snapshot_digest != current_snapshot:
            raise GovernanceError("reporting applicability is stale for current incident evidence")
        if decision.classification_review_digest != review.evidence_digest:
            raise GovernanceError("reporting applicability is stale for current classification review")
        if review.incident_evidence_snapshot_digest != current_snapshot:
            raise GovernanceError("classification review is stale for current incident evidence")

    def assert_route_current(self, route: IncidentReportingRoute) -> None:
        if self.current_route(route.entity_id, route.route_id).evidence_digest != route.evidence_digest:
            raise GovernanceError("incident reporting route is not current")

    def register_package(
        self,
        package: IncidentReportPackage,
        *,
        decision: ReportingApplicabilityDecision,
        review: IncidentClassificationReview,
        route: IncidentReportingRoute,
    ) -> str:
        key = (package.entity_id, package.incident_id, package.report_type, package.sequence)
        revisions = self._packages.setdefault(key, [])
        for existing in revisions:
            if existing.revision == package.revision:
                if existing.evidence_digest != package.evidence_digest:
                    raise GovernanceError("incident report package revision is immutable")
                return existing.evidence_digest

        self.assert_applicability_current(decision, review)
        self.assert_route_current(route)
        if decision.applicability is not ReportingApplicability.APPLICABLE:
            raise GovernanceError("non-applicable incident cannot produce DORA major-incident report package")
        if route.entity_id != package.entity_id or decision.entity_id != package.entity_id:
            raise GovernanceError("incident report package crosses entity scope")
        if decision.incident_id != package.incident_id or review.incident_id != package.incident_id:
            raise GovernanceError("incident report package crosses incident scope")
        if package.incident_evidence_snapshot_digest != decision.incident_evidence_snapshot_digest:
            raise GovernanceError("incident report package is stale for reporting applicability evidence")
        if package.classification_review_digest != review.evidence_digest:
            raise GovernanceError("incident report package does not bind current classification review")
        if package.applicability_decision_digest != decision.evidence_digest:
            raise GovernanceError("incident report package does not bind current applicability decision")
        if package.route_digest != route.evidence_digest:
            raise GovernanceError("incident report package does not bind current reporting route")
        if package.prepared_at < max(decision.decided_at, review.reviewed_at, route.registered_at):
            raise GovernanceError("incident report package predates bound governance evidence")

        if package.report_type is IncidentReportType.RECLASSIFICATION:
            if review.decision is not HumanClassificationDecision.NON_MAJOR:
                raise GovernanceError("reclassification notification requires current non-major human review")
            if not self.receipts(package.entity_id, package.incident_id, IncidentReportType.INITIAL):
                raise GovernanceError("reclassification notification requires prior initial submission evidence")
        else:
            if review.decision is not HumanClassificationDecision.MAJOR:
                raise GovernanceError("major-incident reporting package requires current major human classification")

        expected_revision = len(revisions) + 1
        if package.revision != expected_revision:
            raise GovernanceError("incident report package revisions must be contiguous")
        if package.revision > 1:
            previous = revisions[-1]
            if package.supersedes_package_digest != previous.evidence_digest:
                raise GovernanceError("report package revision must supersede exact previous revision")
            if package.prepared_at <= previous.prepared_at:
                raise GovernanceError("new report package revision must advance prepared_at")

        if package.report_type is IncidentReportType.INTERMEDIATE and package.sequence > 1:
            previous_receipts = self.receipts(
                package.entity_id,
                package.incident_id,
                IncidentReportType.INTERMEDIATE,
                sequence=package.sequence - 1,
            )
            if not previous_receipts:
                raise GovernanceError("intermediate update requires prior intermediate submission evidence")
        if package.report_type is IncidentReportType.FINAL:
            if not self.receipts(package.entity_id, package.incident_id, IncidentReportType.INTERMEDIATE):
                raise GovernanceError("final report requires prior intermediate submission evidence")

        revisions.append(package)
        return package.evidence_digest

    def register_receipt(self, receipt: SubmissionReceiptEvidence) -> str:
        package = self.package_by_digest(receipt.package_digest)
        if (
            package.entity_id != receipt.entity_id
            or package.incident_id != receipt.incident_id
            or package.report_type is not receipt.report_type
            or package.sequence != receipt.sequence
        ):
            raise GovernanceError("submission receipt does not bind the represented report package identity")
        existing = self._receipts.get(receipt.package_digest)
        if existing is not None:
            if existing.evidence_digest != receipt.evidence_digest:
                raise GovernanceError("report package already has different submission receipt evidence")
            return existing.evidence_digest
        if receipt.submitted_at < package.prepared_at:
            raise GovernanceError("report submission cannot predate package preparation")
        self._receipts[receipt.package_digest] = receipt
        return receipt.evidence_digest

    def register_acknowledgement(self, acknowledgement: AuthorityAcknowledgementEvidence) -> str:
        receipt = self.receipt_by_digest(acknowledgement.receipt_digest)
        if receipt.entity_id != acknowledgement.entity_id or receipt.incident_id != acknowledgement.incident_id:
            raise GovernanceError("authority acknowledgement crosses incident scope")
        existing = self._acknowledgements.get(acknowledgement.receipt_digest)
        if existing is not None:
            if existing.evidence_digest != acknowledgement.evidence_digest:
                raise GovernanceError("submission receipt already has different authority acknowledgement")
            return existing.evidence_digest
        if acknowledgement.acknowledged_at < receipt.submitted_at:
            raise GovernanceError("authority acknowledgement cannot predate represented submission")
        self._acknowledgements[acknowledgement.receipt_digest] = acknowledgement
        return acknowledgement.evidence_digest

    def register_deadline_adjustment(self, adjustment: DeadlineAdjustmentEvidence) -> str:
        key = (adjustment.entity_id, adjustment.incident_id, adjustment.report_type, adjustment.sequence)
        existing = self._adjustments.get(key)
        if existing is not None:
            if existing.evidence_digest != adjustment.evidence_digest:
                raise GovernanceError("report deadline adjustment identity is immutable")
            return existing.evidence_digest
        self._adjustments[key] = adjustment
        return adjustment.evidence_digest

    def register_delay_notification(self, notification: DelayNotificationEvidence) -> str:
        key = (notification.entity_id, notification.incident_id, notification.report_type, notification.sequence)
        existing = self._delay_notifications.get(key)
        if existing is not None:
            if existing.evidence_digest != notification.evidence_digest:
                raise GovernanceError("report delay notification identity is immutable")
            return existing.evidence_digest
        self._delay_notifications[key] = notification
        return notification.evidence_digest

    def packages(
        self,
        entity_id: str,
        incident_id: str,
        report_type: IncidentReportType | None = None,
    ) -> tuple[IncidentReportPackage, ...]:
        values = [
            revisions[-1]
            for (entity, incident, kind, _sequence), revisions in self._packages.items()
            if entity == entity_id and incident == incident_id and (report_type is None or kind is report_type)
        ]
        return tuple(sorted(values, key=lambda item: (_report_order(item.report_type), item.sequence)))

    def package_revisions(
        self,
        entity_id: str,
        incident_id: str,
        report_type: IncidentReportType,
        sequence: int,
    ) -> tuple[IncidentReportPackage, ...]:
        return tuple(self._packages.get((entity_id, incident_id, report_type, sequence), ()))

    def package_by_digest(self, package_digest: str) -> IncidentReportPackage:
        _digest("package_digest", package_digest)
        for revisions in self._packages.values():
            for package in revisions:
                if package.evidence_digest == package_digest:
                    return package
        raise GovernanceError("unknown incident report package digest")

    def receipts(
        self,
        entity_id: str,
        incident_id: str,
        report_type: IncidentReportType | None = None,
        *,
        sequence: int | None = None,
    ) -> tuple[SubmissionReceiptEvidence, ...]:
        result: list[SubmissionReceiptEvidence] = []
        for package in self.packages(entity_id, incident_id, report_type):
            if sequence is not None and package.sequence != sequence:
                continue
            receipt = self._receipts.get(package.evidence_digest)
            if receipt is not None:
                result.append(receipt)
        return tuple(sorted(result, key=lambda item: (_report_order(item.report_type), item.sequence, item.submitted_at)))

    def receipt_by_digest(self, receipt_digest: str) -> SubmissionReceiptEvidence:
        _digest("receipt_digest", receipt_digest)
        for receipt in self._receipts.values():
            if receipt.evidence_digest == receipt_digest:
                return receipt
        raise GovernanceError("unknown submission receipt digest")

    def acknowledgement_for(self, receipt: SubmissionReceiptEvidence) -> AuthorityAcknowledgementEvidence | None:
        return self._acknowledgements.get(receipt.evidence_digest)

    def acknowledgements(self, entity_id: str, incident_id: str) -> tuple[AuthorityAcknowledgementEvidence, ...]:
        result = [
            acknowledgement
            for acknowledgement in self._acknowledgements.values()
            if acknowledgement.entity_id == entity_id and acknowledgement.incident_id == incident_id
        ]
        return tuple(sorted(result, key=lambda item: item.acknowledged_at))

    def deadline_adjustments(self, entity_id: str, incident_id: str) -> tuple[DeadlineAdjustmentEvidence, ...]:
        result = [
            value
            for key, value in self._adjustments.items()
            if key[0] == entity_id and key[1] == incident_id
        ]
        return tuple(sorted(result, key=lambda item: (_report_order(item.report_type), item.sequence)))

    def delay_notifications(self, entity_id: str, incident_id: str) -> tuple[DelayNotificationEvidence, ...]:
        result = [
            value
            for key, value in self._delay_notifications.items()
            if key[0] == entity_id and key[1] == incident_id
        ]
        return tuple(sorted(result, key=lambda item: (_report_order(item.report_type), item.sequence)))

    def _adjustment(
        self,
        entity_id: str,
        incident_id: str,
        report_type: IncidentReportType,
        sequence: int,
    ) -> DeadlineAdjustmentEvidence | None:
        return self._adjustments.get((entity_id, incident_id, report_type, sequence))

    def _delay_notification(
        self,
        entity_id: str,
        incident_id: str,
        report_type: IncidentReportType,
        sequence: int,
    ) -> DelayNotificationEvidence | None:
        return self._delay_notifications.get((entity_id, incident_id, report_type, sequence))


def _report_order(report_type: IncidentReportType) -> int:
    return {
        IncidentReportType.INITIAL: 1,
        IncidentReportType.INTERMEDIATE: 2,
        IncidentReportType.FINAL: 3,
        IncidentReportType.RECLASSIFICATION: 4,
    }[report_type]


def _deadline(
    registry: IncidentReportingRegistry,
    *,
    entity_id: str,
    incident_id: str,
    report_type: IncidentReportType,
    sequence: int,
    basis: DeadlineBasis,
    triggered_at: int,
    statutory_due_at: int | None,
) -> ReportingDeadline:
    if statutory_due_at is None:
        return ReportingDeadline(
            entity_id=entity_id,
            incident_id=incident_id,
            report_type=report_type,
            sequence=sequence,
            basis=basis,
            triggered_at=triggered_at,
            statutory_due_at=None,
            effective_due_at=None,
            adjustment_digest=None,
        )
    adjustment = registry._adjustment(entity_id, incident_id, report_type, sequence)
    if adjustment is None:
        effective = statutory_due_at
        adjustment_digest = None
    else:
        if adjustment.original_due_at != statutory_due_at:
            raise GovernanceError("deadline adjustment is stale for current statutory deadline")
        effective = adjustment.adjusted_due_at
        adjustment_digest = adjustment.evidence_digest
    return ReportingDeadline(
        entity_id=entity_id,
        incident_id=incident_id,
        report_type=report_type,
        sequence=sequence,
        basis=basis,
        triggered_at=triggered_at,
        statutory_due_at=statutory_due_at,
        effective_due_at=effective,
        adjustment_digest=adjustment_digest,
    )


def _initial_deadline(
    registry: IncidentReportingRegistry,
    review: IncidentClassificationReview,
) -> ReportingDeadline:
    incident = registry._incidents.incident(review.entity_id, review.incident_id)
    awareness_cap = incident.detected_at + _INITIAL_AWARENESS_SECONDS
    classification_due = review.reviewed_at + _INITIAL_CLASSIFICATION_SECONDS
    if review.reviewed_at > awareness_cap:
        statutory_due = classification_due
        basis = DeadlineBasis.INITIAL_CLASSIFICATION_4H
    elif classification_due <= awareness_cap:
        statutory_due = classification_due
        basis = DeadlineBasis.INITIAL_CLASSIFICATION_4H
    else:
        statutory_due = awareness_cap
        basis = DeadlineBasis.INITIAL_AWARENESS_24H
    return _deadline(
        registry,
        entity_id=review.entity_id,
        incident_id=review.incident_id,
        report_type=IncidentReportType.INITIAL,
        sequence=1,
        basis=basis,
        triggered_at=review.reviewed_at,
        statutory_due_at=statutory_due,
    )


def _latest_receipt_for(
    registry: IncidentReportingRegistry,
    entity_id: str,
    incident_id: str,
    report_type: IncidentReportType,
) -> SubmissionReceiptEvidence | None:
    receipts = registry.receipts(entity_id, incident_id, report_type)
    return receipts[-1] if receipts else None


def _deadline_finding(
    registry: IncidentReportingRegistry,
    deadline: ReportingDeadline,
    receipt: SubmissionReceiptEvidence | None,
    assessed_at: int,
) -> tuple[str | None, bool, bool]:
    if deadline.effective_due_at is None:
        return None, False, False
    if receipt is None:
        if assessed_at <= deadline.effective_due_at:
            return f"{deadline.report_type.value}:{deadline.sequence}:pending", False, True
        late = True
    else:
        if receipt.submitted_at <= deadline.effective_due_at:
            return None, False, False
        late = True
    notification = registry._delay_notification(
        deadline.entity_id,
        deadline.incident_id,
        deadline.report_type,
        deadline.sequence,
    )
    if notification is not None:
        if notification.due_at != deadline.effective_due_at:
            raise GovernanceError("delay notification is stale for current effective deadline")
        return f"{deadline.report_type.value}:{deadline.sequence}:deadline_breached_with_timely_delay_notice", late, False
    return f"{deadline.report_type.value}:{deadline.sequence}:deadline_breached", late, False


def assess_reporting_workflow(
    registry: IncidentReportingRegistry,
    *,
    decision: ReportingApplicabilityDecision,
    review: IncidentClassificationReview,
    route: IncidentReportingRoute | None,
    assessed_at: int,
) -> ReportingWorkflowAssessment:
    _timestamp("assessed_at", assessed_at)
    incident = registry._incidents.incident(decision.entity_id, decision.incident_id)
    current_snapshot = registry._incidents.evidence_snapshot_digest(decision.entity_id, decision.incident_id)
    route_digest = None if route is None else route.evidence_digest

    try:
        registry.assert_applicability_current(decision, review)
        if decision.applicability is ReportingApplicability.APPLICABLE:
            if route is None:
                raise GovernanceError("applicable incident requires current reporting route")
            registry.assert_route_current(route)
            if route.entity_id != decision.entity_id:
                raise GovernanceError("reporting route is outside incident entity scope")
    except GovernanceError as exc:
        return ReportingWorkflowAssessment(
            entity_id=decision.entity_id,
            incident_id=decision.incident_id,
            incident_evidence_snapshot_digest=current_snapshot,
            classification_review_digest=review.evidence_digest,
            applicability_decision_digest=decision.evidence_digest,
            route_digest=route_digest,
            assessed_at=assessed_at,
            state=ReportingWorkflowState.REVALIDATION_REQUIRED,
            deadlines=(),
            latest_package_digests=tuple(item.evidence_digest for item in registry.packages(decision.entity_id, decision.incident_id)),
            latest_receipt_digests=tuple(item.evidence_digest for item in registry.receipts(decision.entity_id, decision.incident_id)),
            findings=(str(exc),),
        )

    packages = registry.packages(decision.entity_id, decision.incident_id)
    receipts = registry.receipts(decision.entity_id, decision.incident_id)
    package_digests = tuple(item.evidence_digest for item in packages)
    receipt_digests = tuple(item.evidence_digest for item in receipts)

    if decision.applicability is ReportingApplicability.NOT_APPLICABLE:
        return ReportingWorkflowAssessment(
            entity_id=decision.entity_id,
            incident_id=decision.incident_id,
            incident_evidence_snapshot_digest=current_snapshot,
            classification_review_digest=review.evidence_digest,
            applicability_decision_digest=decision.evidence_digest,
            route_digest=None,
            assessed_at=assessed_at,
            state=ReportingWorkflowState.NOT_REQUIRED,
            deadlines=(),
            latest_package_digests=package_digests,
            latest_receipt_digests=receipt_digests,
            findings=(),
        )

    if review.decision is HumanClassificationDecision.UNDETERMINED:
        return ReportingWorkflowAssessment(
            entity_id=decision.entity_id,
            incident_id=decision.incident_id,
            incident_evidence_snapshot_digest=current_snapshot,
            classification_review_digest=review.evidence_digest,
            applicability_decision_digest=decision.evidence_digest,
            route_digest=route_digest,
            assessed_at=assessed_at,
            state=ReportingWorkflowState.INCOMPLETE,
            deadlines=(),
            latest_package_digests=package_digests,
            latest_receipt_digests=receipt_digests,
            findings=("major_incident_classification_undetermined",),
        )

    if review.decision is HumanClassificationDecision.NON_MAJOR:
        initial_receipts = registry.receipts(
            decision.entity_id,
            decision.incident_id,
            IncidentReportType.INITIAL,
        )
        if not initial_receipts:
            return ReportingWorkflowAssessment(
                entity_id=decision.entity_id,
                incident_id=decision.incident_id,
                incident_evidence_snapshot_digest=current_snapshot,
                classification_review_digest=review.evidence_digest,
                applicability_decision_digest=decision.evidence_digest,
                route_digest=route_digest,
                assessed_at=assessed_at,
                state=ReportingWorkflowState.NOT_REQUIRED,
                deadlines=(),
                latest_package_digests=package_digests,
                latest_receipt_digests=receipt_digests,
                findings=(),
            )
        reclassification_receipts = registry.receipts(
            decision.entity_id,
            decision.incident_id,
            IncidentReportType.RECLASSIFICATION,
        )
        state = ReportingWorkflowState.COMPLETE if reclassification_receipts else ReportingWorkflowState.PENDING
        findings = () if reclassification_receipts else ("reclassification_notification_pending",)
        return ReportingWorkflowAssessment(
            entity_id=decision.entity_id,
            incident_id=decision.incident_id,
            incident_evidence_snapshot_digest=current_snapshot,
            classification_review_digest=review.evidence_digest,
            applicability_decision_digest=decision.evidence_digest,
            route_digest=route_digest,
            assessed_at=assessed_at,
            state=state,
            deadlines=(),
            latest_package_digests=package_digests,
            latest_receipt_digests=receipt_digests,
            findings=findings,
        )

    deadlines: list[ReportingDeadline] = []
    findings: list[str] = []
    breached = False
    pending = False

    initial_deadline = _initial_deadline(registry, review)
    deadlines.append(initial_deadline)
    initial_receipt = _latest_receipt_for(
        registry,
        decision.entity_id,
        decision.incident_id,
        IncidentReportType.INITIAL,
    )
    finding, is_breached, is_pending = _deadline_finding(registry, initial_deadline, initial_receipt, assessed_at)
    if finding:
        findings.append(finding)
    breached = breached or is_breached
    pending = pending or is_pending

    latest_intermediate: SubmissionReceiptEvidence | None = None
    recovery_update_pending = False
    if initial_receipt is not None:
        intermediate_deadline = _deadline(
            registry,
            entity_id=decision.entity_id,
            incident_id=decision.incident_id,
            report_type=IncidentReportType.INTERMEDIATE,
            sequence=1,
            basis=DeadlineBasis.INTERMEDIATE_72H,
            triggered_at=initial_receipt.submitted_at,
            statutory_due_at=initial_receipt.submitted_at + _INTERMEDIATE_SECONDS,
        )
        deadlines.append(intermediate_deadline)
        intermediate_receipts = registry.receipts(
            decision.entity_id,
            decision.incident_id,
            IncidentReportType.INTERMEDIATE,
        )
        first_intermediate = next((item for item in intermediate_receipts if item.sequence == 1), None)
        finding, is_breached, is_pending = _deadline_finding(
            registry,
            intermediate_deadline,
            first_intermediate,
            assessed_at,
        )
        if finding:
            findings.append(finding)
        breached = breached or is_breached
        pending = pending or is_pending
        latest_intermediate = intermediate_receipts[-1] if intermediate_receipts else None

        recovered_events = [
            event
            for event in registry._incidents.events(decision.entity_id, decision.incident_id)
            if event.event_type is IncidentEventType.RECOVERED
        ]
        if latest_intermediate is not None and recovered_events:
            recovered_at = max(event.occurred_at for event in recovered_events)
            if recovered_at > latest_intermediate.submitted_at:
                next_sequence = latest_intermediate.sequence + 1
                deadlines.append(
                    _deadline(
                        registry,
                        entity_id=decision.entity_id,
                        incident_id=decision.incident_id,
                        report_type=IncidentReportType.INTERMEDIATE,
                        sequence=next_sequence,
                        basis=DeadlineBasis.RECOVERY_UPDATE_WITHOUT_UNDUE_DELAY,
                        triggered_at=recovered_at,
                        statutory_due_at=None,
                    )
                )
                findings.append(f"intermediate_report:{next_sequence}:required_after_recovery_without_undue_delay")
                recovery_update_pending = True
                pending = True

    if latest_intermediate is not None and not recovery_update_pending:
        final_due = _add_calendar_month(latest_intermediate.submitted_at)
        final_deadline = _deadline(
            registry,
            entity_id=decision.entity_id,
            incident_id=decision.incident_id,
            report_type=IncidentReportType.FINAL,
            sequence=1,
            basis=DeadlineBasis.FINAL_ONE_CALENDAR_MONTH,
            triggered_at=latest_intermediate.submitted_at,
            statutory_due_at=final_due,
        )
        deadlines.append(final_deadline)
        final_receipt = _latest_receipt_for(
            registry,
            decision.entity_id,
            decision.incident_id,
            IncidentReportType.FINAL,
        )
        finding, is_breached, is_pending = _deadline_finding(registry, final_deadline, final_receipt, assessed_at)
        if finding:
            findings.append(finding)
        breached = breached or is_breached
        pending = pending or is_pending

    for acknowledgement in registry.acknowledgements(decision.entity_id, decision.incident_id):
        if acknowledgement.status in {AcknowledgementStatus.REJECTED, AcknowledgementStatus.TECHNICAL_ERROR}:
            findings.append(f"submission_acknowledgement:{acknowledgement.status.value}:{acknowledgement.receipt_digest}")
            breached = True

    if breached:
        state = ReportingWorkflowState.BREACHED
    elif pending:
        state = ReportingWorkflowState.PENDING
    else:
        final_receipts = registry.receipts(
            decision.entity_id,
            decision.incident_id,
            IncidentReportType.FINAL,
        )
        state = ReportingWorkflowState.COMPLETE if final_receipts else ReportingWorkflowState.INCOMPLETE
        if not final_receipts:
            findings.append("final_report_sequence_not_yet_reachable")

    return ReportingWorkflowAssessment(
        entity_id=decision.entity_id,
        incident_id=decision.incident_id,
        incident_evidence_snapshot_digest=current_snapshot,
        classification_review_digest=review.evidence_digest,
        applicability_decision_digest=decision.evidence_digest,
        route_digest=route_digest,
        assessed_at=assessed_at,
        state=state,
        deadlines=tuple(deadlines),
        latest_package_digests=package_digests,
        latest_receipt_digests=receipt_digests,
        findings=tuple(findings),
    )
