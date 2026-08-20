from __future__ import annotations

from .inventory import GovernanceError
from .reporting import (
    AuthorityAcknowledgementEvidence,
    DeadlineAdjustmentEvidence,
    DelayNotificationEvidence,
    IncidentReportPackage,
    IncidentReportingRegistry,
    IncidentReportingRoute,
    ReportingApplicabilityDecision,
    SubmissionReceiptEvidence,
    _report_order,
)


def _registry(value: IncidentReportingRegistry) -> IncidentReportingRegistry:
    if not isinstance(value, IncidentReportingRegistry):
        raise GovernanceError("reporting audit access requires IncidentReportingRegistry")
    return value


def applicability_history(
    registry: IncidentReportingRegistry,
    entity_id: str,
    incident_id: str,
) -> tuple[ReportingApplicabilityDecision, ...]:
    registry = _registry(registry)
    return tuple(registry._decisions.get((entity_id, incident_id), ()))


def route_history(
    registry: IncidentReportingRegistry,
    entity_id: str,
    route_id: str,
) -> tuple[IncidentReportingRoute, ...]:
    registry = _registry(registry)
    return tuple(registry._routes.get((entity_id, route_id), ()))


def reporting_routes(
    registry: IncidentReportingRegistry,
    entity_id: str,
) -> tuple[IncidentReportingRoute, ...]:
    registry = _registry(registry)
    result = [
        route
        for (entity, _route_id), versions in registry._routes.items()
        if entity == entity_id
        for route in versions
    ]
    return tuple(
        sorted(
            result,
            key=lambda item: (item.route_id, item.version, item.registered_at),
        )
    )


def package_history(
    registry: IncidentReportingRegistry,
    entity_id: str,
    incident_id: str,
) -> tuple[IncidentReportPackage, ...]:
    registry = _registry(registry)
    result = [
        package
        for (entity, incident, _kind, _sequence), revisions in registry._packages.items()
        if entity == entity_id and incident == incident_id
        for package in revisions
    ]
    return tuple(
        sorted(
            result,
            key=lambda item: (
                _report_order(item.report_type),
                item.sequence,
                item.revision,
                item.prepared_at,
            ),
        )
    )


def submission_receipts(
    registry: IncidentReportingRegistry,
    entity_id: str,
    incident_id: str,
) -> tuple[SubmissionReceiptEvidence, ...]:
    registry = _registry(registry)
    result = [
        receipt
        for receipt in registry._receipts.values()
        if receipt.entity_id == entity_id and receipt.incident_id == incident_id
    ]
    return tuple(
        sorted(
            result,
            key=lambda item: (
                _report_order(item.report_type),
                item.sequence,
                item.submitted_at,
                item.package_digest,
            ),
        )
    )


def authority_acknowledgements(
    registry: IncidentReportingRegistry,
    entity_id: str,
    incident_id: str,
) -> tuple[AuthorityAcknowledgementEvidence, ...]:
    registry = _registry(registry)
    result = [
        acknowledgement
        for acknowledgement in registry._acknowledgements.values()
        if acknowledgement.entity_id == entity_id and acknowledgement.incident_id == incident_id
    ]
    return tuple(
        sorted(
            result,
            key=lambda item: (item.acknowledged_at, item.receipt_digest),
        )
    )


def deadline_adjustment_history(
    registry: IncidentReportingRegistry,
    entity_id: str,
    incident_id: str,
) -> tuple[DeadlineAdjustmentEvidence, ...]:
    registry = _registry(registry)
    result = [
        evidence
        for (entity, incident, _kind, _sequence), evidence in registry._adjustments.items()
        if entity == entity_id and incident == incident_id
    ]
    return tuple(
        sorted(
            result,
            key=lambda item: (_report_order(item.report_type), item.sequence),
        )
    )


def delay_notification_history(
    registry: IncidentReportingRegistry,
    entity_id: str,
    incident_id: str,
) -> tuple[DelayNotificationEvidence, ...]:
    registry = _registry(registry)
    result = [
        evidence
        for (entity, incident, _kind, _sequence), evidence in registry._delay_notifications.items()
        if entity == entity_id and incident == incident_id
    ]
    return tuple(
        sorted(
            result,
            key=lambda item: (_report_order(item.report_type), item.sequence),
        )
    )
