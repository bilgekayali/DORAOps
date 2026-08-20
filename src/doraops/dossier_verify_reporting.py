from __future__ import annotations

from calendar import monthrange
from datetime import datetime, timezone
from typing import Any

from .dossier_verify_strict import verify_dossier_document as _verify_dossier_document
from .inventory import GovernanceError
from .reporting import ITS_TEMPLATE_PROFILE, RTS_CONTENT_PROFILE


_REPORT_ORDER = {
    "initial_notification": 1,
    "intermediate_report": 2,
    "final_report": 3,
    "reclassification_notification": 4,
}


def _non_negative_int(name: str, value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise GovernanceError(f"incident reporting {name} must be a non-negative integer")
    return value


def _positive_int(name: str, value: Any) -> int:
    value = _non_negative_int(name, value)
    if value < 1:
        raise GovernanceError(f"incident reporting {name} must be a positive integer")
    return value


def _digest(name: str, value: Any) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(ch not in "0123456789abcdef" for ch in value)
    ):
        raise GovernanceError(f"incident reporting {name} must be a lowercase SHA-256 digest")
    return value


def _optional_digest(name: str, value: Any) -> str | None:
    if value is None:
        return None
    return _digest(name, value)


def _text(name: str, value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise GovernanceError(f"incident reporting {name} must be non-empty text")
    return value.strip()


def _add_calendar_month(timestamp: int) -> int:
    source = datetime.fromtimestamp(_non_negative_int("calendar-month source", timestamp), tz=timezone.utc)
    if source.month == 12:
        year, month = source.year + 1, 1
    else:
        year, month = source.year, source.month + 1
    day = min(source.day, monthrange(year, month)[1])
    return int(source.replace(year=year, month=month, day=day).timestamp())


def _by_digest(items: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for item in items:
        digest = _digest("artifact digest", item.get("digest"))
        if digest in result:
            raise GovernanceError("incident reporting artifact digests must be unique")
        result[digest] = item
    return result


def _latest_by_version(items: list[dict[str, Any]], version_field: str) -> dict[str, Any]:
    if not items:
        raise GovernanceError("incident reporting version history is empty")
    ordered = sorted(items, key=lambda item: _positive_int(version_field, item["payload"].get(version_field)))
    versions = [_positive_int(version_field, item["payload"].get(version_field)) for item in ordered]
    if versions != list(range(1, len(versions) + 1)):
        raise GovernanceError(f"incident reporting {version_field} history must be contiguous")
    return ordered[-1]


def _verify_route(payload: dict[str, Any], entity_id: str) -> None:
    if payload.get("entity_id") != entity_id:
        raise GovernanceError("incident reporting route is outside dossier entity scope")
    mode = payload.get("submission_mode")
    submitter = _text("route submitter_id", payload.get("submitter_id"))
    outsourcing = _optional_digest("route outsourcing evidence", payload.get("outsourcing_evidence_digest"))
    permission = _optional_digest("route authority permission evidence", payload.get("authority_permission_evidence_digest"))
    scope = _optional_digest("route aggregation scope evidence", payload.get("aggregation_scope_evidence_digest"))
    _digest("route contact evidence", payload.get("contact_evidence_digest"))
    if mode == "direct":
        if submitter != entity_id or any(value is not None for value in (outsourcing, permission, scope)):
            raise GovernanceError("direct incident reporting route has invalid submitter/evidence semantics")
    elif mode == "outsourced":
        if submitter == entity_id or outsourcing is None or permission is not None or scope is not None:
            raise GovernanceError("outsourced incident reporting route has invalid evidence semantics")
    elif mode == "aggregated":
        if submitter == entity_id or outsourcing is None or permission is None or scope is None:
            raise GovernanceError("aggregated incident reporting route lacks required third-party evidence")
    else:
        raise GovernanceError("incident reporting route has unknown submission mode")


def _verify_reporting(
    artifacts: list[dict[str, Any]],
    *,
    entity_id: str,
) -> None:
    reporting = [item for item in artifacts if item.get("domain") == "incident_reporting"]
    if not reporting:
        return
    incident = [item for item in artifacts if item.get("domain") == "incident"]
    incident_by_type: dict[str, list[dict[str, Any]]] = {}
    for item in incident:
        incident_by_type.setdefault(item.get("artifact_type"), []).append(item)
    reporting_by_type: dict[str, list[dict[str, Any]]] = {}
    for item in reporting:
        reporting_by_type.setdefault(item.get("artifact_type"), []).append(item)
    by_digest = _by_digest(reporting + incident)

    assessments = reporting_by_type.get("workflow_assessment", [])
    if len(assessments) != 1:
        raise GovernanceError("incident reporting dossier requires exactly one workflow assessment")
    assessment_item = assessments[0]
    assessment = assessment_item["payload"]
    incident_id = _text("assessment incident_id", assessment.get("incident_id"))
    if assessment.get("entity_id") != entity_id:
        raise GovernanceError("incident reporting assessment is outside dossier entity scope")
    if assessment.get("regulatory_compliance_determined") is not False:
        raise GovernanceError("incident reporting assessment cannot determine regulatory compliance")
    if assessment.get("authority_acceptance_determined") is not False:
        raise GovernanceError("incident reporting assessment cannot determine authority acceptance")

    incident_records = [
        item
        for item in incident_by_type.get("incident", [])
        if item.get("artifact_id") == incident_id
    ]
    reviews = [
        item
        for item in incident_by_type.get("classification_review", [])
        if item.get("artifact_id") == incident_id
    ]
    if len(incident_records) != 1 or len(reviews) != 1:
        raise GovernanceError("incident reporting dossier requires exact embedded incident and classification review")
    incident_record = incident_records[0]
    current_review = reviews[0]
    if assessment.get("classification_review_digest") != current_review["digest"]:
        raise GovernanceError("incident reporting assessment does not bind embedded current classification review")
    current_snapshot = assessment.get("incident_evidence_snapshot_digest")
    _digest("assessment incident snapshot", current_snapshot)
    if current_review["payload"].get("incident_evidence_snapshot_digest") != current_snapshot:
        raise GovernanceError("incident reporting assessment/review incident snapshot bindings disagree")

    decisions = reporting_by_type.get("applicability_decision", [])
    matching_decisions = [item for item in decisions if item["payload"].get("incident_id") == incident_id]
    current_decision = _latest_by_version(matching_decisions, "decision_version")
    if assessment.get("applicability_decision_digest") != current_decision["digest"]:
        raise GovernanceError("incident reporting assessment does not bind current applicability decision")
    if current_decision["payload"].get("incident_evidence_snapshot_digest") != current_snapshot:
        raise GovernanceError("current reporting applicability is stale for assessment incident snapshot")
    if current_decision["payload"].get("classification_review_digest") != current_review["digest"]:
        raise GovernanceError("current reporting applicability does not bind embedded current classification review")

    routes = reporting_by_type.get("reporting_route", [])
    for route_item in routes:
        _verify_route(route_item["payload"], entity_id)
    route_digest = assessment.get("route_digest")
    applicability = current_decision["payload"].get("applicability")
    if applicability == "not_applicable":
        if route_digest is not None:
            raise GovernanceError("not-applicable reporting assessment must not bind a reporting route")
    elif applicability == "applicable":
        route_digest = _digest("assessment route_digest", route_digest)
        current_route = by_digest.get(route_digest)
        if current_route is None or current_route.get("artifact_type") != "reporting_route":
            raise GovernanceError("incident reporting assessment route_digest does not resolve")
        route_id = current_route["payload"].get("route_id")
        route_history = [item for item in routes if item["payload"].get("route_id") == route_id]
        latest_route = _latest_by_version(route_history, "version")
        if latest_route["digest"] != current_route["digest"]:
            raise GovernanceError("incident reporting assessment does not bind current route version")
    else:
        raise GovernanceError("incident reporting applicability uses unknown value")

    packages = reporting_by_type.get("report_package", [])
    package_groups: dict[tuple[str, int], list[dict[str, Any]]] = {}
    for item in packages:
        payload = item["payload"]
        if payload.get("entity_id") != entity_id or payload.get("incident_id") != incident_id:
            raise GovernanceError("incident report package crosses dossier scope")
        kind = payload.get("report_type")
        if kind not in _REPORT_ORDER:
            raise GovernanceError("incident report package has unknown report type")
        sequence = _positive_int("package sequence", payload.get("sequence"))
        revision = _positive_int("package revision", payload.get("revision"))
        if kind != "intermediate_report" and sequence != 1:
            raise GovernanceError("only intermediate report packages may use sequence greater than one")
        if payload.get("rts_content_profile") != RTS_CONTENT_PROFILE:
            raise GovernanceError("incident report package uses unexpected RTS content profile")
        if payload.get("its_template_profile") != ITS_TEMPLATE_PROFILE:
            raise GovernanceError("incident report package uses unexpected ITS template profile")
        decision_digest = _digest("package applicability decision", payload.get("applicability_decision_digest"))
        decision_item = by_digest.get(decision_digest)
        if decision_item is None or decision_item.get("artifact_type") != "applicability_decision":
            raise GovernanceError("incident report package applicability decision does not resolve")
        if payload.get("incident_evidence_snapshot_digest") != decision_item["payload"].get("incident_evidence_snapshot_digest"):
            raise GovernanceError("incident report package/decision snapshot bindings disagree")
        if payload.get("classification_review_digest") != decision_item["payload"].get("classification_review_digest"):
            raise GovernanceError("incident report package/decision review bindings disagree")
        bound_route = by_digest.get(_digest("package route", payload.get("route_digest")))
        if bound_route is None or bound_route.get("artifact_type") != "reporting_route":
            raise GovernanceError("incident report package route does not resolve")
        if bound_route["payload"].get("entity_id") != entity_id:
            raise GovernanceError("incident report package route crosses entity scope")
        _digest("package required content evidence", payload.get("required_content_evidence_digest"))
        _digest("package report payload", payload.get("report_payload_digest"))
        _non_negative_int("package prepared_at", payload.get("prepared_at"))
        package_groups.setdefault((kind, sequence), []).append(item)

    for (_kind, _sequence), revisions in package_groups.items():
        ordered = sorted(revisions, key=lambda item: _positive_int("package revision", item["payload"].get("revision")))
        revision_numbers = [_positive_int("package revision", item["payload"].get("revision")) for item in ordered]
        if revision_numbers != list(range(1, len(revision_numbers) + 1)):
            raise GovernanceError("incident report package revisions must be contiguous")
        previous = None
        previous_prepared_at = None
        for item in ordered:
            payload = item["payload"]
            revision = payload.get("revision")
            supersedes = payload.get("supersedes_package_digest")
            prepared_at = _non_negative_int("package prepared_at", payload.get("prepared_at"))
            if revision == 1:
                if supersedes is not None:
                    raise GovernanceError("first incident report revision cannot supersede another package")
            else:
                if supersedes != previous:
                    raise GovernanceError("incident report revision does not supersede exact previous revision")
                if previous_prepared_at is None or prepared_at <= previous_prepared_at:
                    raise GovernanceError("incident report revision chronology is invalid")
            previous = item["digest"]
            previous_prepared_at = prepared_at

    receipts = reporting_by_type.get("submission_receipt", [])
    receipt_by_package: dict[str, dict[str, Any]] = {}
    for item in receipts:
        payload = item["payload"]
        package_digest = _digest("receipt package_digest", payload.get("package_digest"))
        package_item = by_digest.get(package_digest)
        if package_item is None or package_item.get("artifact_type") != "report_package":
            raise GovernanceError("incident reporting receipt package does not resolve")
        package_payload = package_item["payload"]
        if (
            payload.get("entity_id") != entity_id
            or payload.get("incident_id") != incident_id
            or payload.get("report_type") != package_payload.get("report_type")
            or payload.get("sequence") != package_payload.get("sequence")
        ):
            raise GovernanceError("incident reporting receipt/package identity bindings disagree")
        if _non_negative_int("receipt submitted_at", payload.get("submitted_at")) < _non_negative_int("package prepared_at", package_payload.get("prepared_at")):
            raise GovernanceError("incident reporting submission predates package preparation")
        channel = payload.get("channel")
        technical = _optional_digest("technical impossibility evidence", payload.get("technical_impossibility_evidence_digest"))
        if channel == "alternative":
            if technical is None:
                raise GovernanceError("alternative incident submission lacks technical-impossibility evidence")
        elif technical is not None:
            raise GovernanceError("non-alternative incident submission carries technical-impossibility evidence")
        _digest("external submission evidence", payload.get("external_submission_evidence_digest"))
        if package_digest in receipt_by_package:
            raise GovernanceError("incident report package has multiple submission receipts")
        receipt_by_package[package_digest] = item

    acknowledgements = reporting_by_type.get("authority_acknowledgement", [])
    for item in acknowledgements:
        payload = item["payload"]
        receipt_digest = _digest("acknowledgement receipt_digest", payload.get("receipt_digest"))
        receipt_item = by_digest.get(receipt_digest)
        if receipt_item is None or receipt_item.get("artifact_type") != "submission_receipt":
            raise GovernanceError("authority acknowledgement receipt does not resolve")
        if payload.get("entity_id") != entity_id or payload.get("incident_id") != incident_id:
            raise GovernanceError("authority acknowledgement crosses dossier scope")
        if _non_negative_int("acknowledged_at", payload.get("acknowledged_at")) < _non_negative_int("submitted_at", receipt_item["payload"].get("submitted_at")):
            raise GovernanceError("authority acknowledgement predates represented submission")
        _digest("acknowledgement evidence", payload.get("acknowledgement_evidence_digest"))

    adjustments = reporting_by_type.get("deadline_adjustment", [])
    adjustment_by_key: dict[tuple[str, int], dict[str, Any]] = {}
    for item in adjustments:
        payload = item["payload"]
        key = (payload.get("report_type"), _positive_int("deadline adjustment sequence", payload.get("sequence")))
        if key in adjustment_by_key:
            raise GovernanceError("incident reporting deadline adjustment identities must be unique")
        original = _non_negative_int("deadline adjustment original due", payload.get("original_due_at"))
        adjusted = _non_negative_int("deadline adjustment adjusted due", payload.get("adjusted_due_at"))
        if adjusted <= original or payload.get("reason") != "weekend_or_bank_holiday":
            raise GovernanceError("incident reporting deadline adjustment semantics are invalid")
        _digest("deadline calendar evidence", payload.get("calendar_evidence_digest"))
        adjustment_by_key[key] = item

    delay_notices = reporting_by_type.get("delay_notification", [])
    delay_by_key: dict[tuple[str, int], dict[str, Any]] = {}
    for item in delay_notices:
        payload = item["payload"]
        key = (payload.get("report_type"), _positive_int("delay notice sequence", payload.get("sequence")))
        if key in delay_by_key:
            raise GovernanceError("incident reporting delay-notification identities must be unique")
        due_at = _non_negative_int("delay notice due_at", payload.get("due_at"))
        notified_at = _non_negative_int("delay notice notified_at", payload.get("notified_at"))
        if notified_at > due_at:
            raise GovernanceError("incident reporting delay notification occurs after represented deadline")
        _digest("delay reason evidence", payload.get("reason_evidence_digest"))
        _digest("delay authority notification evidence", payload.get("authority_notification_evidence_digest"))
        delay_by_key[key] = item

    deadlines = assessment.get("deadlines")
    if not isinstance(deadlines, list):
        raise GovernanceError("incident reporting assessment deadlines must be an array")
    seen_deadlines: set[tuple[str, int]] = set()
    for deadline in deadlines:
        if not isinstance(deadline, dict):
            raise GovernanceError("incident reporting deadline must be an object")
        kind = deadline.get("report_type")
        sequence = _positive_int("assessment deadline sequence", deadline.get("sequence"))
        key = (kind, sequence)
        if key in seen_deadlines:
            raise GovernanceError("incident reporting assessment deadline identities must be unique")
        seen_deadlines.add(key)
        basis = deadline.get("basis")
        triggered_at = _non_negative_int("assessment deadline triggered_at", deadline.get("triggered_at"))
        statutory = deadline.get("statutory_due_at")
        effective = deadline.get("effective_due_at")
        adjustment_digest = deadline.get("adjustment_digest")
        if basis == "recovery_update_without_undue_delay":
            if statutory is not None or effective is not None or adjustment_digest is not None:
                raise GovernanceError("without-undue-delay reporting obligation cannot fabricate numeric deadline")
            continue
        statutory = _non_negative_int("assessment statutory due", statutory)
        effective = _non_negative_int("assessment effective due", effective)
        if effective < statutory:
            raise GovernanceError("incident reporting effective deadline predates statutory deadline")
        adjustment = adjustment_by_key.get(key)
        if adjustment is None:
            if adjustment_digest is not None or effective != statutory:
                raise GovernanceError("unadjusted incident reporting deadline differs from statutory deadline")
        else:
            if adjustment_digest != adjustment["digest"]:
                raise GovernanceError("incident reporting deadline does not bind exact adjustment evidence")
            if adjustment["payload"].get("original_due_at") != statutory or adjustment["payload"].get("adjusted_due_at") != effective:
                raise GovernanceError("incident reporting deadline adjustment values disagree")

        if kind == "initial_notification":
            review_at = _non_negative_int("classification reviewed_at", current_review["payload"].get("reviewed_at"))
            detected_at = _non_negative_int("incident detected_at", incident_record["payload"].get("detected_at"))
            awareness_cap = detected_at + 24 * 60 * 60
            classification_due = review_at + 4 * 60 * 60
            if review_at > awareness_cap:
                expected = classification_due
                expected_basis = "initial_classification_4h"
            elif classification_due <= awareness_cap:
                expected = classification_due
                expected_basis = "initial_classification_4h"
            else:
                expected = awareness_cap
                expected_basis = "initial_awareness_24h"
            if statutory != expected or basis != expected_basis or triggered_at != review_at:
                raise GovernanceError("incident reporting initial deadline is inconsistent with incident/review evidence")
        elif kind == "intermediate_report" and sequence == 1 and basis == "intermediate_72h":
            initial_candidates = [
                item
                for item in receipts
                if item["payload"].get("report_type") == "initial_notification"
            ]
            if not initial_candidates:
                raise GovernanceError("intermediate deadline exists without initial submission evidence")
            initial_receipt = sorted(initial_candidates, key=lambda item: item["payload"].get("submitted_at"))[-1]
            submitted_at = _non_negative_int("initial submitted_at", initial_receipt["payload"].get("submitted_at"))
            if statutory != submitted_at + 72 * 60 * 60 or triggered_at != submitted_at:
                raise GovernanceError("incident reporting intermediate deadline is inconsistent with initial submission")
        elif kind == "final_report" and basis == "final_one_calendar_month":
            intermediate_candidates = [
                item
                for item in receipts
                if item["payload"].get("report_type") == "intermediate_report"
            ]
            if not intermediate_candidates:
                raise GovernanceError("final deadline exists without intermediate submission evidence")
            latest = sorted(
                intermediate_candidates,
                key=lambda item: (item["payload"].get("sequence"), item["payload"].get("submitted_at")),
            )[-1]
            submitted_at = _non_negative_int("latest intermediate submitted_at", latest["payload"].get("submitted_at"))
            if statutory != _add_calendar_month(submitted_at) or triggered_at != submitted_at:
                raise GovernanceError("incident reporting final deadline is inconsistent with latest intermediate submission")

    expected_latest_packages = [
        revisions[-1]["digest"]
        for _key, revisions in sorted(
            package_groups.items(),
            key=lambda pair: (_REPORT_ORDER[pair[0][0]], pair[0][1]),
        )
    ]
    if assessment.get("latest_package_digests") != expected_latest_packages:
        raise GovernanceError("incident reporting assessment latest package digests are inconsistent")

    expected_latest_receipts: list[str] = []
    for package_digest in expected_latest_packages:
        receipt = receipt_by_package.get(package_digest)
        if receipt is not None:
            expected_latest_receipts.append(receipt["digest"])
    if assessment.get("latest_receipt_digests") != expected_latest_receipts:
        raise GovernanceError("incident reporting assessment latest receipt digests are inconsistent")

    state = assessment.get("state")
    findings = assessment.get("findings")
    if state not in {"not_required", "incomplete", "pending", "breached", "complete", "revalidation_required"}:
        raise GovernanceError("incident reporting assessment has unknown state")
    if not isinstance(findings, list) or findings != sorted(set(findings)):
        raise GovernanceError("incident reporting assessment findings must be sorted and unique")


def verify_dossier_document(document: Any) -> str:
    """Verify v0.1-v0.3 dossier integrity and incident-reporting semantics offline."""
    digest = _verify_dossier_document(document)
    dossier = document["dossier"]
    _verify_reporting(dossier["artifacts"], entity_id=dossier["entity_id"])
    return digest
