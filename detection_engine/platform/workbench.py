"""Bounded, organization-scoped FHIR investigations using canonical engines."""

from __future__ import annotations

import hashlib
import json
import uuid
from collections import Counter
from datetime import datetime, timezone
from importlib.metadata import version

from pydantic import BaseModel, Field
from sqlalchemy import select

from ..healthcare.detector import PatientAccessDetector
from ..healthcare.schema import ClinicalAccessEvent
from . import db
from .connectors.base import ConnectorError
from .connectors.fhir_auditevent import FhirAuditEventConnector
from .correlation import CorrelationEngine
from .models import DataOrigin, DetectionFindingRecord, SecurityEvent
from .provenance import (
    APP_VERSION,
    CORE_REVISION,
    RULE_VERSION,
    source_hash,
    source_provenance,
)
from .repository import Repository

MAX_INPUT_BYTES = 1024 * 1024
MAX_ITEMS = 1000


class CaseConfig(BaseModel):
    model_config = {"extra": "forbid", "strict": True}
    bulk_access_threshold: int = Field(default=25, ge=2, le=1000)
    denial_streak_threshold: int = Field(default=3, ge=2, le=100)


class CaseImport(BaseModel):
    model_config = {"extra": "forbid"}
    title: str = Field(default="Local FHIR investigation", min_length=1, max_length=160)
    input_text: str = Field(min_length=1, max_length=MAX_INPUT_BYTES)
    config: CaseConfig = Field(default_factory=CaseConfig)


class CaseRerun(BaseModel):
    model_config = {"extra": "forbid"}
    config: CaseConfig
    expected_run_id: str = Field(min_length=1, max_length=64)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha(value):
    return hashlib.sha256(value.encode()).hexdigest()


def parse_text(input_text, org):
    if len(input_text.encode("utf-8")) > MAX_INPUT_BYTES:
        raise ConnectorError("input exceeds 1 MiB UTF-8 limit")
    try:
        payload = json.loads(input_text)
    except (ValueError, RecursionError):
        raise ConnectorError("input must be bounded JSON") from None
    connector = FhirAuditEventConnector()
    parsed = connector.parse(payload, organization_id=org, max_items=MAX_ITEMS)
    if not parsed.events:
        raise ConnectorError(
            "no supported AuditEvent records; correct input before importing"
        )
    # Clinical schema validation is fail-closed and does not echo field values.
    for item in parsed.items:
        if item.ok and item.event is not None:
            try:
                ClinicalAccessEvent.model_validate(item.event.normalized_attributes)
            except ValueError:
                item.error = "unsupported clinical metadata; use opaque identifiers"
                item.event = None
    if not parsed.events:
        raise ConnectorError("no supported clinical events after validation")
    return parsed, connector._extract_resources(payload)


def latest_run(session, case_id):
    return session.execute(
        select(db.WorkbenchRunRow)
        .where(db.WorkbenchRunRow.case_id == case_id)
        .order_by(
            db.WorkbenchRunRow.created_at.desc(), db.WorkbenchRunRow.run_id.desc()
        )
        .limit(1)
    ).scalar_one_or_none()


def execute_run(session, case, config, *, context=None):
    """Runs atomically in caller's transaction. No mutable global detector state."""
    started = datetime.now(timezone.utc)
    parsed, resources = parse_text(case.input_text, case.organization_id)
    repo = Repository(session)
    run_id = "run-" + uuid.uuid4().hex
    previous = latest_run(session, case.case_id)
    events = []
    records = []
    by_actor = {}
    for item in parsed.items:
        if not item.ok or item.event is None:
            continue
        event = item.event
        event.data_origin = DataOrigin(case.origin)
        event.normalized_attributes["data_origin"] = case.origin
        # Event identity includes source content: conflicting reused FHIR ids do
        # not silently substitute an older dataset's persisted event.
        event.source_event_id = sha(canonical(resources[item.index]))
        row, _ = repo.upsert_event(event)
        records.append(event.normalized_attributes)
        by_actor.setdefault(event.identity_id, []).append(row.event_id)
        events.append(
            {
                "event_id": row.event_id,
                "source_index": item.index,
                "source": resources[item.index],
                "normalized": SecurityEvent.model_validate(
                    {name: getattr(row, name) for name in SecurityEvent.model_fields}
                ).model_dump(mode="json"),
            }
        )
    detector = PatientAccessDetector(context=context, **config.model_dump())
    findings = []
    adapted = []
    links = {}
    for finding in detector.detect(records):
        record = DetectionFindingRecord.from_engine_finding(
            finding, organization_id=case.organization_id, rule_version=RULE_VERSION
        )
        # Use source event time for correlation, not wall clock import time.
        record.detection_timestamp = datetime.fromisoformat(finding.timestamp)
        repo.add_finding(record)
        adapted.append(record)
        related = by_actor.get(record.affected_identity, [])
        links[record.finding_id] = related
        fingerprint = sha(
            canonical(
                [record.rule_id, record.affected_identity, record.affected_resource]
            )
        )
        findings.append(
            {
                **record.model_dump(mode="json"),
                "fingerprint": fingerprint,
                "related_event_ids": related,
                "hypothesis": "Deterministic access-pattern signal; review required.",
                "counter_evidence": "No authoritative assignments or shift context supplied."
                if context is None
                else "Context-dependent signal; confirm assignments and legitimate purpose.",
                "uncertainty": "A threshold crossing is not proof of unauthorized or malicious access. ATT&CK mapping is absent when unsupported by the signal.",
            }
        )
    incidents = []
    for correlated in CorrelationEngine().correlate(
        adapted, event_ids_by_finding=links
    ):
        incident = correlated.incident
        incident.correlation_key = sha(
            canonical([case.case_id, run_id, incident.correlation_key])
        )
        row, _ = repo.upsert_incident(
            incident, finding_ids=correlated.finding_ids, event_ids=correlated.event_ids
        )
        incidents.append(
            {
                "incident_id": row.incident_id,
                "title": row.title,
                "correlation_reason": row.correlation_reason,
                "finding_ids": correlated.finding_ids,
                "event_ids": correlated.event_ids,
            }
        )
    old = (
        Counter(f["fingerprint"] for f in previous.report["findings"])
        if previous
        else Counter()
    )
    current = Counter(f["fingerprint"] for f in findings)
    delta = {
        "baseline_run_id": previous.run_id if previous else None,
        "added": sum((current - old).values()),
        "removed": sum((old - current).values()),
        "unchanged": sum((old & current).values()),
        "added_fingerprints": list((current - old).elements()),
        "removed_fingerprints": list((old - current).elements()),
    }
    report = {
        "schema_version": "1.0",
        "case_id": case.case_id,
        "title": case.title,
        "run_id": run_id,
        "data_origin": case.origin,
        "input_sha256": case.input_sha256,
        "input_bytes": len(case.input_text.encode()),
        "config": config.model_dump(),
        "config_sha256": sha(canonical(config.model_dump())),
        "app_version": APP_VERSION,
        "rule_version": RULE_VERSION,
        "core_revision": CORE_REVISION,
        "source": source_provenance(),
        "source_sha256": source_hash(),
        "dependencies": {
            name: version(name)
            for name in (
                "attack-detection-engine",
                "attack-v19-core",
                "pydantic",
                "fastapi",
                "sqlalchemy",
            )
        },
        "started_at": started.isoformat(),
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "connector": parsed.as_summary(),
        "events": sorted(
            events,
            key=lambda e: (e["normalized"]["event_timestamp"], e["source_index"]),
        ),
        "findings": findings,
        "incidents": incidents,
        "delta": delta,
        "limitations": [
            "Offline batch investigation; no continuous monitoring.",
            "Input references are extracted tokens, not guaranteed anonymization. Source JSON is retained locally in PostgreSQL.",
            "No external authorization context, field accuracy, or malicious intent is established.",
            "R4 security metadata subset, not full FHIR conformance validation.",
            "No ATT&CK mapping is asserted for the supported read-access bulk signal.",
        ],
    }
    row = db.WorkbenchRunRow(
        run_id=run_id,
        case_id=case.case_id,
        organization_id=case.organization_id,
        report=report,
    )
    session.add(row)
    session.flush()
    return report
