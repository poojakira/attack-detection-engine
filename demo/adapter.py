import hashlib
import json
from datetime import datetime
from detection_engine.healthcare.detector import PatientAccessDetector
from detection_engine.platform.connectors.fhir_auditevent import FhirAuditEventConnector
from detection_engine.platform.correlation import CorrelationEngine
from detection_engine.platform.models import DataOrigin, DetectionFindingRecord
from detection_engine.platform.sample import synthetic_sample


SPEC = {
    "title": "Aegis HealthSec Engine Preview",
    "version": "1.1.0",
    "description": "Normalize the same 30 synthetic FHIR AuditEvents, run the clinical "
    "detector and correlator, then challenge the bulk-read threshold.",
    "scenarios": [
        {
            "id": "threshold25",
            "label": "30 synthetic distinct-patient reads · threshold 25",
        },
        {"id": "threshold40", "label": "Same exact 30 events · threshold 40"},
        {"id": "compare", "label": "Run both configurations on the same input"},
    ],
    "limitations": [
        "Only the first-party synthetic sample is accepted; no PHI, "
        "credentials or arbitrary event uploads.",
        "This stateless notebook preview has no database, user accounts or "
        "saved investigations. The full local React/API product uses "
        "PostgreSQL.",
        "Signals support investigation; they prove neither malicious access "
        "nor field accuracy.",
        "No anonymization, full FHIR conformance, hard parser isolation, "
        "public full-workbench approval or HIPAA certification.",
    ],
    "repository": "https://github.com/poojakira/attack-detection-engine/tree/codex/local-workbench-20261116",
}


def evaluate(threshold):
    sample = synthetic_sample()
    parsed = FhirAuditEventConnector().parse(
        sample, organization_id="synthetic-notebook-demo", max_items=1000
    )
    for event in parsed.events:
        event.data_origin = DataOrigin.SYNTHETIC
        event.normalized_attributes["data_origin"] = "synthetic"
    findings = PatientAccessDetector(bulk_access_threshold=threshold).detect(
        [e.normalized_attributes for e in parsed.events]
    )
    adapted = []
    for finding in findings:
        item = DetectionFindingRecord.from_engine_finding(
            finding,
            organization_id="synthetic-notebook-demo",
            rule_version="clinical-access-1.1",
        )
        item.detection_timestamp = datetime.fromisoformat(finding.timestamp)
        adapted.append(item)
    incidents = CorrelationEngine().correlate(adapted)
    return {
        "input_sha256": hashlib.sha256(
            json.dumps(sample, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
        "config": {"bulk_access_threshold": threshold},
        "event_count": len(parsed.events),
        "rejected_count": sum(not item.ok for item in parsed.items),
        "findings": [f.model_dump(mode="json") for f in adapted],
        "incidents": [i.incident.model_dump(mode="json") for i in incidents],
        "normalized_evidence": [e.model_dump(mode="json") for e in parsed.events[:2]],
        "data_origin": "synthetic",
        "persistence": "NOT USED in notebook engine preview; full local product uses PostgreSQL",
    }


def run(scenario):
    if scenario not in {item["id"] for item in SPEC["scenarios"]}:
        raise ValueError("Choose one of the documented synthetic scenarios")
    first = evaluate(25 if scenario != "threshold40" else 40)
    result = {"current": first}
    if scenario == "compare":
        second = evaluate(40)
        assert first["input_sha256"] == second["input_sha256"]
        result["after"] = second
        result["finding_count_removed"] = len(first["findings"]) - len(
            second["findings"]
        )
    return {
        "summary": str(len(first["findings"]))
        + " canonical finding(s), "
        + str(len(first["incidents"]))
        + " correlated incident(s); events="
        + str(first["event_count"])
        + (
            "; removed=" + str(result["finding_count_removed"])
            if scenario == "compare"
            else ""
        ),
        "engine_report": result,
    }
