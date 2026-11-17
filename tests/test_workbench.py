"""Real PostgreSQL case/run boundaries and real clinical detector regressions."""

from __future__ import annotations

import asyncio
import copy
import hashlib
import json
import os

import pytest
from fastapi.testclient import TestClient

from detection_engine.healthcare.detector import PatientAccessDetector
from detection_engine.healthcare.schema import ClinicalAccessEvent
from detection_engine.platform import db
from detection_engine.platform.api import create_app
from detection_engine.platform.body_limit import BodyLimitMiddleware
from detection_engine.platform.bootstrap import seed_user
from detection_engine.platform.connectors.base import ConnectorError
from detection_engine.platform.connectors.fhir_auditevent import FhirAuditEventConnector
from detection_engine.platform.sample import synthetic_sample


@pytest.mark.parametrize(
    "field,value",
    [
        ("action", None),
        ("action", "X"),
        ("outcome", "wat"),
        ("outcome", 0),
        ("recorded", "2026-11-16"),
        ("recorded", "2026-11-16T10:00:00"),
        ("recorded", "2026-99-01T10:00:00Z"),
        ("agent", [None]),
        ("entity", "bad"),
    ],
)
def test_malformed_fhir_not_relabelled(field, value):
    event = synthetic_sample()["entry"][0]["resource"]
    event[field] = value
    parsed = FhirAuditEventConnector().parse(
        event, organization_id="test", max_items=100
    )
    assert not parsed.events and len(parsed.errors) == 1


@pytest.mark.parametrize("field", ["action", "outcome"])
def test_optional_r4_values_remain_unknown_through_detector(field):
    bundle = synthetic_sample()
    for entry in bundle["entry"]:
        del entry["resource"][field]
    parsed = FhirAuditEventConnector().parse(
        bundle, organization_id="test", max_items=100
    )
    assert len(parsed.events) == 30
    records = [e.normalized_attributes for e in parsed.events]
    assert all(r[field] == "unknown" for r in records)
    assert PatientAccessDetector(bulk_access_threshold=2).detect(records) == []
    assert (
        getattr(
            ClinicalAccessEvent.from_fhir_audit_event(bundle["entry"][0]["resource"]),
            field,
        ).value
        == "unknown"
    )


def test_major_failure_supported_and_not_success():
    event = synthetic_sample()["entry"][0]["resource"]
    event["outcome"] = "12"
    assert (
        ClinicalAccessEvent.from_fhir_audit_event(event).outcome.value
        == "major_failure"
    )


def test_unsupported_entries_counted_before_limit():
    payload = [
        synthetic_sample()["entry"][0]["resource"],
        None,
        42,
        {"resourceType": "Patient"},
    ]
    result = FhirAuditEventConnector().parse(
        payload, organization_id="test", max_items=4
    )
    assert result.as_summary()["parsed"] == 4 and len(result.errors) == 3
    with pytest.raises(ConnectorError):
        FhirAuditEventConnector().parse(payload, organization_id="test", max_items=3)


@pytest.mark.parametrize("length", [None, b"1", b"99999999"])
def test_streamed_body_cut_off_before_unbounded_accumulation(length):
    consumed = 0
    called = False
    sent = []

    async def receive():
        nonlocal consumed
        consumed += 1
        return {"type": "http.request", "body": b"x" * 10, "more_body": True}

    async def handler(scope, receive, send):
        nonlocal called
        called = True

    async def send(message):
        sent.append(message)

    scope = {
        "type": "http",
        "headers": [] if length is None else [(b"content-length", length)],
    }
    asyncio.run(BodyLimitMiddleware(handler, max_bytes=25)(scope, receive, send))
    assert consumed == 3 and not called and sent[0]["status"] == 413


def test_slow_stream_deadline_before_handler():
    sent = []

    async def receive():
        await asyncio.sleep(0.03)
        return {"type": "http.request", "body": b"x", "more_body": True}

    async def handler(*args):
        pytest.fail("slow body reached parser")

    async def send(message):
        sent.append(message)

    asyncio.run(
        BodyLimitMiddleware(handler, max_bytes=100, timeout=0.01)(
            {"type": "http"}, receive, send
        )
    )
    assert sent[0]["status"] == 408


@pytest.fixture
def clients(pg_engine, monkeypatch):
    url = os.environ.get(
        "AEGIS_TEST_DATABASE_URL",
        "postgresql+psycopg://aegis:synthetic-local-db-only@127.0.0.1:55432/aegis",
    )
    monkeypatch.setenv("AEGIS_DATABASE_URL", url)
    with db.make_session_factory(pg_engine)() as session:
        for i, role, org in [
            ("a", "security_analyst", "org-a"),
            ("b", "security_analyst", "org-b"),
            ("r", "read_only_auditor", "org-a"),
        ]:
            seed_user(
                session,
                user_id=i,
                username=i,
                password="synthetic-test-password",
                role=role,
                organization_id=org,
            )
    client = TestClient(create_app(), raise_server_exceptions=False)
    tokens = {}
    for user in ("a", "b", "r"):
        response = client.post(
            "/api/v1/auth/token",
            json={"username": user, "password": "synthetic-test-password"},
        )
        assert response.status_code == 200
        tokens[user] = {"Authorization": "Bearer " + response.json()["access_token"]}
    return client, tokens


def imported(client, tokens, payload=None):
    response = client.post(
        "/api/v1/workbench/cases",
        json={
            "input_text": json.dumps(payload or synthetic_sample()),
            "title": "<img src=x onerror=alert(1)>",
        },
        headers=tokens["a"],
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_full_persisted_rerun_delta_export_restart_and_org_isolation(
    clients, pg_engine
):
    client, tokens = clients
    first = imported(client, tokens)
    assert (
        len(first["events"]) == 30
        and len(first["findings"]) == 1
        and len(first["incidents"]) == 1
    )
    assert first["findings"][0]["rule_id"] == "HC-ACCESS-BULK"
    assert first["data_origin"] == "synthetic"
    case_id = first["case_id"]
    route = f"/api/v1/workbench/cases/{case_id}"
    assert client.get(route, headers=tokens["b"]).status_code == 404
    assert (
        client.get(route, headers={"Authorization": "Bearer forged"}).status_code == 401
    )
    assert client.get(route).status_code == 401
    assert (
        client.post(
            route + "/runs",
            json={
                "config": {"bulk_access_threshold": 40},
                "expected_run_id": first["run_id"],
            },
            headers=tokens["b"],
        ).status_code
        == 404
    )
    assert (
        client.post(
            route + "/runs",
            json={
                "config": {"bulk_access_threshold": 40},
                "expected_run_id": first["run_id"],
            },
            headers=tokens["r"],
        ).status_code
        == 403
    )
    next_response = client.post(
        route + "/runs",
        json={
            "config": {"bulk_access_threshold": 40},
            "expected_run_id": first["run_id"],
        },
        headers=tokens["a"],
    )
    assert next_response.status_code == 201, next_response.text
    second = next_response.json()
    assert (
        second["findings"] == []
        and second["delta"]["removed"] == 1
        and second["input_sha256"] == first["input_sha256"]
    )
    assert second["config_sha256"] != first["config_sha256"]
    assert [e["normalized"] for e in first["events"]] == [
        e["normalized"] for e in second["events"]
    ]
    assert [e["event_id"] for e in first["events"]] == [
        e["event_id"] for e in second["events"]
    ]
    assert (
        client.post(
            route + "/runs",
            json={
                "config": {"bulk_access_threshold": 40},
                "expected_run_id": first["run_id"],
            },
            headers=tokens["a"],
        ).status_code
        == 409
    )
    report_route = route + f"/runs/{second['run_id']}/export"
    assert client.get(report_route, headers=tokens["b"]).status_code == 404
    report = client.get(report_route, headers=tokens["a"])
    assert report.json() == second
    assert (
        hashlib.sha256(report.content).hexdigest() == report.headers["X-Report-SHA256"]
    )
    assert (
        "access_token" not in report.text
        and "synthetic-test-password" not in report.text
    )
    # New app/session reads committed evidence, without browser storage.
    restarted = TestClient(create_app())
    assert len(restarted.get(route, headers=tokens["a"]).json()["runs"]) == 2
    with db.make_session_factory(pg_engine)() as session:
        assert session.query(db.SecurityEventRow).count() == 30
        assert session.query(db.DetectionFindingRow).count() == 1
        assert session.query(db.IncidentRow).count() == 1
        user = session.get(db.UserRow, "a")
        user.token_version += 1
        session.commit()
    assert restarted.get(route, headers=tokens["a"]).status_code == 401


@pytest.mark.parametrize(
    "config",
    [
        {"bulk_access_threshold": 0},
        {"bulk_access_threshold": 1001},
        {"bulk_access_threshold": True},
        {"bulk_access_threshold": "20"},
        {"path": "/etc/passwd"},
        {"url": "http://169.254.169.254"},
    ],
)
def test_configuration_rejects_unsafe_or_invalid_fields(clients, config):
    client, tokens = clients
    response = client.post(
        "/api/v1/workbench/cases",
        json={"input_text": json.dumps(synthetic_sample()), "config": config},
        headers=tokens["a"],
    )
    assert response.status_code == 422


def test_reject_malformed_parse_failure_is_atomic(clients, pg_engine, monkeypatch):
    client, tokens = clients
    for text in (
        "{broken",
        "[]",
        '{"resourceType":"Observation"}',
        "x" * (1024 * 1024 + 1),
    ):
        response = client.post(
            "/api/v1/workbench/cases", json={"input_text": text}, headers=tokens["a"]
        )
        assert response.status_code in (413, 422)

    def crashed(*args, **kwargs):
        raise RuntimeError("private-parser-detail")

    monkeypatch.setattr(PatientAccessDetector, "detect", crashed)
    response = client.post(
        "/api/v1/workbench/cases",
        json={"input_text": json.dumps(synthetic_sample())},
        headers=tokens["a"],
    )
    assert response.status_code == 500 and "private-parser-detail" not in response.text
    with db.make_session_factory(pg_engine)() as session:
        assert session.query(db.WorkbenchCaseRow).count() == 0
        assert session.query(db.SecurityEventRow).count() == 0


def test_mixed_rejections_unknown_and_byo_origin_persisted(clients):
    client, tokens = clients
    bundle = synthetic_sample()
    bundle["entry"].extend([{"resource": {"resourceType": "Patient"}}, None])
    del bundle["entry"][0]["resource"]["outcome"]
    report = imported(client, tokens, bundle)
    assert report["connector"]["rejected"] == 2 and report["connector"]["parsed"] == 32
    assert report["data_origin"] == "unspecified"
    assert report["events"][0]["normalized"]["outcome"] == "unknown"
    assert report["findings"][0]["evidence_references"]["distinct_patients"] == 29


def test_same_ids_changed_dataset_never_reuses_old_metadata(clients):
    client, tokens = clients
    first = imported(client, tokens)
    changed = copy.deepcopy(synthetic_sample())
    changed["entry"][0]["resource"]["outcome"] = "4"
    second = imported(client, tokens, changed)
    assert first["events"][0]["event_id"] != second["events"][0]["event_id"]
    assert second["events"][0]["normalized"]["outcome"] == "minor_failure"


def test_no_care_context_no_invented_authorization(clients):
    client, tokens = clients
    report = imported(client, tokens)
    assert report["findings"][0]["mapped_attack_techniques"] == []
    assert "No authoritative assignments" in report["findings"][0]["counter_evidence"]


def test_host_and_cors_boundaries(clients):
    client, tokens = clients
    assert (
        client.get("/health", headers={"host": "attacker.invalid"}).status_code == 400
    )
    response = client.options(
        "/api/v1/workbench/cases",
        headers={
            "Origin": "https://attacker.invalid",
            "Access-Control-Request-Method": "POST",
        },
    )
    assert response.status_code == 400
    assert "access-control-allow-origin" not in response.headers
    assert client.get("/health").headers["x-content-type-options"] == "nosniff"


def test_replayed_config_is_case_local(clients):
    client, tokens = clients
    first = imported(client, tokens)
    second = imported(client, tokens)
    route = f"/api/v1/workbench/cases/{first['case_id']}/runs"
    rerun = client.post(
        route,
        json={
            "config": {"bulk_access_threshold": 40},
            "expected_run_id": first["run_id"],
        },
        headers=tokens["a"],
    )
    assert rerun.status_code == 201 and rerun.json()["findings"] == []
    other = client.get(
        f"/api/v1/workbench/cases/{second['case_id']}", headers=tokens["a"]
    ).json()
    assert other["runs"][0]["config"]["bulk_access_threshold"] == 25
    assert len(other["runs"][0]["findings"]) == 1
    assert len(other["runs"]) == 1


def test_alembic_restart_and_new_table_rollback(pg_engine, monkeypatch):
    from alembic import command
    from alembic.config import Config
    from pathlib import Path
    from sqlalchemy import inspect
    from detection_engine.platform import api

    monkeypatch.setenv("AEGIS_DATABASE_URL", os.environ["AEGIS_TEST_DATABASE_URL"])
    db.Base.metadata.drop_all(pg_engine)
    with pg_engine.begin() as conn:
        conn.exec_driver_sql("DROP TABLE IF EXISTS alembic_version")
    cfg = Config(str(Path(api.__file__).with_name("alembic.ini")))
    command.upgrade(cfg, "head")
    assert "workbench_runs" in inspect(pg_engine).get_table_names()
    command.upgrade(cfg, "head")
    command.downgrade(cfg, "a1b2c3d4e5f6")
    tables = inspect(pg_engine).get_table_names()
    assert "workbench_cases" not in tables and "security_events" in tables
    command.upgrade(cfg, "head")
    assert "workbench_cases" in inspect(pg_engine).get_table_names()
