"""FastAPI application: authenticated ingestion + investigation API.

Every data endpoint requires a valid bearer token and is scoped to the caller's
organization. There are no unauthenticated data endpoints (only /health,
/readiness and the token login). Role checks gate ingestion and incident writes.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import text

from . import auth, db
from .auth import Principal
from .correlation import CorrelationEngine
from .ingestion import IngestionService
from .investigation import InvalidTransition, InvestigationService
from .models import IncidentStatus
from .repository import Repository
from .workbench import CaseImport, CaseRerun

MAX_BATCH = int(os.environ.get("AEGIS_MAX_BATCH", "1000"))
MAX_BODY_BYTES = int(os.environ.get("AEGIS_MAX_BODY_BYTES", str(2 * 1024 * 1024)))


# --- request/response schemas ----------------------------------------------


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    organization_id: str


class ClinicalBatchRequest(BaseModel):
    events: List[Dict[str, Any]] = Field(
        ..., description="Clinical access event records"
    )


class StatusChangeRequest(BaseModel):
    status: IncidentStatus
    expected_version: Optional[int] = None


class NoteRequest(BaseModel):
    note: str = Field(..., min_length=1, max_length=4000)


class AssignRequest(BaseModel):
    analyst_id: str = Field(..., min_length=1)


class DispositionRequest(BaseModel):
    disposition: str = Field(..., min_length=1)
    summary: str = Field(default="", max_length=4000)


class CloseRequest(BaseModel):
    reason: str = Field(..., min_length=1, max_length=512)


def create_app(*, pipeline_factory=None, clinical_detector_factory=None) -> FastAPI:
    """Build the app. Factories allow injecting the ATT&CK pipeline and the
    clinical detector lazily (so importing the app does not require the ATT&CK
    bundle to be loaded, and tests can inject fakes)."""

    app = FastAPI(title="Aegis HealthSec Investigation API", version="1.1.0")

    # --- security middleware ------------------------------------------------
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.responses import JSONResponse, Response

    _ALLOWED_ORIGINS = [
        o.strip()
        for o in os.environ.get("AEGIS_CORS_ORIGINS", "http://localhost:8080").split(
            ","
        )
        if o.strip()
    ]

    class SecurityMiddleware(BaseHTTPMiddleware):
        """Adds security headers and enforces a hard request-body-size limit by
        reading the actual bytes (not trusting the Content-Length header)."""

        async def dispatch(self, request: Request, call_next):
            response: Response = await call_next(request)
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["X-Frame-Options"] = "DENY"
            response.headers["Referrer-Policy"] = "no-referrer"
            response.headers["Content-Security-Policy"] = (
                "default-src 'none'; frame-ancestors 'none'"
                if request.url.path.startswith(
                    ("/api/", "/health", "/readiness", "/docs", "/openapi")
                )
                else "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
            )
            response.headers["Cache-Control"] = "no-store"
            response.headers["Permissions-Policy"] = (
                "geolocation=(), camera=(), microphone=()"
            )
            return response

    from .body_limit import BodyLimitMiddleware

    from starlette.middleware.trustedhost import TrustedHostMiddleware

    app.add_middleware(
        TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost", "testserver"]
    )
    app.add_middleware(BodyLimitMiddleware, max_bytes=MAX_BODY_BYTES)
    app.add_middleware(SecurityMiddleware)

    from fastapi.middleware.cors import CORSMiddleware

    # Restrictive CORS: explicit allowlist only (never "*" with credentials).
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_ALLOWED_ORIGINS,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH"],
        allow_headers=["Authorization", "Content-Type"],
    )

    # Generic error handler: never leak internal/DB exception detail to clients.
    from fastapi import HTTPException as _HTTPExc

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception):
        if isinstance(exc, _HTTPExc):
            raise exc
        return JSONResponse(
            status_code=500, content={"detail": "internal server error"}
        )

    engine = db.make_engine()
    SessionFactory = db.make_session_factory(engine)

    # Lazily-built singletons.
    state: Dict[str, Any] = {"pipeline": None, "clinical_detector": None}
    # Per-process login throttle (documented limitation: resets on restart;
    # back with a shared store for multi-process deployments).
    login_throttle = auth.LoginThrottle()

    def get_session():
        s = SessionFactory()
        try:
            yield s
        finally:
            # Roll back any uncommitted (e.g. read-only) transaction so sessions
            # never linger as "idle in transaction" holding locks.
            try:
                s.rollback()
            except Exception:
                pass
            s.close()

    def get_pipeline():
        if state["pipeline"] is None and pipeline_factory is not None:
            state["pipeline"] = pipeline_factory()
        return state["pipeline"]

    def get_clinical_detector():
        if state["clinical_detector"] is None and clinical_detector_factory is not None:
            state["clinical_detector"] = clinical_detector_factory()
        return state["clinical_detector"]

    def current_principal(
        authorization: str = Header(default=""), session=Depends(get_session)
    ) -> Principal:
        if not authorization.lower().startswith("bearer "):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "not authenticated")
        token = authorization.split(" ", 1)[1].strip()
        claims = auth.decode_token(token)
        if claims is None:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "not authenticated")
        # DB-backed resolution: re-validate against the authoritative user row so
        # disabled accounts and stale role/org/token_version fail closed.
        user_row = session.get(db.UserRow, claims.user_id)
        principal = auth.resolve_principal(token, user_row)
        if principal is None:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "not authenticated")
        return principal

    # --- health -------------------------------------------------------------

    @app.get("/health")
    def health():
        from .provenance import (
            APP_VERSION,
            CORE_REVISION,
            RULE_VERSION,
            source_provenance,
        )

        return {
            "status": "ok",
            "time": datetime.now(timezone.utc).isoformat(),
            "version": APP_VERSION,
            "rule_version": RULE_VERSION,
            "core_revision": CORE_REVISION,
            "source": source_provenance(),
        }

    @app.get("/readiness")
    def readiness():
        try:
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            return {"status": "ready", "database": "ok"}
        except Exception:
            # DB down must NOT report healthy, and must NOT leak the connection
            # string or driver error detail to the caller.
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE, "database unavailable"
            )

    # --- auth ---------------------------------------------------------------

    @app.post("/api/v1/auth/token", response_model=TokenResponse)
    def login(body: LoginRequest, request: Request, session=Depends(get_session)):
        client_ip = request.client.host if request.client else "unknown"
        # Throttle brute-force / credential-stuffing by (username, ip). A locked
        # key returns the same generic 401 as a bad credential (no enumeration).
        if login_throttle.is_locked(body.username, client_ip):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid credentials")

        user = session.query(db.UserRow).filter_by(username=body.username).one_or_none()
        if (
            user is None
            or not user.is_active
            or not auth.verify_password(body.password, user.password_hash)
        ):
            # Record failure and return a GENERIC error (no user enumeration,
            # no distinction between unknown user / disabled / bad password).
            login_throttle.record_failure(body.username, client_ip)
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid credentials")

        login_throttle.record_success(body.username, client_ip)
        # Migrate legacy/interim password hashes to Argon2id, but ONLY after a
        # successful verification (verify-then-upgrade). Never weakens security.
        if auth.needs_rehash(user.password_hash):
            try:
                user.password_hash = auth.hash_password(body.password)
                session.commit()
            except Exception:
                session.rollback()  # migration is best-effort; auth already OK
        token = auth.create_access_token(
            user_id=user.id,
            username=user.username,
            role=user.role,
            organization_id=user.organization_id,
            token_version=getattr(user, "token_version", 0),
        )
        return TokenResponse(
            access_token=token, role=user.role, organization_id=user.organization_id
        )

    # --- ingestion ----------------------------------------------------------

    @app.post("/api/v1/events", status_code=status.HTTP_202_ACCEPTED)
    def ingest_events(
        body: ClinicalBatchRequest,
        principal: Principal = Depends(current_principal),
        session=Depends(get_session),
    ):
        if not principal.can_ingest():
            raise HTTPException(status.HTTP_403_FORBIDDEN, "role may not ingest events")
        if len(body.events) > MAX_BATCH:
            raise HTTPException(
                status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                f"batch exceeds max {MAX_BATCH}",
            )
        svc = IngestionService(
            session,
            get_pipeline(),
            correlation_engine=CorrelationEngine(),
            clinical_detector=get_clinical_detector(),
        )
        result = svc.ingest_clinical_batch(
            body.events, organization_id=principal.organization_id
        )
        return result.as_dict()

    @app.post(
        "/api/v1/connectors/fhir/auditevent", status_code=status.HTTP_202_ACCEPTED
    )
    def ingest_fhir_auditevent(
        body: Dict[str, Any],
        principal: Principal = Depends(current_principal),
        session=Depends(get_session),
    ):
        """Ingest HL7 FHIR R4 AuditEvent(s): a single resource, a Bundle, or a
        {"resources": [...]} list. Parsed + normalized by the FHIR connector,
        then run through the existing detection -> correlation -> persistence
        flow. Organization is taken from the caller's token."""
        if not principal.can_ingest():
            raise HTTPException(status.HTTP_403_FORBIDDEN, "role may not ingest events")
        from .connectors.fhir_auditevent import FhirAuditEventConnector
        from .connectors.base import ConnectorError

        payload = (
            body.get("resources", body)
            if isinstance(body, dict) and "resources" in body
            else body
        )
        connector = FhirAuditEventConnector()
        try:
            parsed = connector.parse(
                payload, organization_id=principal.organization_id, max_items=MAX_BATCH
            )
        except ConnectorError as exc:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc))
        svc = IngestionService(
            session,
            get_pipeline(),
            correlation_engine=CorrelationEngine(),
            clinical_detector=get_clinical_detector(),
        )
        result = svc.ingest_normalized_events(
            parsed.events, organization_id=principal.organization_id
        )
        out = result.as_dict()
        out["connector"] = parsed.as_summary()  # per-item parse errors surfaced
        return out

    # --- Local investigation workbench --------------------------------------
    from .workbench import execute_run, latest_run, sha
    from .connectors.base import ConnectorError
    from sqlalchemy import select, func
    from contextlib import contextmanager
    import threading
    import time
    import uuid
    import json
    from collections import deque

    workbench_slots = threading.BoundedSemaphore(2)
    workbench_rates = {}
    rate_lock = threading.Lock()

    @contextmanager
    def bounded_work(principal):
        # Process-wide bound includes all organizations. Requests rejected before
        # detector work, without a background queue or external destinations.
        with rate_lock:
            now = time.monotonic()
            for key in list(workbench_rates):
                if not workbench_rates[key] or workbench_rates[key][-1] < now - 60:
                    del workbench_rates[key]
            hits = workbench_rates.setdefault(principal.organization_id, deque())
            while hits and hits[0] < now - 60:
                hits.popleft()
            if len(hits) >= 30:
                raise HTTPException(429, "workbench rate limit; retry in one minute")
            hits.append(now)
        if not workbench_slots.acquire(blocking=False):
            raise HTTPException(429, "workbench busy; retry later")
        try:
            yield
        finally:
            workbench_slots.release()

    def load_case(session, case_id, principal, *, lock=False):
        stmt = select(db.WorkbenchCaseRow).where(
            db.WorkbenchCaseRow.case_id == case_id,
            db.WorkbenchCaseRow.organization_id == principal.organization_id,
        )
        if lock:
            stmt = stmt.with_for_update()
        case = session.execute(stmt).scalar_one_or_none()
        if case is None:
            raise HTTPException(404, "case not found")
        return case

    def run_case(session, case, config):
        try:
            report = execute_run(session, case, config)
            session.commit()
            return report
        except ConnectorError as exc:
            session.rollback()
            raise HTTPException(422, str(exc)) from None

    @app.get("/api/v1/workbench/sample")
    def workbench_sample(principal: Principal = Depends(current_principal)):
        from .sample import synthetic_sample

        return {
            "input_text": json.dumps(synthetic_sample(), indent=2),
            "label": "Synthetic local sample; 30 successful reads of distinct synthetic patients",
        }

    @app.get("/api/v1/workbench/cases")
    def workbench_cases(
        principal: Principal = Depends(current_principal), session=Depends(get_session)
    ):
        rows = session.execute(
            select(db.WorkbenchCaseRow)
            .where(db.WorkbenchCaseRow.organization_id == principal.organization_id)
            .order_by(db.WorkbenchCaseRow.created_at.desc())
            .limit(100)
        ).scalars()
        return {
            "items": [
                {
                    "case_id": c.case_id,
                    "title": c.title,
                    "created_at": c.created_at.isoformat(),
                }
                for c in rows
            ]
        }

    @app.post("/api/v1/workbench/cases", status_code=201)
    def workbench_import(
        body: CaseImport,
        principal: Principal = Depends(current_principal),
        session=Depends(get_session),
    ):
        if not principal.can_ingest():
            raise HTTPException(403, "role may not import investigations")
        with bounded_work(principal):
            from .sample import synthetic_sample

            # Only exact trusted sample bytes/structure earn a synthetic label.
            origin = "unspecified"
            try:
                if json.loads(body.input_text) == synthetic_sample():
                    origin = "synthetic"
            except (ValueError, RecursionError):
                pass
            if (
                session.scalar(
                    select(func.count())
                    .select_from(db.WorkbenchCaseRow)
                    .where(
                        db.WorkbenchCaseRow.organization_id == principal.organization_id
                    )
                )
                >= 100
            ):
                raise HTTPException(409, "local organization case quota reached (100)")
            case = db.WorkbenchCaseRow(
                case_id="case-" + uuid.uuid4().hex,
                organization_id=principal.organization_id,
                title=body.title,
                input_text=body.input_text,
                input_sha256=sha(body.input_text),
                origin=origin,
            )
            session.add(case)
            session.flush()
            return run_case(session, case, body.config)

    @app.get("/api/v1/workbench/cases/{case_id}")
    def workbench_case(
        case_id: str,
        principal: Principal = Depends(current_principal),
        session=Depends(get_session),
    ):
        load_case(session, case_id, principal)
        rows = (
            session.execute(
                select(db.WorkbenchRunRow)
                .where(
                    db.WorkbenchRunRow.case_id == case_id,
                    db.WorkbenchRunRow.organization_id == principal.organization_id,
                )
                .order_by(db.WorkbenchRunRow.created_at, db.WorkbenchRunRow.run_id)
            )
            .scalars()
            .all()
        )
        return {"runs": [row.report for row in rows]}

    @app.post("/api/v1/workbench/cases/{case_id}/runs", status_code=201)
    def workbench_rerun(
        case_id: str,
        body: CaseRerun,
        principal: Principal = Depends(current_principal),
        session=Depends(get_session),
    ):
        if not principal.can_ingest():
            raise HTTPException(403, "role may not rerun investigations")
        with bounded_work(principal):
            case = load_case(session, case_id, principal, lock=True)
            if (
                session.scalar(
                    select(func.count())
                    .select_from(db.WorkbenchRunRow)
                    .where(db.WorkbenchRunRow.case_id == case.case_id)
                )
                >= 20
            ):
                raise HTTPException(409, "case run quota reached (20)")
            previous = latest_run(session, case.case_id)
            if previous is None or previous.run_id != body.expected_run_id:
                raise HTTPException(409, "case changed; reload before rerunning")
            return run_case(session, case, body.config)

    @app.get("/api/v1/workbench/cases/{case_id}/runs/{run_id}/export")
    def workbench_export(
        case_id: str,
        run_id: str,
        principal: Principal = Depends(current_principal),
        session=Depends(get_session),
    ):
        from .workbench import canonical

        load_case(session, case_id, principal)
        row = session.execute(
            select(db.WorkbenchRunRow).where(
                db.WorkbenchRunRow.case_id == case_id,
                db.WorkbenchRunRow.run_id == run_id,
                db.WorkbenchRunRow.organization_id == principal.organization_id,
            )
        ).scalar_one_or_none()
        if row is None:
            raise HTTPException(404, "run not found")
        payload = canonical(row.report)
        return Response(
            content=payload,
            media_type="application/json",
            headers={
                "Content-Disposition": f'attachment; filename="{row.run_id}.json"',
                "X-Report-SHA256": sha(payload),
            },
        )

    # --- incidents ----------------------------------------------------------

    def _incident_dict(row) -> Dict[str, Any]:
        return {
            "incident_id": row.incident_id,
            "title": row.title,
            "description": row.description,
            "severity": row.severity,
            "status": row.status,
            "created_at": row.created_at.isoformat(),
            "updated_at": row.updated_at.isoformat(),
            "first_seen": row.first_seen.isoformat() if row.first_seen else None,
            "last_seen": row.last_seen.isoformat() if row.last_seen else None,
            "assigned_analyst": row.assigned_analyst,
            "correlation_reason": row.correlation_reason,
            "affected_entities": row.affected_entities,
            "resolution_summary": row.resolution_summary,
            "close_reason": row.close_reason,
            "row_version": row.row_version,
            "organization_id": row.organization_id,
        }

    @app.get("/api/v1/incidents")
    def list_incidents(
        principal: Principal = Depends(current_principal),
        session=Depends(get_session),
        status_filter: Optional[str] = Query(default=None, alias="status"),
        severity: Optional[str] = None,
        limit: int = Query(default=50, le=200),
        offset: int = 0,
    ):
        repo = Repository(session)
        rows, total = repo.list_incidents(
            principal.organization_id,
            status=status_filter,
            severity=severity,
            limit=limit,
            offset=offset,
        )
        return {
            "total": total,
            "items": [
                {
                    **_incident_dict(r),
                    "related_finding_count": len(repo.incident_findings(r.incident_id)),
                }
                for r in rows
            ],
        }

    def _load_incident_or_404(repo, incident_id, principal):
        row = repo.get_incident(incident_id, principal.organization_id)
        if row is None:
            # 404 (not 403) to avoid leaking existence across orgs.
            raise HTTPException(status.HTTP_404_NOT_FOUND, "incident not found")
        return row

    @app.get("/api/v1/incidents/{incident_id}")
    def get_incident(
        incident_id: str,
        principal: Principal = Depends(current_principal),
        session=Depends(get_session),
    ):
        repo = Repository(session)
        row = _load_incident_or_404(repo, incident_id, principal)
        return _incident_dict(row)

    @app.get("/api/v1/incidents/{incident_id}/evidence")
    def incident_evidence(
        incident_id: str,
        principal: Principal = Depends(current_principal),
        session=Depends(get_session),
    ):
        repo = Repository(session)
        _load_incident_or_404(repo, incident_id, principal)
        findings = repo.incident_findings(incident_id)
        events = repo.incident_events(incident_id)
        return {
            "findings": [
                {
                    "finding_id": f.finding_id,
                    "rule_id": f.rule_id,
                    "severity": f.severity,
                    "confidence": f.confidence,
                    "description": f.description,
                    "attack_techniques": f.mapped_attack_techniques,
                    "evidence": f.evidence_references,
                }
                for f in findings
            ],
            "events": [
                {
                    "event_id": e.event_id,
                    "source_type": e.source_type,
                    "action": e.action,
                    "outcome": e.outcome,
                    "timestamp": e.event_timestamp.isoformat(),
                }
                for e in events
            ],
        }

    @app.get("/api/v1/incidents/{incident_id}/timeline")
    def incident_timeline(
        incident_id: str,
        principal: Principal = Depends(current_principal),
        session=Depends(get_session),
    ):
        _load_incident_or_404(Repository(session), incident_id, principal)
        return {
            "timeline": InvestigationService(session).timeline(
                incident_id, principal.organization_id
            )
        }

    @app.get("/api/v1/incidents/{incident_id}/history")
    def incident_history(
        incident_id: str,
        principal: Principal = Depends(current_principal),
        session=Depends(get_session),
    ):
        repo = Repository(session)
        _load_incident_or_404(repo, incident_id, principal)
        return {
            "actions": [
                {
                    "action_id": a.action_id,
                    "analyst_id": a.analyst_id,
                    "action_type": a.action_type,
                    "previous_value": a.previous_value,
                    "updated_value": a.updated_value,
                    "note": a.note,
                    "timestamp": a.timestamp.isoformat(),
                }
                for a in repo.incident_actions(incident_id)
            ]
        }

    def _require_write(principal: Principal):
        if not principal.can_write_incidents():
            raise HTTPException(
                status.HTTP_403_FORBIDDEN, "role may not modify incidents"
            )

    @app.post("/api/v1/incidents/{incident_id}/assign")
    def assign(
        incident_id: str,
        body: AssignRequest,
        principal: Principal = Depends(current_principal),
        session=Depends(get_session),
    ):
        _require_write(principal)
        svc = InvestigationService(session)
        _load_incident_or_404(svc.repo, incident_id, principal)
        svc.assign(
            incident_id,
            principal.organization_id,
            analyst_id=body.analyst_id,
            actor=principal.username,
        )
        return {"ok": True}

    @app.post("/api/v1/incidents/{incident_id}/notes")
    def add_note(
        incident_id: str,
        body: NoteRequest,
        principal: Principal = Depends(current_principal),
        session=Depends(get_session),
    ):
        _require_write(principal)
        svc = InvestigationService(session)
        _load_incident_or_404(svc.repo, incident_id, principal)
        svc.add_note(
            incident_id,
            principal.organization_id,
            note=body.note,
            actor=principal.username,
        )
        return {"ok": True}

    @app.patch("/api/v1/incidents/{incident_id}")
    def change_status(
        incident_id: str,
        body: StatusChangeRequest,
        principal: Principal = Depends(current_principal),
        session=Depends(get_session),
    ):
        _require_write(principal)
        svc = InvestigationService(session)
        _load_incident_or_404(svc.repo, incident_id, principal)
        try:
            svc.change_status(
                incident_id,
                principal.organization_id,
                new_status=body.status,
                actor=principal.username,
                expected_version=body.expected_version,
            )
        except InvalidTransition as exc:
            raise HTTPException(status.HTTP_409_CONFLICT, str(exc))
        except Exception as exc:
            if "ConcurrencyError" in type(exc).__name__:
                raise HTTPException(status.HTTP_409_CONFLICT, str(exc))
            raise
        return {"ok": True}

    @app.post("/api/v1/incidents/{incident_id}/disposition")
    def disposition(
        incident_id: str,
        body: DispositionRequest,
        principal: Principal = Depends(current_principal),
        session=Depends(get_session),
    ):
        _require_write(principal)
        svc = InvestigationService(session)
        _load_incident_or_404(svc.repo, incident_id, principal)
        svc.record_disposition(
            incident_id,
            principal.organization_id,
            disposition=body.disposition,
            summary=body.summary,
            actor=principal.username,
        )
        return {"ok": True}

    @app.post("/api/v1/incidents/{incident_id}/close")
    def close(
        incident_id: str,
        body: CloseRequest,
        principal: Principal = Depends(current_principal),
        session=Depends(get_session),
    ):
        _require_write(principal)
        svc = InvestigationService(session)
        _load_incident_or_404(svc.repo, incident_id, principal)
        try:
            svc.close(
                incident_id,
                principal.organization_id,
                reason=body.reason,
                actor=principal.username,
            )
        except InvalidTransition as exc:
            raise HTTPException(status.HTTP_409_CONFLICT, str(exc))
        return {"ok": True}

    @app.get("/api/v1/incidents/{incident_id}/export")
    def export_incident(
        incident_id: str,
        principal: Principal = Depends(current_principal),
        session=Depends(get_session),
    ):
        repo = Repository(session)
        row = _load_incident_or_404(repo, incident_id, principal)
        return {
            "incident": _incident_dict(row),
            "findings": [
                {
                    "finding_id": f.finding_id,
                    "rule_id": f.rule_id,
                    "severity": f.severity,
                    "attack_techniques": f.mapped_attack_techniques,
                    "evidence": f.evidence_references,
                }
                for f in repo.incident_findings(incident_id)
            ],
            "events": [
                {
                    "event_id": e.event_id,
                    "source_type": e.source_type,
                    "action": e.action,
                    "outcome": e.outcome,
                    "timestamp": e.event_timestamp.isoformat(),
                }
                for e in repo.incident_events(incident_id)
            ],
            "history": [
                {
                    "analyst_id": a.analyst_id,
                    "action_type": a.action_type,
                    "previous_value": a.previous_value,
                    "updated_value": a.updated_value,
                    "note": a.note,
                    "timestamp": a.timestamp.isoformat(),
                }
                for a in repo.incident_actions(incident_id)
            ],
        }

    app.state.engine = engine
    app.state.session_factory = SessionFactory
    return app
