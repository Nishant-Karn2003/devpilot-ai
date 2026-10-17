import ast
import difflib
import json
import logging
import re
import uuid
from contextlib import asynccontextmanager
from contextvars import ContextVar
from datetime import UTC, datetime
from pathlib import PurePosixPath, PureWindowsPath

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from app.analysis import FindingData, analyze_source, redact_secrets
from app.config import get_settings
from app.database import SessionLocal, get_db
from app.dependencies import ManifestError, VulnerabilityServiceError, inspect_manifest, query_osv
from app.llm import ProviderError, request_review
from app.models import Analysis, AuditEvent, DependencyScan, Finding, PatchSuggestion, User
from app.quality import evaluate_quality_gate
from app.schemas import (
    AnalysisRequest,
    AnalysisResponse,
    Credentials,
    DependencyScanRequest,
    DependencyScanResponse,
    DiffRequest,
    PatchDecision,
    PatchSuggestionResponse,
    TokenResponse,
)
from app.security import create_access_token, current_user, hash_password, verify_password

request_id_context: ContextVar[str | None] = ContextVar("request_id", default=None)


class JsonLogFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        return json.dumps(
            {
                "timestamp": datetime.now(UTC).isoformat(),
                "level": record.levelname,
                "logger": record.name,
                "request_id": getattr(record, "request_id", None),
                "message": record.getMessage(),
            }
        )


class RequestIdFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = request_id_context.get()
        return True


root_logger = logging.getLogger()
root_logger.setLevel(logging.INFO)
if not any(getattr(handler, "_devpilot_json", False) for handler in root_logger.handlers):
    json_handler = logging.StreamHandler()
    json_handler.setFormatter(JsonLogFormatter())
    json_handler.addFilter(RequestIdFilter())
    json_handler._devpilot_json = True
    root_logger.addHandler(json_handler)
logger = logging.getLogger("devpilot")


class RequestSizeLimitMiddleware:
    def __init__(self, app, max_body_bytes: int = 4_000_000):
        self.app = app
        self.max_body_bytes = max_body_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = dict(scope.get("headers", []))
        content_length = headers.get(b"content-length")
        if content_length:
            try:
                declared_size = int(content_length)
            except ValueError:
                declared_size = 0
            if declared_size > self.max_body_bytes:
                await self._reject(send)
                return

        messages = []
        total_size = 0
        while True:
            message = await receive()
            messages.append(message)
            if message["type"] == "http.request":
                total_size += len(message.get("body", b""))
                if total_size > self.max_body_bytes:
                    await self._reject(send)
                    return
                if not message.get("more_body", False):
                    break
            elif message["type"] == "http.disconnect":
                break

        async def replay_body():
            if messages:
                return messages.pop(0)
            return await receive()

        await self.app(scope, replay_body, send)

    async def _reject(self, send):
        body = b'{"detail":"Request body exceeds the configured size limit"}'
        await send(
            {
                "type": "http.response.start",
                "status": status.HTTP_413_CONTENT_TOO_LARGE,
                "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())],
            }
        )
        await send({"type": "http.response.body", "body": body})


@asynccontextmanager
async def lifespan(_: FastAPI):
    yield


app = FastAPI(title="DevPilot AI API", version="0.1.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[get_settings().frontend_origin],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
)
app.add_middleware(RequestSizeLimitMiddleware, max_body_bytes=4_000_000)


@app.middleware("http")
async def add_request_id(request, call_next):
    supplied_id = request.headers.get("X-Request-ID", "")
    request_id = supplied_id if re.fullmatch(r"[A-Za-z0-9._-]{1,64}", supplied_id) else str(uuid.uuid4())
    context_token = request_id_context.set(request_id)
    try:
        response = await call_next(request)
    finally:
        request_id_context.reset(context_token)
    response.headers["X-Request-ID"] = request_id
    return response


@app.get("/health")
def health(db: Session = Depends(get_db)):
    try:
        db.execute(select(1))
    except Exception as exc:
        logger.error("Database health check failed error_type=%s", type(exc).__name__)
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Database unavailable") from exc
    settings = get_settings()
    return {
        "status": "ok",
        "database": "ok",
        "llm_configured": bool(settings.llm_base_url and settings.llm_api_key and settings.llm_model),
    }


@app.post("/api/auth/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
def register(payload: Credentials, db: Session = Depends(get_db)):
    email = payload.email.lower()
    if db.scalar(select(User).where(User.email == email)):
        raise HTTPException(status.HTTP_409_CONFLICT, "An account with this email already exists")
    user = User(email=email, password_hash=hash_password(payload.password))
    db.add(user)
    try:
        db.flush()
        db.add(AuditEvent(user_id=user.id, action="auth.register"))
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, "An account with this email already exists") from exc
    db.refresh(user)
    return TokenResponse(access_token=create_access_token(user.id), user=user)


@app.post("/api/auth/login", response_model=TokenResponse)
def login(payload: Credentials, db: Session = Depends(get_db)):
    user = db.scalar(select(User).where(User.email == payload.email.lower()))
    if user is None or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid email or password")
    db.add(AuditEvent(user_id=user.id, action="auth.login"))
    db.commit()
    return TokenResponse(access_token=create_access_token(user.id), user=user)


@app.get("/api/auth/me")
def me(user: User = Depends(current_user)):
    return {"id": user.id, "email": user.email, "created_at": user.created_at}


@app.post("/api/analyses", response_model=AnalysisResponse, status_code=status.HTTP_202_ACCEPTED)
def submit_analysis(
    payload: AnalysisRequest,
    background: BackgroundTasks,
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    if len(payload.code.encode("utf-8")) > get_settings().max_source_bytes:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "Source exceeds configured size limit")
    analysis = Analysis(
        owner_id=user.id,
        language=payload.language,
        source_name=payload.file_name,
        source_code=payload.code,
        status="queued",
        gate_threshold=payload.fail_on_severity,
    )
    db.add(analysis)
    db.add(AuditEvent(user_id=user.id, action="analysis.submitted", resource_id=analysis.id))
    db.commit()
    db.refresh(analysis)
    background.add_task(run_analysis, analysis.id)
    return analysis


def run_analysis(analysis_id: str) -> None:
    db = SessionLocal()
    try:
        analysis = db.get(Analysis, analysis_id)
        if analysis is None:
            return
        analysis.status = "running"
        db.commit()
        findings, summary = analyze_source(
            analysis.source_code,
            analysis.language,
            _analysis_file_path(analysis),
        )
        analysis.findings = [
            Finding(
                fingerprint=item.fingerprint,
                file_path=item.file_path,
                line=item.line,
                column=item.column,
                end_line=item.end_line,
                end_column=item.end_column,
                rule_id=item.rule_id,
                analyzer=item.analyzer,
                severity=item.severity,
                category=item.category,
                title=item.title,
                description=item.description,
                evidence=item.evidence,
                remediation=item.remediation,
                origin=item.origin,
            )
            for item in findings
        ]
        analysis.summary = summary
        analysis.quality_gate = evaluate_quality_gate(findings, summary, analysis.gate_threshold)
        analysis.status = "completed"
        analysis.completed_at = datetime.now(UTC)
        db.commit()
        logger.info("Analysis completed id=%s findings=%d", analysis_id, len(findings))
    except Exception as exc:
        db.rollback()
        analysis = db.get(Analysis, analysis_id)
        if analysis:
            analysis.status = "failed"
            analysis.error_message = "Analysis failed; check server logs using the request ID."
            analysis.completed_at = datetime.now(UTC)
            db.commit()
        logger.error("Analysis failed id=%s error_type=%s", analysis_id, type(exc).__name__)
    finally:
        db.close()


def _analysis_file_path(analysis: Analysis) -> str:
    if analysis.mode == "diff" and analysis.source_name.startswith("diff: "):
        return analysis.source_name.removeprefix("diff: ")
    return analysis.source_name


@app.get("/api/analyses", response_model=list[AnalysisResponse])
def list_analyses(
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    rows = db.scalars(
        select(Analysis)
        .where(Analysis.owner_id == user.id)
        .options(selectinload(Analysis.findings), selectinload(Analysis.patch_suggestions))
        .order_by(Analysis.created_at.desc())
        .limit(limit)
        .offset(offset)
    ).all()
    return rows


@app.get("/api/analyses/{analysis_id}", response_model=AnalysisResponse)
def get_analysis(analysis_id: str, db: Session = Depends(get_db), user: User = Depends(current_user)):
    analysis = db.scalar(
        select(Analysis)
        .where(Analysis.id == analysis_id, Analysis.owner_id == user.id)
        .options(selectinload(Analysis.findings), selectinload(Analysis.patch_suggestions))
    )
    if analysis is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Analysis not found")
    return analysis


@app.post("/api/analyses/{analysis_id}/ai-review")
def ai_review(analysis_id: str, db: Session = Depends(get_db), user: User = Depends(current_user)):
    analysis = db.scalar(select(Analysis).where(Analysis.id == analysis_id, Analysis.owner_id == user.id))
    if analysis is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Analysis not found")
    try:
        review = request_review(redact_secrets(analysis.source_code), analysis.language)
    except ProviderError as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc)) from exc
    reviewed_source = redact_secrets(analysis.source_code)
    lines = reviewed_source.splitlines()
    saved = []
    for item in review.findings:
        if item.line and (item.line > len(lines) or item.evidence not in lines[item.line - 1]):
            raise HTTPException(
                status.HTTP_502_BAD_GATEWAY,
                "AI review returned evidence that does not match the source",
            )
        if not item.line and item.evidence not in reviewed_source:
            raise HTTPException(
                status.HTTP_502_BAD_GATEWAY,
                "AI review returned evidence that does not match the source",
            )
        duplicate = any(
            existing.line == item.line
            and existing.category == item.category
            and existing.title.casefold().strip() == item.title.casefold().strip()
            for existing in analysis.findings
        )
        if duplicate:
            continue
        title = redact_secrets(item.title)
        description = redact_secrets(item.description)
        evidence = redact_secrets(item.evidence)
        remediation = redact_secrets(item.remediation)
        data = FindingData(
            file_path=_analysis_file_path(analysis),
            line=item.line,
            column=None,
            end_line=item.line,
            end_column=None,
            rule_id=f"ai.{item.category}",
            analyzer="llm-review",
            severity=item.severity,
            category=item.category,
            title=title,
            description=description,
            evidence=evidence,
            remediation=remediation,
            origin="ai",
        )
        saved.append(
            Finding(
                analysis_id=analysis.id,
                fingerprint=data.fingerprint,
                file_path=data.file_path,
                line=data.line,
                column=data.column,
                end_line=data.end_line,
                end_column=data.end_column,
                rule_id=data.rule_id,
                analyzer=data.analyzer,
                severity=data.severity,
                category=data.category,
                title=data.title,
                description=data.description,
                evidence=data.evidence,
                remediation=data.remediation,
                origin=data.origin,
            )
        )
    db.add_all(saved)
    db.commit()
    return {
        "analysis_id": analysis_id,
        "added_findings": len(saved),
        "provider": get_settings().llm_model,
    }


@app.post(
    "/api/analyses/{analysis_id}/patch-suggestions",
    response_model=PatchSuggestionResponse,
    status_code=201,
)
def create_patch_suggestion(
    analysis_id: str,
    finding_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    analysis = db.scalar(select(Analysis).where(Analysis.id == analysis_id, Analysis.owner_id == user.id))
    if analysis is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Analysis not found")
    issue = db.scalar(select(Finding).where(Finding.id == finding_id, Finding.analysis_id == analysis_id))
    if issue is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Finding not found")
    if issue.rule_id != "python.unused-import" or issue.line is None:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            "No validated safe patch is available for this rule",
        )
    source_lines = analysis.source_code.splitlines(keepends=True)
    index = issue.line - 1
    if index >= len(source_lines):
        raise HTTPException(status.HTTP_409_CONFLICT, "Finding source location no longer matches the stored source")
    candidate = source_lines[index]
    try:
        tree = ast.parse(analysis.source_code)
    except SyntaxError as exc:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "Cannot suggest a patch for syntactically invalid source"
        ) from exc
    node = next(
        (
            item
            for item in ast.walk(tree)
            if isinstance(item, (ast.Import, ast.ImportFrom)) and item.lineno == issue.line
        ),
        None,
    )
    if node is None or node.end_lineno != issue.line or len(node.names) != 1 or ";" in candidate or "#" in candidate:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "Import is not a single-line standalone statement")
    before = "".join(source_lines)
    after = "".join(source_lines[:index] + source_lines[index + 1 :])
    patch = "".join(
        difflib.unified_diff(
            before.splitlines(keepends=True),
            after.splitlines(keepends=True),
            fromfile=f"a/{analysis.source_name}",
            tofile=f"b/{analysis.source_name}",
        )
    )
    if not patch:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "Could not construct a non-empty patch")
    suggestion = PatchSuggestion(
        analysis_id=analysis_id,
        finding_id=finding_id,
        patch=patch,
        explanation=(
            "Remove this standalone unused import. The source is unchanged; inspect and validate "
            "the proposed diff before using it."
        ),
    )
    db.add(suggestion)
    db.add(AuditEvent(user_id=user.id, action="patch.suggested", resource_id=suggestion.id))
    db.commit()
    db.refresh(suggestion)
    return suggestion


@app.patch("/api/patch-suggestions/{suggestion_id}", response_model=PatchSuggestionResponse)
def decide_patch(
    suggestion_id: str,
    payload: PatchDecision,
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    suggestion = db.scalar(
        select(PatchSuggestion)
        .join(Analysis, Analysis.id == PatchSuggestion.analysis_id)
        .where(PatchSuggestion.id == suggestion_id, Analysis.owner_id == user.id)
    )
    if suggestion is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Patch suggestion not found")
    if suggestion.status != "pending":
        raise HTTPException(status.HTTP_409_CONFLICT, "Patch suggestion has already been reviewed")
    suggestion.status = payload.decision
    suggestion.reviewed_at = datetime.now(UTC)
    db.add(AuditEvent(user_id=user.id, action=f"patch.{payload.decision}", resource_id=suggestion.id))
    db.commit()
    db.refresh(suggestion)
    return suggestion


@app.post(
    "/api/dependency-scans",
    response_model=DependencyScanResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
def submit_dependency_scan(
    payload: DependencyScanRequest,
    background: BackgroundTasks,
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    if len(payload.manifest.encode()) > 1_000_000 or (payload.lockfile and len(payload.lockfile.encode()) > 2_000_000):
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "Manifest exceeds the configured size limit")
    try:
        inventory, warnings = inspect_manifest(payload.ecosystem, payload.manifest, payload.lockfile)
    except ManifestError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    if len(inventory) > 500:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "A scan is limited to 500 package records")
    scan = DependencyScan(
        owner_id=user.id,
        ecosystem=payload.ecosystem,
        inventory=inventory,
        warnings=warnings,
        status="queued",
    )
    db.add(scan)
    db.add(AuditEvent(user_id=user.id, action="dependencies.submitted", resource_id=scan.id))
    db.commit()
    db.refresh(scan)
    background.add_task(run_dependency_scan, scan.id)
    return scan


def run_dependency_scan(scan_id: str) -> None:
    db = SessionLocal()
    try:
        scan = db.get(DependencyScan, scan_id)
        if scan is None:
            return
        scan.status = "running"
        db.commit()
        scan.vulnerabilities = query_osv(scan.inventory)
        if not any(item.get("resolved_version") for item in scan.inventory):
            scan.warnings = [
                *scan.warnings,
                "No exact resolved versions were supplied; vulnerability lookup was skipped.",
            ]
        scan.status = "completed"
        scan.completed_at = datetime.now(UTC)
        db.commit()
        logger.info(
            "Dependency scan completed id=%s packages=%d advisories=%d",
            scan_id,
            len(scan.inventory),
            len(scan.vulnerabilities),
        )
    except VulnerabilityServiceError as exc:
        db.rollback()
        scan = db.get(DependencyScan, scan_id)
        if scan:
            scan.status = "failed"
            scan.error_message = str(exc)
            scan.completed_at = datetime.now(UTC)
            db.commit()
        logger.warning("Dependency scan failed id=%s error_type=%s", scan_id, type(exc).__name__)
    except Exception as exc:
        db.rollback()
        scan = db.get(DependencyScan, scan_id)
        if scan:
            scan.status = "failed"
            scan.error_message = "Dependency scan failed; check server logs using the scan ID."
            scan.completed_at = datetime.now(UTC)
            db.commit()
        logger.error("Dependency scan failed id=%s error_type=%s", scan_id, type(exc).__name__)
    finally:
        db.close()


@app.get("/api/dependency-scans", response_model=list[DependencyScanResponse])
def list_dependency_scans(
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    return db.scalars(
        select(DependencyScan)
        .where(DependencyScan.owner_id == user.id)
        .order_by(DependencyScan.created_at.desc())
        .limit(limit)
        .offset(offset)
    ).all()


@app.get("/api/dependency-scans/{scan_id}", response_model=DependencyScanResponse)
def get_dependency_scan(scan_id: str, db: Session = Depends(get_db), user: User = Depends(current_user)):
    scan = db.scalar(select(DependencyScan).where(DependencyScan.id == scan_id, DependencyScan.owner_id == user.id))
    if scan is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Dependency scan not found")
    return scan


@app.get("/api/analytics/overview")
def analytics(db: Session = Depends(get_db), user: User = Depends(current_user)):
    total = db.scalar(select(func.count()).select_from(Analysis).where(Analysis.owner_id == user.id)) or 0
    severity = db.execute(
        select(Finding.severity, func.count(Finding.id))
        .join(Analysis, Analysis.id == Finding.analysis_id)
        .where(Analysis.owner_id == user.id)
        .group_by(Finding.severity)
    ).all()
    recent = db.scalars(
        select(Analysis)
        .where(Analysis.owner_id == user.id)
        .options(selectinload(Analysis.findings))
        .order_by(Analysis.created_at.desc())
        .limit(5)
    ).all()
    return {
        "analysis_count": total,
        "severity_distribution": {name: count for name, count in severity},
        "recent_analyses": [
            {
                "id": row.id,
                "status": row.status,
                "language": row.language,
                "source_name": row.source_name,
                "created_at": row.created_at,
                "findings": len(row.findings),
            }
            for row in recent
        ],
        "snapshot_note": "Metrics are calculated from this user's persisted analyses.",
    }


@app.post("/api/diffs", response_model=AnalysisResponse, status_code=status.HTTP_202_ACCEPTED)
def submit_diff(
    payload: DiffRequest,
    background: BackgroundTasks,
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    added_files = parse_added_diff(payload.diff)
    if not added_files:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "Diff contains no analyzable added lines")
    if len({path for path, _ in added_files}) > 1:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            "Submit one changed source file per diff analysis.",
        )
    code = "\n".join(text for _, text in added_files)
    # Diffs can contain multiple files; keep bounded and preserve provenance in the report name.
    if len(code.encode()) > get_settings().max_source_bytes:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "Diff additions exceed configured size limit")
    language = _language_for_path(added_files[0][0])
    if language is None:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            "First changed file is not Python, JavaScript, or TypeScript",
        )
    analysis = Analysis(
        owner_id=user.id,
        language=language,
        source_name=f"diff: {added_files[0][0]}",
        source_code=code,
        mode="diff",
        gate_threshold=payload.fail_on_severity,
    )
    db.add(analysis)
    db.add(AuditEvent(user_id=user.id, action="diff.submitted", resource_id=analysis.id))
    db.commit()
    db.refresh(analysis)
    background.add_task(run_analysis, analysis.id)
    return analysis


def parse_added_diff(diff: str) -> list[tuple[str, str]]:
    results = []
    current_file = None
    in_hunk = False
    for line in diff.splitlines():
        if line.startswith("+++ "):
            name = line[4:].strip()
            current_file = name[2:] if name.startswith("b/") else name
            if current_file == "/dev/null":
                current_file = None
            elif not _safe_relative_path(current_file):
                raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "Diff contains an unsafe file path")
        elif line.startswith("@@"):
            in_hunk = True
        elif line.startswith("diff --git "):
            in_hunk = False
        elif in_hunk and current_file and line.startswith("+") and not line.startswith("+++"):
            results.append((current_file, line[1:]))
    return results


def _safe_relative_path(value: str) -> bool:
    posix = PurePosixPath(value)
    windows = PureWindowsPath(value)
    return (
        bool(value)
        and "\x00" not in value
        and value not in {".", ".."}
        and not posix.is_absolute()
        and not windows.is_absolute()
        and not windows.drive
        and all(part not in {".", ".."} for part in (*posix.parts, *windows.parts))
    )


def _language_for_path(path: str) -> str | None:
    lower = path.lower()
    if lower.endswith(".py"):
        return "python"
    if lower.endswith((".js", ".jsx", ".mjs", ".cjs")):
        return "javascript"
    if lower.endswith((".ts", ".tsx", ".mts", ".cts")):
        return "typescript"
    return None
