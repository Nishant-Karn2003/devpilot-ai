# Architecture and tradeoffs

## Shape

DevPilot is a modular monolith: a React/TypeScript single-page application, a synchronous FastAPI application, SQLAlchemy persistence, and Alembic migrations. PostgreSQL is the Compose database; the same model layer supports SQLite. There is no Redis/task queue because current analysis is bounded, text-only, and short-running. FastAPI `BackgroundTasks` keeps submission responses non-blocking but does not provide durable delivery; this tradeoff is explicit and is not suitable for reliability-critical production jobs.

```text
Browser (React + Query + Monaco)
    | same-origin Vite proxy in development
FastAPI: auth / analysis / diff / dependencies / reports / quality gates / AI / patch review
    | SQLAlchemy session transactions
SQLite (local) or PostgreSQL (Compose)
    | bounded trusted subprocess, no shell
ESLint CLI (only when installed) + built-in Python AST and secret-pattern analyzers
```

## Analysis flow

1. Validate authenticated request fields, language, filename path, and byte limit.
2. Persist a `queued` analysis owned by the user and schedule its identifier with FastAPI.
3. Mark it running, analyze the stored source as data (never execute it), normalize/deduplicate findings, evaluate the configured default severity threshold, and persist results and completion time.
4. On failure, record a generic user-visible message and log only analysis ID and exception type; do not log source, secrets, provider tokens, or database exception payloads.
5. Reports and analytics always filter by the owning user.

Python parsing uses `ast.parse`. JavaScript/TypeScript invokes a fixed local ESLint CLI using an argument list, stdin, a 10-second timeout and no shell when available. Without that tool, a conservative delimiter validator is explicitly reported. Secret scans are heuristics and can have false positives/negatives.

## Persistence

`users`, `analyses`, `findings`, `audit_events`, `patch_suggestions`, and `dependency_scans` have foreign keys and indexes. Alembic revisions create core tables, patch decisions, dependency reports, and per-analysis gate thresholds. Source submitted for analysis is retained with its report in the database. Apply migrations with `python -m alembic upgrade head`; startup does not delete or recreate data.

## Observability

Application log records are JSON with timestamp, severity, logger, and a validated request ID. The API accepts only short alphanumeric/dot/underscore/hyphen `X-Request-ID` values and generates a UUID otherwise; responses return the selected ID. `/health` checks database connectivity without exposing connection details. Provider and background-job failures are logged without source, credentials, or exception payloads.

## AI boundary

The AI adapter speaks the OpenAI-compatible chat-completions shape through Python's standard HTTP client. A user action triggers a bounded (20-second, response-size-limited) request. Recognized secrets are pattern-redacted before the outbound request. Pydantic validates response shape; evidence must exist in the submitted/redacted text and supplied line coordinates must match. Validated suggestions are persisted as `ai` findings. Provider credentials remain in the backend environment. This is advisory review, not proof, and source disclosure to a configured provider remains an explicit user choice.

## Patch boundary

Patch previews are deliberately restricted to standalone, one-line, single-name Python imports already identified by the AST analyzer. Unified diffs are generated in memory, saved with pending/accepted/rejected state, and never applied to a file. Review acceptance records a decision only.

## Dependency intelligence

Requirements-style Python and npm package manifests are parsed without invoking installers. npm package-lock v2/v3 and exact Python lock pins provide resolved versions. Only exact package coordinates are submitted to the fixed public OSV batch-query API; the returned IDs, aliases, summaries and source-provided severity are persisted. Missing exact versions are explicitly not scanned. Network failure leaves the inventory and a failed job status; no CVE is synthesized.

## Deployment

Compose runs API, frontend dev server, and PostgreSQL. PostgreSQL has no exposed host port; API and web development ports bind to loopback. Production hosting needs a hardened deployment profile (TLS/reverse proxy, strong secrets, secure cookie/session strategy, request throttling, durable workers, backups, monitoring and tested isolation); Compose alone is not a production certification.
