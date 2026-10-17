# API guide

Base URL for local work is `http://127.0.0.1:8000`. Interactive OpenAPI is available at `/docs`. Authenticated endpoints use `Authorization: Bearer <access_token>`. Passwords are sent only to the backend over the local/dev connection and stored as Argon2 hashes.

## Authentication

- `POST /api/auth/register` and `POST /api/auth/login`: JSON `{ "email": "...", "password": "12+ chars" }`, return a bearer token and user.
- `GET /api/auth/me`: current account.

## Source and reports

- `POST /api/analyses` — JSON `{ "code": "...", "language": "python|javascript|typescript", "file_name": "src/example.py" }`; returns `202` with an analysis job/report identifier.
- `GET /api/analyses?limit=20&offset=0` — current account's paginated reports.
- `GET /api/analyses/{analysis_id}` — status, findings, analyzer summary and quality-gate result.
- `POST /api/diffs` — JSON `{ "diff": "unified diff text" }`; supported files only. Added lines are analyzed as a fragment.
- `POST /api/dependency-scans` — JSON `{ "ecosystem": "python|npm", "manifest": "...", "lockfile": "..." }`; persists an inventory and queries OSV for exact versions only.
- `GET /api/dependency-scans?limit=20&offset=0` and `GET /api/dependency-scans/{scan_id}` — current account's scan history/report.
- `GET /api/analytics/overview` — aggregate snapshot calculated from this account's stored analyses.
- `GET /health` — API/database state and a boolean provider-configuration indicator; no credentials are returned.

Analysis and diff submission may include `fail_on_severity` (`critical`, `high`, `medium`, or `low`). A finding at or above the selected severity threshold fails the per-analysis quality gate; a syntax error also fails it.

## Review and patch actions

- `POST /api/analyses/{analysis_id}/ai-review` — explicit provider call; source is pattern-redacted first. Returns `503` when not configured/provider unavailable and rejects invalid evidence.
- `POST /api/analyses/{analysis_id}/patch-suggestions?finding_id={finding_id}` — creates a persisted, safe unused-import diff preview.
- `PATCH /api/patch-suggestions/{suggestion_id}` — JSON `{ "decision": "accepted|rejected" }`; records the review decision without applying the patch.

Dependency scans support requirements-style Python manifests/lockfiles and npm `package.json` with lockfile v2/v3. They do not install packages. Exact package names/versions are sent to `https://api.osv.dev`; no code or manifest text is sent to that service. Missing lock resolution is marked unscanned; “no advisory returned” is not proof of safety. All private resource operations verify ownership server-side. Errors use meaningful HTTP status codes and do not include internal stack traces. There is currently no webhook, GitHub, repository filesystem, or test-execution API.
