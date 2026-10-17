# DevPilot AI

DevPilot AI is a developer engineering-intelligence workspace for bounded source and manual-diff analysis. It combines authenticated report persistence, deterministic analysis, evidence-backed optional AI review, quality gates, and safe patch previews. It is a deliberately scoped modular monolith, not an automated code-modification or arbitrary-code-execution service.

## Start locally on Windows

Requirements: Python 3.11+ (tested here with 3.13), Node.js 24 LTS/current, and npm. PostgreSQL is optional for local use; SQLite is the default. Docker Compose is an alternative.

1. From the project root, create and activate the backend environment:

   ```powershell
   py -3.13 -m venv backend\.venv
   .\backend\.venv\Scripts\Activate.ps1
   Set-Location backend
   python -m pip install -r requirements.lock
   python -m alembic upgrade head
   uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
   ```

2. In a second PowerShell window, install and start the frontend:

   ```powershell
   Set-Location "C:\path\to\DevPilot AI\frontend"
   npm ci
   npm run dev
   ```

3. Open <http://127.0.0.1:5173>, create an account with a password of at least 12 characters, and submit Python, JavaScript, or TypeScript source. The Vite development proxy forwards API calls to `http://127.0.0.1:8000`.

The local default signing key is for development only. Set `DEVPILOT_ENVIRONMENT=production` and `DEVPILOT_JWT_SECRET` to a unique random value of at least 32 characters outside local development; production mode rejects the built-in development key and shorter values. Never expose the API directly to an untrusted network with the development default.

## Docker Compose

Copy `.env.example` to `.env`, replace `POSTGRES_PASSWORD` and `DEVPILOT_JWT_SECRET`, then run:

```powershell
docker compose up --build
```

The web interface is at <http://127.0.0.1:5173>; the API is bound to loopback at port 8000. PostgreSQL has no published host port. Container startup applies Alembic migrations before starting the API. `docker compose down` stops services while retaining the named database volume. Do not use `down -v` unless you intentionally want to destroy that development database.

## What is implemented

- Password-hashed registration/login, short-lived JWT bearer tokens, a production-mode signing-key guard, account ownership checks, audit events, and per-user analysis history.
- Python AST syntax checks, unused-import checks, bare-except checks, and secret-pattern detection with redacted evidence.
- ESLint-backed JavaScript/TypeScript analysis when the adjacent frontend dependencies are installed; a clearly labelled delimiter validator is used when ESLint is unavailable.
- Manual unified-diff submission for supported source paths. Only added lines are analyzed; reports identify that fragment scope.
- Findings normalized with rule, analyzer, severity, category, origin, location, evidence, remediation, stable fingerprint, and deduplication.
- Persisted background-task status and report history; report/overview endpoints and a real-data dashboard.
- Configurable-at-deployment OpenAI-compatible structured review, with backend-only credentials, secret-pattern redaction before transmission, evidence/location validation, and explicit provider errors.
- A conservative Python unused-import patch preview. Users can accept/reject its recorded suggestion, but no workspace/repository file is ever changed.
- Per-analysis severity threshold and syntax quality-gate results.
- Persisted Python requirements/npm package inventories, lockfile-resolved versions, and OSV vulnerability records for exact versions when the public OSV API is reachable.
- PostgreSQL and SQLite database support through SQLAlchemy and Alembic.

## Deliberate limitations

This initial delivery does **not** include local repository browsing or Git inspection, GitHub App/OAuth integration, full changed-line mapping/baseline comparison, offline vulnerability data, Bandit normalization for submitted code, general-purpose LLM patch generation, generated test suites, test execution, coverage collection, saved/global quality-gate policies, database-backed durable queue/retries/cancellation, pagination UI, or rate limiting. Dependency scans use the real OSV API only for exact resolved versions; they fail visibly if the service is unavailable and do not invent CVEs. The `bandit` package is used to scan the backend project in CI/local checks, not as a per-submission API analyzer.

FastAPI `BackgroundTasks` persist queued/running/completed/failed state but are process-local and are not a durable queue. If the API stops during analysis, queued/running work may need operator recovery. JavaScript/TypeScript checks are not a type-check or proof of syntax when ESLint is absent. Diff findings use added-line fragment coordinates, not original-file coordinates, and a diff request is limited to one changed source file. There is no sandbox; arbitrary test execution is not offered.

See [architecture](docs/ARCHITECTURE.md), [API guide](docs/API.md), [testing guide](docs/TESTING.md), [security model](docs/SECURITY.md), [threat model](docs/THREAT-MODEL.md), and [troubleshooting](docs/TROUBLESHOOTING.md).

## Commands

Backend (from `backend` with the virtual environment activated):

```powershell
python -m alembic upgrade head
python -m pytest --cov=app --cov-report=term-missing
python -m ruff check app tests migrations
python -m bandit -q -ll -r app
python -m pip_audit
```

Frontend (from `frontend`):

```powershell
npm ci
npm run typecheck
npm run lint
npm test
npm run build
npm audit
npx playwright install chromium
$env:E2E_BACKEND_PYTHON = (Resolve-Path "..\backend\.venv\Scripts\python.exe").Path
npm run test:e2e
```

API OpenAPI docs: <http://127.0.0.1:8000/docs>; liveness/database health: <http://127.0.0.1:8000/health>.

To explicitly reset only the local SQLite development database, stop the API first, then run:

```powershell
Set-Location "C:\path\to\DevPilot AI\backend"
Remove-Item .\devpilot.db -ErrorAction SilentlyContinue
python -m alembic upgrade head
```

This irreversibly deletes the local database at that exact path. It is not run by application startup. It does not reset the Compose PostgreSQL volume.

## Repository preparation

Local environments, credentials, and generated build artifacts are excluded by `.gitignore`.
