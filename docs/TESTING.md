# Testing and validation

## Backend

```powershell
Set-Location backend
python -m pytest --cov=app --cov-report=term-missing
python -m ruff check app tests migrations
python -m bandit -q -ll -r app
python -m pip_audit
python -m alembic upgrade head
```

Tests use an isolated in-memory SQLite database and FastAPI `TestClient`; AI/OSV provider responses are patched in unit/integration tests. Static analysis itself is real. The test suite covers production JWT-secret validation, Python AST findings, syntax diagnostics, Unicode source coordinates, multiple-secret evidence redaction, oversized HTTP bodies, ESLint diagnostics when the local frontend installation is present, dependency manifest normalization, quality gates, registration/login, report persistence, diff input, cross-user access isolation, evidence validation, and patch decision persistence. PostgreSQL service tests are not currently included.

## Frontend

```powershell
Set-Location frontend
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

Vitest/Testing Library exercise the login/register switch and API client authorization/error behavior. The Monaco editor is mocked in component tests. Playwright starts an isolated SQLite-backed API and Vite server, registers accounts, runs real Python AST and JavaScript ESLint analysis plus a manual diff, inspects findings/quality gates/history, rejects a traversal filename, verifies unauthenticated API access is denied, records a non-applying patch decision, inventories a manifest without contacting OSV when no exact versions are supplied, and verifies analysis data is not carried across account changes. Set `E2E_BACKEND_PYTHON` to the backend interpreter path if `python` is not the interpreter containing the backend dependencies.

## CI

GitHub Actions runs backend tests/lint/security scanning, frontend typecheck/lint/unit tests/build/dependency audit, and the Playwright workflow on pushes and pull requests. It does not need LLM credentials. PostgreSQL and provider integrations are not exercised by CI.

Bandit is run at medium severity or higher (`-ll`); its two low-severity reports are the deliberately constrained ESLint subprocess import/invocation. `pip-audit` and `npm audit` query public advisory databases and require network access.
