# Troubleshooting

## The frontend says “API unavailable”

- Confirm Uvicorn is listening at `http://127.0.0.1:8000/health`.
- Start Vite from `frontend`; its proxy defaults to the loopback API above.
- If the API database health is down, verify `DEVPILOT_DATABASE_URL` and apply `python -m alembic upgrade head` from `backend`.
- Do not expose the development API or default token key outside a trusted local machine.

## The API rejects its JWT secret

`DEVPILOT_ENVIRONMENT=production` requires a non-default `DEVPILOT_JWT_SECRET` of at least 32 characters. Compose enables production mode; replace the example value with a high-entropy secret in `.env`. For local development, omit `DEVPILOT_ENVIRONMENT` or set it to `development`.

## Alembic cannot find a migration or cannot connect

Run Alembic from the `backend` working directory with the same `DEVPILOT_DATABASE_URL` used by the API. For PostgreSQL, ensure the URL uses the installed psycopg v3 driver (`postgresql+psycopg://...`) and the database is reachable. SQLite files are relative to the backend working directory by default.

Compose builds its PostgreSQL URL from `.env` values. If a database password contains URL-reserved characters, percent-encode them in the password value or choose a generated password that is safe in a connection URL.

## Reports show queued/running for too long

Analysis tasks run in FastAPI's process-local background executor and have no durable recovery mechanism. Inspect API logs for the report identifier and exception type. Restarting the API may strand a job; do not delete database rows as a recovery shortcut. For dependency scans, check outbound HTTPS access to `api.osv.dev`. External scans return a failed job with an explicit message when the provider is not reachable.

## JavaScript/TypeScript shows “source-validator”

The backend could not locate the frontend ESLint installation or it timed out. In a local monorepo, run `npm ci` in `frontend` and retry. The fallback validates delimiters/strings only; it is not ESLint, a TypeScript type-check, or full syntax proof.

## AI review returns unavailable

Configure `DEVPILOT_LLM_BASE_URL`, `DEVPILOT_LLM_API_KEY`, and `DEVPILOT_LLM_MODEL` in the backend environment. The base URL should be an OpenAI-compatible API root (for example, ending in `/v1`). Provider credentials are never configured in the frontend. Review is optional; deterministic analysis remains available.

## Playwright cannot start its servers

- Install Chromium with `npx playwright install chromium`.
- Ensure ports 8010 and 5174 are free.
- Activate the backend virtual environment or set `E2E_BACKEND_PYTHON` to its Python executable before `npm run test:e2e`.
- E2E applies migrations to an ignored local `backend/.e2e.db`; it does not reset it on startup.

## Docker commands are unavailable

Install Docker Desktop and enable its Compose v2 plugin, or use the documented Python/SQLite and Node local workflow. Docker/Compose deployment has not been verified in this environment.

## Dependency audit needs network access

`pip-audit`, `npm audit`, and exact-version OSV lookups consult public vulnerability metadata. An offline/blocked network failure must be treated as “not checked,” not as a clean result.
