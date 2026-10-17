# Security model

## Implemented controls

- Passwords use `pwdlib`'s recommended Argon2 hasher; raw passwords are not persisted.
- JWT access tokens expire after a configured hour. Endpoints require bearer authentication and apply user ownership filters.
- SQLAlchemy parameterized statements are used for user input. Alembic migrations preserve data.
- Request schemas restrict language, source size, password length, filename traversal and diff paths.
- An ASGI middleware rejects HTTP request bodies larger than 4,000,000 bytes, including chunked bodies, before route parsing.
- Static analysis parses source text only. It does not execute input. ESLint uses a fixed trusted executable path, argument arrays, stdin, no shell and a timeout.
- Secret-pattern findings replace matched evidence with `[REDACTED]`; AI transmission also redacts the configured recognized patterns.
- AI keys stay server-side; structured output is size/schema/evidence checked; provider failures do not return success-shaped fallbacks.
- Patch workflow only previews a narrowly validated transformation. No source file is written.
- Logs avoid source text, credentials, secret values and SQL exception payloads.
- Compose database has no published host port; API/web ports bind to loopback.

## Known security limitations

- JWT is stored in browser `localStorage` and is not server-revocable before expiry. Sign-out removes the browser copy only. An XSS bug could expose a token; deploy behind TLS and consider an HttpOnly session-cookie/refresh-token design.
- Login/registration have no built-in rate limiting, CAPTCHA, email verification, MFA, account recovery, or session revocation. Put an appropriate gateway in front of externally reachable deployments.
- The local fallback signing secret is intentionally development-only. Set `DEVPILOT_ENVIRONMENT=production` to reject the built-in key and secrets shorter than 32 characters; Compose enables this mode and requires a supplied secret. Operators must still use a high-entropy value, rotate it, and keep `.env` out of version control.
- Source is stored in the application database. Configure access controls, backups, retention and encryption appropriate to data sensitivity.
- AI review sends redacted source to the configured provider; heuristic redaction cannot guarantee detection of every credential. Use only a provider and data policy approved for the code.
- Secret detection is heuristic, not a full secret scanner. Dependency scans send exact package coordinates (not source or manifests) to the public OSV API; no offline database/cache is provided. No arbitrary test execution/sandbox is provided.
- Background work is process-local; this application has no durable queue, cancellation, or retry orchestration.
- No formal penetration test, threat-model validation, TLS deployment, PostgreSQL integration test, or production operational review has been performed.

## Operator checklist

Use a unique high-entropy JWT secret, TLS, private database networking, least-privilege database credentials, managed secret storage, backups/restores, rate limits, alerting, retention policy and a durable worker before exposing beyond local development. Do not mount the Docker socket or mount developer credentials into analysis containers. No untrusted source code is executed.
