# Threat model and limitations

## Assets

Account credentials and tokens; submitted source and diffs; findings and evidence; database contents; optional provider key; analysis results.

## Trust boundaries

- Browser to API: untrusted request bodies, bearer tokens and client-side validation.
- API to database: persisted account-owned data.
- API to ESLint: untrusted source provided through stdin to a trusted local analyzer process.
- API to optional LLM: outbound source disclosure and untrusted model output.
- Diff text: untrusted file names and hunks; paths are checked and never opened.

## Main threats and current treatment

| Threat | Current treatment | Remaining limitation |
|---|---|---|
| Cross-account report access | Ownership predicates and integration test | No roles/organizations |
| Path traversal through names/diffs | Relative-path validation; paths are metadata only | No repository filesystem workflow |
| Arbitrary code execution | No source/test execution; ESLint only receives input text | No test runner exists |
| Secret exposure in findings/logs | Pattern redaction and restricted logging | Patterns are incomplete; original submitted source is persisted |
| Prompt injection/fabricated AI claims | Source marked untrusted; schema, location and evidence checks | Provider may still return incorrect advice |
| LLM credential disclosure | Key sent only from backend; omitted from health/API/logs | Environment/host configuration must be secured |
| Denial of service | Bounded manifest/source sizes and package count; 15-second OSV timeout; 20-second provider timeout | No request rate limit or durable worker quotas |
| Dependency scanner data exposure | Sends package name/version pairs only to the fixed HTTPS OSV API | Online lookup is unavailable without network; no offline database |
| Database loss/tampering | Foreign keys, migrations, Compose named volume | No tested backup/restore, encryption-at-rest configuration, or deployment hardening |

## Out of scope

GitHub webhooks, repository checkout, offline dependency scanning, sandboxed tests, patch application, production deployment certification, and formal security assurance are not implemented.
