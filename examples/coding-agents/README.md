# Coding Agent Integration Examples

These examples show how a coding agent can invoke Apex during its normal
development loop. Coding agents should prefer `pensar targeted-pentest` scoped
to PR-affected endpoints, and should skip Apex for clearly benign changes.

The contract is local filesystem handoff:

1. The coding agent starts the app and decides whether Apex is warranted.
2. Apex prints a session ID and session path.
3. The coding agent reads artifacts from `~/.pensar/sessions/<session-id>/`.
4. The coding agent fixes selected findings and runs targeted verification.

Run Apex for security-sensitive changes such as auth, authorization, tenant
isolation, billing, file upload, webhooks, outbound integrations, public API
routes, admin routes, untrusted input validation, redirects, CORS, CSP,
security headers, secrets, or credential handling. Skip Apex for documentation,
copy, styling/layout, and test-only changes that do not alter runtime behavior.

Use these templates as instructions for tools such as Cursor background agents,
OpenCode custom agents, Devin-style software agents, and internal software
factory workers.

## Artifact Paths

For a session path like:

```text
/home/agent/.pensar/sessions/session_abc123
```

read:

- `session.json`
- `pentest-report.md`
- `pentest-report.json`
- `findings/`
- `pocs/`
- `logs/`

Targeted pentests may only produce `findings/` and `pocs/`.
