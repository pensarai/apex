# Generic Coding Agent Instructions

Use Apex as a security review gate after security-relevant code changes are
implemented and the development environment is running.

## Invocation Policy

Run Apex only when the user or workflow explicitly requests Apex security
validation, or when repository policy enables Apex as a required gate. When
Apex is enabled for the task, run it only when the change touches
security-sensitive code or behavior:

- authentication, sessions, cookies, tokens, OAuth, SSO, or password flows
- authorization, RBAC, object ownership, admin checks, or tenant isolation
- billing, payments, plans, credits, quotas, or entitlement logic
- file upload, imports, exports, attachments, or user-controlled paths
- webhooks, callbacks, outbound integrations, proxying, or SSRF-prone fetches
- public API routes, admin routes, data access layers, or untrusted input
  validation
- redirects, CORS, CSP, security headers, secrets, or credential handling

Do not run Apex for clearly benign changes such as documentation-only changes,
copy-only changes, styling/layout-only changes, or tests that do not change
runtime behavior.

## Workflow

1. Implement the requested code change.
2. Run the project's normal validation commands.
3. Start the app and determine the local target URL.
4. Map changed files to affected endpoints using the PR diff, route files,
   framework conventions, OpenAPI specs, or direct code search.
5. Prefer `pensar targeted-pentest` for the affected endpoints.
6. Capture the printed `Session:` and `Session path:`.
7. Read Apex artifacts from the session path.
8. Decide what to fix according to the user's policy.
9. Re-run targeted Apex verification for fixed findings.
10. Include discovery and verification session IDs in the final summary.

## Targeted Command Template

```bash
git diff --name-only origin/main...HEAD
git diff origin/main...HEAD

pensar targeted-pentest \
  --target http://localhost:3000/api/projects/123/members \
  --objective "Test authorization and tenant isolation for the changed project member management path"
```

## Broad Fallback Template

Use a broad pentest only when changed files cannot be mapped to specific
endpoints or the PR intentionally changes application-wide security behavior.

```bash
PROMPT_FILE="$HOME/.pensar/agent-runs/current/prompt.md"
mkdir -p "$(dirname "$PROMPT_FILE")"
cat > "$PROMPT_FILE" <<'EOF'
Only test behavior affected by this PR. Prioritize changed auth,
authorization, tenant isolation, file upload, webhook, redirect, SSRF, and
public API paths. Do not spend time on unrelated routes unless they are needed
to prove impact for the changed paths.
EOF

pensar pentest \
  --target http://localhost:3000 \
  --cwd . \
  --prompt "@${PROMPT_FILE}"
```

## Reading Results

After Apex exits, read the printed session path:

```text
~/.pensar/sessions/<session-id>/
```

Open these files:

- `pentest-report.md`
- `pentest-report.json`
- `findings/`
- `pocs/`

Do not rely on stdout alone. The filesystem artifacts are the source of truth.

## Verification Template

```bash
pensar targeted-pentest \
  --target http://localhost:3000 \
  --objective "Verify the fixed finding is no longer exploitable"
```
