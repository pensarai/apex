# Software Factory Runbook

Use this runbook for background workers that clone a repo, run a coding agent,
and need Apex results available on the same local filesystem.

## Inputs

- Repository path
- Target URL for the running dev or preview environment
- Optional changed files list
- Optional threat model path
- Optional user security policy
- Optional security-sensitive path/service allowlist supplied by the repository
- AI provider configuration for Apex

## Job Flow

1. Create an isolated job home:

   ```bash
   export HOME="$WORKSPACE/.agent-home"
   mkdir -p "$HOME"
   ```

2. Install dependencies and start the application.
3. Run the coding agent's normal implementation and validation loop.
4. Decide whether Apex is enabled for this job. Invoke Apex only when the user
   or workflow explicitly requests Apex security validation, or when repository
   policy enables Apex as a required gate.
5. If Apex is enabled, decide whether it is warranted for the PR. Continue only
   when the PR touches security-sensitive services or paths: authentication,
   authorization, tenant isolation, billing or entitlements, file upload,
   webhooks, outbound integrations, public API routes, admin routes, untrusted
   input validation, redirects, CORS, CSP, security headers, secrets, or
   credential handling. Skip Apex for documentation-only, copy-only,
   styling/layout-only, or test-only changes that do not alter runtime behavior.
6. Map changed files to affected endpoints using the PR diff, route manifests,
   framework conventions, OpenAPI specs, or direct code search.
7. Prefer targeted Apex testing:

   ```bash
   pensar targeted-pentest \
     --target "$AFFECTED_ENDPOINT_URL" \
     --objective "$AFFECTED_ENDPOINT_SECURITY_OBJECTIVE"
   ```

8. If the affected surface cannot be narrowed safely, write scoped Apex
   guidance:

   ```bash
   PROMPT_FILE="$HOME/.pensar/agent-runs/current/prompt.md"
   mkdir -p "$(dirname "$PROMPT_FILE")"
   printf '%s\n' "$APEX_AGENT_PROMPT" > "$PROMPT_FILE"
   ```

9. Run a broad fallback pentest only for that ambiguous or application-wide
   security change:

   ```bash
   pensar pentest \
     --target "$TARGET_URL" \
     --cwd "$REPO_PATH" \
     --prompt "@${PROMPT_FILE}"
   ```

10. Parse `Session:` and `Session path:` from the Apex handoff block.

11. Persist the session ID and session path in the software factory job record.
12. Let the coding agent read findings and POCs from the session path.
13. Run targeted verification after fixes.

## Outputs

Record these values in the factory job summary:

- Discovery session ID
- Discovery session path
- Findings count by severity from `pentest-report.json`
- Report path
- POCs path
- Verification session ID, when run
- Fixed findings
- Deferred findings and rationale

## Cleanup

Keep `~/.pensar/sessions/<session-id>/` for auditability at least as long as the
PR or job record exists. If the job home is ephemeral, archive the session
directory as a build artifact before teardown.
