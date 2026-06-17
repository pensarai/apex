# Cursor Background Agent Template

Use this pattern when a Cursor background agent can run shell commands in a
remote workspace.

## Environment Setup

Keep the app process running before invoking Apex. A project-specific Cursor
environment can start the dev server and make the target URL predictable.

Example `.cursor/environment.json` shape:

```json
{
  "terminals": [
    {
      "name": "web",
      "command": "npm run dev",
      "description": "Start the local web application"
    }
  ]
}
```

Adjust the command for the repository's package manager and app entrypoint.

## Agent Instruction Block

````markdown
Run Apex only when the user or workflow explicitly requests Apex security
validation, or when repository policy enables Apex as a required gate.

When Apex is enabled for the task, first implement code changes and pass normal
validation. Then decide whether an Apex security review is warranted. Continue
only when the PR touches authentication, authorization, tenant isolation,
billing or entitlements, file upload, webhooks, outbound integrations, public
API routes, admin routes, untrusted input validation, redirects, CORS, CSP,
security headers, secrets, or credential handling.

Skip Apex for documentation-only, copy-only, styling/layout-only, or test-only
changes that do not alter runtime behavior.

1. Confirm the dev server URL, usually `http://localhost:3000`.
2. Inspect the PR diff and map changed files to affected endpoints:

   ```bash
   git diff --name-only origin/main...HEAD
   git diff origin/main...HEAD
   ```

3. Prefer `pensar targeted-pentest` for affected endpoints:

   ```bash
   pensar targeted-pentest \
     --target http://localhost:3000/api/projects/123/members \
     --objective "Test authorization and tenant isolation for the changed project member management path"
   ```

4. If the affected surface cannot be narrowed safely, write scoped Apex
   guidance and run a broad pentest:

   ```bash
   PROMPT_FILE="$HOME/.pensar/agent-runs/current/prompt.md"
   mkdir -p "$(dirname "$PROMPT_FILE")"
   cat > "$PROMPT_FILE" <<'EOF'
   Only test behavior affected by this PR. Prioritize changed authentication,
   authorization, tenant isolation, input validation, redirects, file upload,
   SSRF, webhooks, and public API routes. Do not spend time on unrelated routes
   unless they are needed to prove impact for the changed paths.
   EOF

   pensar pentest --target http://localhost:3000 --cwd . --prompt "@${PROMPT_FILE}"
   ```

5. Capture `Session:` and `Session path:` from the Apex handoff block.
6. Read `pentest-report.md`, `pentest-report.json`, `findings/`, and `pocs/`
   from the session path.
7. Follow the user's fix policy. If no policy is specified, summarize proposed
   fixes before editing auth, billing, or tenant isolation behavior.
8. Re-run `pensar targeted-pentest` for verification after fixes.
9. Include the Apex session IDs and artifact paths in the final response.
````
