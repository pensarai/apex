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
After implementing code changes and passing normal validation, run an Apex
security review against the live dev server.

1. Confirm the dev server URL, usually `http://localhost:3000`.
2. Write Apex guidance:

   ```bash
   PROMPT_FILE="$HOME/.pensar/agent-runs/current/prompt.md"
   mkdir -p "$(dirname "$PROMPT_FILE")"
   cat > "$PROMPT_FILE" <<'EOF'
   Focus on the current code changes and security-sensitive behavior:
   authentication, authorization, tenant isolation, input validation, redirects,
   file upload, SSRF, webhooks, and public API routes.
   EOF
   ```

3. Run:

   ```bash
   pensar pentest --target http://localhost:3000 --cwd . --prompt "@${PROMPT_FILE}"
   ```

4. Capture `Session:` and `Session path:` from the final Apex output.
5. Read `pentest-report.md`, `pentest-report.json`, `findings/`, and `pocs/`
   from the session path.
6. Follow the user's fix policy. If no policy is specified, summarize proposed
   fixes before editing auth, billing, or tenant isolation behavior.
7. Re-run `pensar targeted-pentest` for verification after fixes.
8. Include the Apex session IDs and artifact paths in the final response.
````
