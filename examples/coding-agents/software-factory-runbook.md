# Software Factory Runbook

Use this runbook for background workers that clone a repo, run a coding agent,
and need Apex results available on the same local filesystem.

## Inputs

- Repository path
- Target URL for the running dev or preview environment
- Optional changed files list
- Optional threat model path
- Optional user security policy
- AI provider configuration for Apex

## Job Flow

1. Create an isolated job home:

   ```bash
   export HOME="$WORKSPACE/.agent-home"
   mkdir -p "$HOME"
   ```

2. Install dependencies and start the application.
3. Run the coding agent's normal implementation and validation loop.
4. Write Apex guidance:

   ```bash
   PROMPT_FILE="$HOME/.pensar/agent-runs/current/prompt.md"
   mkdir -p "$(dirname "$PROMPT_FILE")"
   printf '%s\n' "$APEX_AGENT_PROMPT" > "$PROMPT_FILE"
   ```

5. Run Apex:

   ```bash
   pensar pentest \
     --target "$TARGET_URL" \
     --cwd "$REPO_PATH" \
     --prompt "@${PROMPT_FILE}"
   ```

6. Parse the final Apex output for:

   ```text
   Session:       <session-id>
   Session path:  <session-path>
   ```

7. Persist the session ID and session path in the software factory job record.
8. Let the coding agent read findings and POCs from the session path.
9. Run targeted verification after fixes.

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
