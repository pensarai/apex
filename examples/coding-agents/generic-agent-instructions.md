# Generic Coding Agent Instructions

Use Apex as a security review gate after code changes are implemented and the
development environment is running.

## Workflow

1. Implement the requested code change.
2. Run the project's normal validation commands.
3. Start the app and determine the local target URL.
4. Write optional Apex guidance to a prompt file.
5. Run Apex with `--target`, `--cwd`, and `--prompt` when useful.
6. Capture the printed `Session:` and `Session path:`.
7. Read Apex artifacts from the session path.
8. Decide what to fix according to the user's policy.
9. Re-run targeted Apex verification for fixed findings.
10. Include discovery and verification session IDs in the final summary.

## Command Template

```bash
PROMPT_FILE="$HOME/.pensar/agent-runs/current/prompt.md"
mkdir -p "$(dirname "$PROMPT_FILE")"
cat > "$PROMPT_FILE" <<'EOF'
Focus on the security impact of the current code changes. Prioritize changed
auth, authorization, tenant isolation, file upload, webhook, redirect, SSRF,
and public API paths. Include POC evidence and likely remediation files.
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
