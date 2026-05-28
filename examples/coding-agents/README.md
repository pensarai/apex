# Coding Agent Integration Examples

These examples show how a coding agent can invoke Apex during its normal
development loop.

The contract is local filesystem handoff:

1. The coding agent starts the app and runs Apex.
2. Apex prints a session ID and session path.
3. The coding agent reads artifacts from `~/.pensar/sessions/<session-id>/`.
4. The coding agent fixes selected findings and runs targeted verification.

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
