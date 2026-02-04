---
name: clean
description: Commit all changes to a new branch, push, and create a draft PR
disable-model-invocation: true
allowed-tools: Bash, Read, Glob, Grep
---

Clean up the current work by committing everything to a new branch and creating a draft PR.

## Steps

1. **Check for changes** - Run `git status` to see what needs to be committed. If no changes, inform the user and stop.

2. **Create a branch** - Create a descriptive branch name based on the changes (e.g., `fix/auth-bug`, `feat/add-logging`, `refactor/cleanup-utils`). Use format: `<type>/<short-description>`

3. **Stage and commit** - Stage all changes and commit with a concise message describing what changed. Keep it short and descriptive. Do NOT include any Co-Authored-By lines.

4. **Push the branch** - Push to origin with `-u` flag

5. **Create draft PR** - Use `gh pr create --draft` with:
   - A clear, concise title
   - Body that briefly summarizes the changes (just bullet points of what changed, no fluff)

## Commit message format

```
<type>: <short description>

- Change 1
- Change 2
```

Types: feat, fix, refactor, docs, test, chore

## Important

- Never include Co-Authored-By lines
- Keep PR body minimal - just the changes, no templates
- Always create as draft PR
