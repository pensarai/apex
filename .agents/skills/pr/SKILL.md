---
name: pr
description: Create, update, format, babysit, resolve conflicts and review findings on, and merge Apex pull requests and PR stacks. Use when the user asks to open or update a PR or merge request, align a stack, get CI green, address review or Bugbot findings, resolve merge conflicts, or merge.
argument-hint: "[create | update | stack | babysit | comments | conflicts | merge | PR number]"
allowed-tools: Bash(gh *) Bash(git *) Bash(bun *)
---

# PR

Apex pull-request workflow. Read this file, then **read every applicable playbook** under [`.agent-instructions/skills/pr/`](../../../.agent-instructions/skills/pr/) before acting. Do not improvise past a playbook.

This is repository-development guidance for coding agents working on Apex. Keep it in the repo's `.agents/skills` tree only; do not copy or link it into `.claude/skills`, `.skills`, `skills`, `~/.agents/skills`, or `~/.pensar/skills`, because Apex scans those locations as runtime skills.

## Invariants

- Resolve `OWNER/REPO`, the target PR's current head/base SHAs, and stack topology from live Git and GitHub state. A body saying "stack" is not proof of dependent branches.
- Ordinary Apex work branches from and targets `canary`. Do not target `main`, retarget a PR, or rewrite stack topology unless the user explicitly asks for that exact change.
- GitHub reads and writes go through `gh api` (REST or GraphQL). Do not use `gh pr create`, `gh pr comment`, or `gh pr merge`.
- Preserve bot-managed body regions (`CURSOR_SUMMARY`, `codesmith:footer`) byte-for-byte when editing human-authored sections.
- Never merge, squash, close, enable auto-merge, force-push, or delete a branch unless the user explicitly authorizes that exact action. A request to resolve conflicts and push does not authorize merging.
- Work from a clean, isolated checkout when the user's current checkout has unrelated changes. Never stash, reset, or overwrite user work to make a PR task convenient.
- Judge CI, reviews, and mergeability on the latest PR head SHA. Pending work or green checks on an older SHA are not done.

## Route

| Intent                                               | Playbook                                                                                  |
| ---------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| Create or update a feature/fix/docs PR               | [`create-and-update.md`](../../../.agent-instructions/skills/pr/create-and-update.md)     |
| Create, inspect, format, or refresh a PR stack       | [`stacks.md`](../../../.agent-instructions/skills/pr/stacks.md)                           |
| Stay until CI and mergeability settle                | [`babysit.md`](../../../.agent-instructions/skills/pr/babysit.md)                         |
| Review comments, Cursor Bugbot, or thread resolution | [`comments-and-bugbot.md`](../../../.agent-instructions/skills/pr/comments-and-bugbot.md) |
| Resolve conflicts or perform an authorized merge     | [`conflicts-and-merge.md`](../../../.agent-instructions/skills/pr/conflicts-and-merge.md) |

After creating, updating, refreshing, or fixing a PR, babysit the new SHA. If it belongs to a stack, also apply `stacks.md`. If review findings exist, apply `comments-and-bugbot.md` before declaring the PR ready.

**Babysit** means staying until required checks have conclusions on the latest SHA, mergeability is known, and no unresolved actionable review work remains. Waiting for human approval after every technical gate is green is terminal; pending CI is not.
