---
name: code-comments
description: Write tasteful, load-bearing comments in Apex source. Use when writing or editing code, JSDoc, TODOs, or file headers, or when deciding whether a comment should exist.
---

# Code comments

How to comment when working on Apex. Read this before adding or rewriting comments.

This is repository-development guidance for coding agents working on Apex. Keep it in the repo's `.agents/skills` tree only; do not copy or link it into `.claude/skills`, `.skills`, `skills`, `~/.agents/skills`, or `~/.pensar/skills`, because Apex scans those locations as runtime skills.

## Invariants

- A comment must carry information the code cannot recover. If a better name or a smaller function would make it unnecessary, do that instead.
- Comment the why, the why-not, and the invariant. Never narrate the next line.
- Place a load-bearing comment next to the code it constrains. Distant essays get skipped and do not protect the dangerous line.
- Stale comments are bugs. If you change behavior a comment describes, update or delete it in the same edit.
- Write for the next reader who was not in this conversation — human or agent. No session notes, "the user asked for this," or chat residue.
- Default to one sentence. Two or three lines when the constraint needs them. No multi-paragraph docstrings and no labeled taxonomies (`CONTRACT`, `MUST`, `ARCHITECTURE`).
- Don't comment-out code; git remembers. Don't add comments to code you did not touch.

## Write one when

- The obvious approach is wrong, and the next editor will "fix" it
- Correctness depends on order, aliasing, re-entrancy, ownership, or a peer that is not visible here
- A value, timeout, limit, or encoding looks arbitrary
- The code works around a platform, SDK, or spec quirk (name the quirk)
- A public contract is not expressible in the type (single-read streams, processor ordering, "do not route X through Y")
- You spent real time learning something the next reader will not see
- A TODO is still justified — say why it is deferred and what "done" means

## Do not write one when

- It restates the identifier, type, or the next statement
- JSDoc would only echo parameter names and return types
- The code is unclear and should be renamed or extracted instead
- You are padding a change so it "looks documented"
- The file already makes the point at the call site that matters

Agents treat comments as durable memory. A precise invariant next to the line it protects prevents a locally reasonable, globally wrong edit. A paragraph of narration gets skipped or copied. Prefer the former.

## House style

Match neighboring Apex comments: natural prose, complete sentences, no banner art except where a test file already uses section rules.

JSDoc is for exported types and methods when the types cannot carry the contract — who must call what, in what order, and what silently breaks. See `src/core/observability/active-spans.ts` and `src/core/api/index.ts`.

An empty `catch` still needs the reason the error is swallowed.

## Shape

**Narration — delete it:**

```
// Reverse the spans
const spans = [...this.active.entries()].reverse();
```

**Load-bearing — keep this shape:**

```
// Spans start parent-first, so reverse insertion order closes the deepest
// children before their parents. Copy first because span.end() calls onEnd.
```

**Weak JSDoc:** `/** Tracks active spans. */`

**Useful JSDoc:** states why `forceFlush` cannot recover open spans, and that this processor must stay first in the provider list.

## Before you keep a comment

1. Can the code say this instead?
2. Will this still be true after the next obvious refactor?
3. Is it next to the line it protects?
4. Would skipping it let someone make a locally reasonable, globally wrong edit?
