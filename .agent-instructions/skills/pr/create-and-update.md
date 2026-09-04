# Create or update an Apex PR

Use for ordinary feature, fix, refactor, test, documentation, or chore work. Ordinary Apex PRs target `canary`.

## Preflight

1. Resolve `OWNER/REPO` from `origin`; do not assume a fork or repository name.
2. Inspect `git status`, the branch upstream, and the full commit/diff range against the intended base. If the checkout contains unrelated work, use a separate worktree or clone rather than stashing or moving it.
3. For a new PR, fetch current `canary` and branch from it. For an existing PR, fetch and trust the live `base.ref`, `base.sha`, `head.ref`, and `head.sha` from GitHub.
4. Before changing an existing branch, confirm its remote head still equals the SHA you inspected. Surface concurrent updates instead of overwriting them.
5. Read the complete PR delta, not only the newest commit:

   ```
   git log --oneline origin/<base>..HEAD
   git diff --stat origin/<base>...HEAD
   git diff origin/<base>...HEAD
   ```

6. The branch and PR must contain one coherent change. Keep refactors separate from feature behavior unless the feature cannot land cleanly without the refactor.
7. Run checks proportional to the diff. For code changes, the floor is `bun run test`, `bun run tsc`, `bun run lint`, and `bun run format:check`; add focused tests while iterating, `bun run knip` for dependency/export changes, and `bun run build` for CLI/build-path changes. Record exact results and any named pre-existing warnings.
8. Never put credentials, customer data, local configuration, or generated runtime artifacts in the branch or PR body.

## Issue link

Search before claiming there is no issue:

```
gh api -X GET search/issues -f q='repo:OWNER/REPO is:issue <terms>'
```

Use `Fixes #N`, `Closes #N`, or `Resolves #N` only when the PR actually completes that issue. Otherwise say `No linked issue`; never invent a number.

## Title and body

Titles follow recent Apex conventional-commit style: `fix(observability): flush traces on exit`, `feat(models): add family search`, or `docs(agents): add PR workflow`.

The repository template is the floor. Prefer this compact human-authored structure:

```
## Summary

<what changed, why it was needed, and the resulting behavior in 1–3 short paragraphs>

No linked issue

## Changes

- <reviewable outcome, not a file inventory>

## Validation

- `bun run test` — <result>
- `bun run tsc` — <result>
- Manual: <behavior verified, when applicable>
```

Omit **Changes** when the summary is sufficient. Validation must describe commands and behavior actually verified; do not mark planned work as completed. Add screenshots or terminal captures only when they materially help review and contain no sensitive data.

For stacked work, prepend the exact stack block from `stacks.md`.

## Create

Push the branch with a regular push, then create the PR through the API:

```
git push -u origin HEAD
gh api --method POST repos/OWNER/REPO/pulls \
  -f title='<type(scope): imperative summary>' \
  -f head='<branch>' \
  -f base='canary' \
  -f body='<markdown>' \
  -F draft=false
```

Use a draft only when the user asks or the work is knowingly incomplete. Return the URL, then apply `babysit.md`.

## Update

GET the current PR before every PATCH:

```
gh api repos/OWNER/REPO/pulls/<N>
gh api --method PATCH repos/OWNER/REPO/pulls/<N> -f title='…' -f body='…'
```

Splice only the intended human-authored section. Preserve these regions and their contents exactly:

- `<!-- CURSOR_SUMMARY -->` through `<!-- /CURSOR_SUMMARY -->`
- `<!-- codesmith:footer -->` through `<!-- /codesmith:footer -->`

After patching, GET the PR again and verify the title, base, stack block, bot-region marker counts, and current-row emphasis. Push code changes normally; force-push only with explicit authorization and only with `--force-with-lease`. Then babysit the new SHA.
