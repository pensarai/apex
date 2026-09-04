# Resolve conflicts and merge Apex PRs

Conflict resolution and merging are separate intents. A request to resolve conflicts and push authorizes updating the PR branch; it does **not** authorize merging the PR.

## Resolve conflicts

1. GET the live PR and record its number, head/base refs and SHAs, stack metadata, mergeability, and current checks.
2. Use a clean isolated checkout of the PR head. Verify the checked-out commit equals the recorded remote head before editing.
3. Read `stacks.md` when the PR belongs to a dependent or parallel series. Preserve that topology.
4. Fetch the current head and base. If the remote head advanced since step 1, stop and incorporate the new work before continuing.
5. Prefer a regular merge of the current base into the PR branch; this refreshes reviewed history without requiring a force-push:

   ```
   git fetch origin <head-ref> <base-ref>
   git merge --no-edit origin/<base-ref>
   ```

   Rebase only when the user explicitly asks or established stack tooling requires it. Never use an unguarded force-push.

6. If conflicts occur, list every unmerged path and read both sides plus relevant callers/tests. Reconcile behavior deliberately; never blanket-select `ours` or `theirs`, and never remove one side's feature just to clear markers.
7. Verify `git ls-files -u` is empty, `git diff --check` passes, the resulting diff still represents the PR's intended delta, and no conflict markers remain in changed source.
8. Run focused regression tests and the project-level checks appropriate to the touched files. `bun run test` is mandatory when code changed.
9. Fetch once more and confirm the remote PR head is still the SHA from which the resolution started. If it changed, integrate it rather than overwriting it.
10. Push normally. Then wait until the PR `head.sha` matches the pushed branch ref and GitHub reports known mergeability. Native stacks may need a few minutes to recalculate; do not PATCH the base to hurry them.

Report the merge commit SHA, validation, push result, and fresh CI state. Do not call `BLOCKED` a conflict when GitHub reports `MERGEABLE` and is only waiting on checks or approval.

## Merge only when explicitly authorized

Immediately before merging:

1. Re-fetch the PR and confirm its latest head SHA, intended base, stack position, approvals, required checks, Bugbot conclusion, unresolved threads, and mergeability.
2. Re-run `babysit.md` if any technical state is stale or pending.
3. For a dependent stack, merge bottom-to-top and verify each merge before refreshing the next PR. For a parallel series, merge one requested PR at a time and refresh remaining branches from the new `canary` before their merges.
4. Use the repository's current accepted merge method. If the method is ambiguous or materially changes history, ask rather than guessing.
5. Supply the inspected head SHA as a concurrency guard:

   ```
   gh api --method PUT repos/OWNER/REPO/pulls/<N>/merge \
     -f sha='<latest-head-sha>' \
     -f merge_method='<approved-method>'
   ```

6. Verify the API reports `merged: true`, record the merge commit, and confirm the target branch contains it before moving to another stack member.

Do not bypass branch protection, enable auto-merge, delete branches, merge additional stack members, or retry a rejected merge unless the user authorized those actions.
