# Resolve conflicts and merge Apex PRs

Conflict resolution and merging are separate intents. A request to resolve conflicts and push authorizes updating the PR branch; it does **not** authorize merging the PR.

## Resolve conflicts

1. GET the live PR and record its number, head/base refs and SHAs, stack metadata, mergeability, and current checks.
2. Use a clean isolated checkout of the PR head. Verify the checked-out commit equals the recorded remote head before editing.
3. Read `stacks.md` when the PR belongs to a dependent or parallel series. Preserve that topology.
4. Fetch the current head and base. If the remote head advanced since step 1, stop and incorporate the new work before continuing.
5. Rebase the PR branch onto the current base. Do not merge the base into the PR branch: PR branches keep linear history, and a merge commit hides which changes belong to the PR.

   ```
   git fetch origin <head-ref> <base-ref>
   git rebase origin/<base-ref>
   ```

   For a dependent stack, rebase bottom-to-top per `stacks.md`. A child branch still contains its parent's old commits, so name them to leave them behind. Record the parent's head SHA before rebasing the parent, then:

   ```
   git rebase --onto <rebased-parent> <old-parent-sha> <child-branch>
   ```

   A plain `git rebase <rebased-parent>` only skips old parent commits that are still patch-identical. One that changed while the parent was rebased is replayed into the child.

6. If conflicts occur, list every unmerged path and read both sides plus relevant callers/tests. Reconcile behavior deliberately; never blanket-select `ours` or `theirs`, and never remove one side's feature just to clear markers.
7. Verify `git ls-files -u` is empty, `git diff --check` passes, the resulting diff still represents the PR's intended delta, and no conflict markers remain in changed source.
8. Run focused regression tests and the project-level checks appropriate to the touched files. `bun run test` is mandatory when code changed.
9. Publish the rebase with a force-push leased on the head SHA you recorded in step 1, or the newer one you integrated in step 4. Do not fetch and lease on whatever the remote holds now: that accepts a commit pushed since you last looked and then discards it.

   ```
   git push --force-with-lease=<head-ref>:<recorded-head-sha> origin HEAD:<head-ref>
   ```

   A rejected push means the remote head moved. Fetch, integrate the new work, and go back to step 4. Never force-push `canary` or `main`.

10. Wait until the PR `head.sha` matches the pushed branch ref and GitHub reports known mergeability. Native stacks may need a few minutes to recalculate; do not PATCH the base to hurry them.

Report the old and new head SHAs, validation, push result, and fresh CI state. Do not call `BLOCKED` a conflict when GitHub reports `MERGEABLE` and is only waiting on checks or approval.

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
