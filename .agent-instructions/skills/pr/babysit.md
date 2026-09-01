# Babysit an Apex PR

Stay with the PR until its technical state is settled. Opening it, pushing a fix, or seeing queued checks is not done.

## Terminal state

All of these must hold on the **latest PR head SHA**:

| Gate                    | Pass when                                                                                                                                                                                                                  |
| ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Branch identity         | The remote branch ref and PR `head.sha` match. Native-stack metadata has finished catching up.                                                                                                                             |
| Core CI                 | Current expected checks — `lint / lint`, `dead-code / dead-code`, `typecheck / typecheck`, `test / test`, and `build / build` — succeed. Honor any additional required check GitHub reports.                               |
| Integration/docs checks | `console-typecheck` and repository-owned documentation checks succeed when posted or required. A genuinely skipped non-applicable job is acceptable; a missing required status is pending.                                 |
| Bugbot                  | `Cursor Bugbot` has a conclusion when posted. `success` and `neutral` are terminal; `neutral` may contain findings that still require review.                                                                              |
| Mergeability            | GitHub reports `MERGEABLE`. `mergeStateStatus: BLOCKED` is terminal only after technical checks are green and the only remaining gate is human/CODEOWNERS approval. `DIRTY`, `BEHIND`, and `UNKNOWN` are not ready states. |
| Review                  | No unresolved actionable human or Bugbot threads remain.                                                                                                                                                                   |

Pending, queued, or in-progress work means keep waiting. Green checks from a previous SHA do not count.

## Poll with backoff

```
gh api repos/OWNER/REPO/pulls/<N> --jq '{head:.head.sha,base:.base.sha,mergeable,mergeable_state,draft}'
gh api repos/OWNER/REPO/commits/<SHA>/check-runs --paginate
gh api repos/OWNER/REPO/commits/<SHA>/status
```

If mergeability is `null` or stack metadata still shows an older SHA, wait and retry using tens-of-seconds then minute-scale intervals. Do not busy-loop, mutate the PR to provoke recomputation, or call stale checks current.

## Red CI

1. Identify the failing check, run, job, and first substantive failure.
2. Fetch enough logs to establish the cause:

   ```
   gh api repos/OWNER/REPO/actions/runs/<run_id>/jobs --paginate
   gh api repos/OWNER/REPO/actions/jobs/<job_id>/logs
   ```

3. Reproduce locally when possible. Fix the smallest root cause and add or update a regression test for behavioral defects.
4. Re-run focused checks plus the relevant project-level commands from `create-and-update.md`.
5. Commit and push only when authorized by the user's requested workflow, then restart babysitting on the new SHA.

Do not use `--no-verify`, retry a deterministic failure without a code/config change, or cancel another contributor's workflows.

## CI outage or stuck run

First distinguish queued capacity, an active run, a cancelled/failed outage run, and a missing workflow trigger. If the user asks to re-kick CI and the prior run is terminal, rerun the existing workflow through the Actions API. Do not create empty commits merely to retrigger checks, and do not duplicate a run that is still active.

## Done

Report the PR URL, latest head SHA, required-check conclusions, Bugbot/review state, mergeability, and any remaining human approval. Human approval alone may remain; unresolved technical state may not.
