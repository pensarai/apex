# Review comments and Cursor Bugbot

Use after a PR exists and human reviews, inline comments, or Bugbot findings appear. Fix findings that are real; do not resolve a thread that has not been addressed.

## Fetch everything

Paginate issue comments, reviews, and inline comments:

```
gh api repos/OWNER/REPO/issues/<N>/comments --paginate
gh api repos/OWNER/REPO/pulls/<N>/reviews --paginate
gh api repos/OWNER/REPO/pulls/<N>/comments --paginate
```

Fetch review threads and resolved state through GraphQL, paging until `hasNextPage` is false:

```
gh api graphql -f query='
query($o:String!,$r:String!,$n:Int!,$after:String) {
  repository(owner:$o,name:$r) {
    pullRequest(number:$n) {
      headRefOid
      reviewThreads(first:100,after:$after) {
        pageInfo { hasNextPage endCursor }
        nodes {
          id isResolved isOutdated path
          comments(first:50) { nodes { databaseId author { login } body createdAt } }
        }
      }
    }
  }
}' -f o=OWNER -f r=REPO -F n=<N>
```

Also inspect the `Cursor Bugbot` check output for the current SHA. A successful check does not replace reading unresolved review threads.

## Classify against current HEAD

For every unresolved item:

1. Re-read the cited code at the current head; stale findings may already be fixed.
2. **Valid** — reproduce or prove the violated invariant, fix the smallest cause, and add/adapt a test that would have caught behavioral defects.
3. **Already fixed** — reply with the fixing SHA and current code path; do not make a duplicate change.
4. **False positive** — reply with concrete evidence showing why the invariant holds. Do not distort code to silence a bot.
5. **Out of scope or product disagreement** — explain the boundary and leave the thread open unless the user explicitly waives it.

When two comments conflict, pick the interpretation supported by newer code, tests, or product direction. Explain the conflict; do not average incompatible requests.

## Reply and resolve

Reply to an inline comment with its database ID:

```
gh api --method POST repos/OWNER/REPO/pulls/<N>/comments \
  -f body='<finding, evidence, change, and SHA>' \
  -F in_reply_to=<comment_id>
```

Resolve a review thread only after the fix is pushed or the evidence-backed false-positive reply is posted:

```
gh api graphql -f query='
mutation($id:ID!) {
  resolveReviewThread(input:{threadId:$id}) { thread { isResolved } }
}' -f id=<THREAD_NODE_ID>
```

Do not bulk-resolve, dismiss a human changes-requested review, or post a vague "fixed" reply. Preserve `CURSOR_SUMMARY` and `codesmith:footer` regions when updating the body.

After pushing, apply `babysit.md` to the new SHA and re-fetch threads because Bugbot or reviewers may add findings during the run.
