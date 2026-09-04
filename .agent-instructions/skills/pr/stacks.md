# Apex PR stacks

Use for any group called a stack, series, chain, or set of parallel PRs. Branch topology is an invariant; formatting follows it rather than defining it.

## Discover the topology

For every PR, record `number`, `state`, `base.ref`, `base.sha`, `head.ref`, `head.sha`, and URL from the API. Also query native stack metadata when present:

```
gh api repos/OWNER/REPO/pulls/<N>
gh api graphql -f query='
query($o:String!,$r:String!,$n:Int!) {
  repository(owner:$o,name:$r) {
    pullRequest(number:$n) {
      number baseRefName baseRefOid headRefName headRefOid
      stack {
        number baseRefName size
        entries(first:100) {
          nodes { position pullRequest { number state baseRefName baseRefOid headRefName headRefOid } }
        }
      }
    }
  }
}' -f o=OWNER -f r=REPO -F n=<N>
```

Classify before editing:

- **Dependent stack** — each PR is based on the preceding branch, or GitHub reports a native stack. Review and merge bottom-to-top.
- **Parallel series** — every PR independently targets `canary`. They can be reviewed in parallel, but each branch must be refreshed against current `canary` before merge.
- **Mixed or inconsistent** — the advertised order and live bases disagree. Stop and surface the exact mismatch; do not silently retarget branches.

Do not convert a parallel series into a dependent stack, flatten a dependent stack, or PATCH native-stack bases merely to make the UI look tidy.

## Body format

Every member gets the same table and a bold current row. Keep this block at the very top:

```
## Stack

> [!NOTE]
> **<Stack name> · PR N of M**<br>
> <Accurate topology/review instruction.>

| Step | Pull request | Focus |
| :---: | --- | --- |
| 1 | [#101](url) | Foundation |
| **2** | **[#102](url)** | **Current focus** · `Current` |
| 3 | [#103](url) | Follow-up |
```

Use one of these notes unless the live topology needs more specificity:

- Dependent: `Review and merge in table order; each PR is based on the preceding step.`
- Parallel: `All PRs target canary and are independently reviewable. The table order follows the implementation story; refresh each branch against canary before merge.`

Use short outcome-oriented focus labels. Do not use arrow chains, repeat full titles, add decorative diagrams, or claim dependencies that do not exist.

## Update every body safely

1. GET every current body.
2. Replace only the leading `## Stack` section, stopping at the next human section such as `## Summary`.
3. Preserve Cursor and CodeSmith regions byte-for-byte.
4. PATCH each PR through `gh api`.
5. GET every body again. Verify the same PR order and labels, exactly one `Current` marker per body, the correct emphasized row, and unchanged bot-region marker counts.

If any body has no unambiguous section boundary, stop rather than replacing it heuristically.

## Refresh code without breaking the stack

- Dependent stacks move bottom-to-top. Refresh the first PR from `canary`, then propagate the resulting parent through each child while preserving each PR's isolated delta.
- Parallel series refresh each branch independently from `canary`.
- Use `conflicts-and-merge.md` for conflict handling. Do not force-push unless explicitly authorized.
- After each push, verify both the branch ref and PR `headRefOid`. GitHub native stacks can briefly show the old head/base and `UNKNOWN` mergeability after a successful push; wait for metadata to converge instead of trying to retarget the PR.

Before declaring the stack aligned, report the verified order, topology type, base for each PR, and whether all displayed bodies match that topology.
