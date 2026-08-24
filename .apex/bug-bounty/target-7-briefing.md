# Target #7 — Apex briefing (snapshot / fork content lineage)

HackerOne program: vercel_sandbox. Use only `https://api.vercel.com` sandbox REST routes (`/v2|/v3|/v4/sandboxes*`) plus inbound `*.vercel.run` hosts disclosed for **our** sandboxes. Cap at 5 rps. One root cause per finding. Live PoC required. Stop at confirmation. Do not dump customer data. Prefer this briefing over `web_search`.

Session headers inject **Account A**. Account B PAT is `.apex/bug-bounty/local/headers-b.json`. **Do not print tokens.** Python urllib needs `allow_unprotected: true`.

Target #1 already proved B→A snapshot/fork/session **authorization** is 403/404. **Do not re-prove that.** This hunt is **content lineage**: whether a child snapshot/fork/restore serves the **wrong disk**, including another owned tenant’s canary, via shared snapshot store / S3 / NVMe cache.

## Dual loop

1. **Mutate** via `http_request`: `POST /v3/sandboxes/sessions/{sessionId}/snapshot`, `POST /v3/sandboxes/{name}/fork?projectId=`, `POST /v4/sandboxes` with `source.snapshotId`, `GET/DELETE /v2/sandboxes/snapshots/{snapshotId}`. Snapshot **stops** the session — only snapshot **throwaways**, never `fw-victim` / `fw-observer` / `inbound-a` / `inbound-b` / `host-probe` / `victim-base` while siblings need them.
2. **Observe content** with `POST …/cmd` or `POST …/fs/read` of a unique canary file. Compare **canary bytes**, not HTTP 200.

## Identities

Account A: team `team_7jHS1s2yIuXVrcsI74DRljdn`, project `prj_WgeFvOlmQM1BbtJTEHdQKySMzvC5`, same-team `prj_7uASgsVYJvWLTU8aWVtm059LlSoZ`. Filesystem canary on `victim-base` `/vercel/SECRET.txt` = `CANARY-E1DE39E5-3F20-4243-8F71-3B7410EC73F9`.

Account B: team `team_LO7V6PmnTOI8i66m8MO6g6yb`, project `prj_fuEcV8s1ISZBg4LncdBK1MfScxb9`.

## What counts as a finding

- Fork/restore of sandbox X boots canary of sandbox Y (other name, other project, or Account B).
- B creates/forks from A’s `snapshotId` / `sourceSandbox` and **reads A’s canary** (authz miss with content — Target #1 was 403/404 without content).
- Two owned snapshots with distinct canaries: restore A’s id, guest contains B’s canary (cache/dedup mix).
- `PATCH currentSnapshotId` grafts a foreign snapshot onto a sandbox the caller owns.

Same-sandbox fork inheriting its **own** parent canary is expected. Cross-project 404 for the owner is expected-secure. `getOrCreate` ignoring create params is documented.

## Objectives (focused)

1. Same-account throwaway: write unique canary, snapshot, fork under a new name, confirm child has **that** canary only.
2. Two throwaways (A and B, or A and A2) with distinct canaries, snapshot both, restore each, confirm no mix.
3. Cross-account: B `source.snapshotId` / fork A’s name — 403/404 expected; 200 + A canary is a finding. Stop at confirmation.

## API facts (Target #7 hybrid probe 20 Aug 2026 — do not rediscover)

- Throwaway `lineage-a` canary `/vercel/LINEAGE.txt` = `CANARY-LINEAGE-A-7F3C9B2E`. Manual snapshot `snap_mwyJmWAswBhOSJM71KDRZfqpv5ke`. Fork `lineage-a-child` boots **that** canary only.
- `lineage-b` snapshot `snap_1WxLTImif0JG0bexqQNPZE8UHaf3` (`CANARY-LINEAGE-B-D41A80C1`). Resume of `lineage-a-child` after B’s snapshot still has **A** canary only (no cache mix).
- Owner restore: `POST /v4/sandboxes` `{source:{type:"snapshot", snapshotId}}` on the **same** project returns 200 and the matching canary. `{source:{snapshotId}}` without `type` is 400 additional property.
- Cross-account GET snapshot: B+A `teamId` → 403 Not authorized; B+B `teamId` → 404 Snapshot not found.
- Cross-account create from foreign snapshot → 404 Snapshot not found (A↔B both ways).
- Same-team A2 project create from victim-project snapshot → 404 Snapshot not found (snapshots are **project-scoped**, not team-wide).
- `PATCH currentSnapshotId` foreign snap onto owned sandbox → 404 Snapshot not found. B PATCH on A named sandbox → 403.
- B fork A’s name + B project → 404 name not in this project. B fork A’s name + A project/team → 403.
- Snapshot list cursor from A replayed as B → 400 `invalid_cursor` (not a data leak).

## Documented non-findings

- Target #1 BOLA 403/404 on session/fs/cmd/interactive (no content). Same-sandbox fork inheriting its **own** parent canary.
- `getOrCreate` ignoring create params.

Do not DELETE keep-list sandboxes. Snapshot throwaways only. ≤5 rps.

Read also: `.apex/bug-bounty/scope.md`, `.apex/threat-models/2026-08-20-vercel-sandbox-snapshot-lineage.md`.
