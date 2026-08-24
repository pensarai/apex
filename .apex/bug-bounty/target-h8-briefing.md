# H8 — Apex briefing (snapshot eviction / `keepLastSnapshots`)

HackerOne: vercel_sandbox. Only `https://api.vercel.com` `/v2|/v3|/v4/sandboxes*`. Cap 5 rps. Stop at confirmation. Do not print tokens. Python urllib needs `allow_unprotected: true`. `{host}` in Python format strings trips the scope guard.

**One hypothesis. One worker. No exploratory spawn. Stop at the kill-gate.**

Absolute path: `/Users/yuvaneshanand/Documents/Github/apex-bug-bounty-auto-triage-patch/.apex/bug-bounty/target-h8-briefing.md`

## Hypothesis

Create/PATCH accept `keepLastSnapshots: {count, expiration, deleteEvicted}` (vendored `sandbox.d.ts`). With `count: 1` and `deleteEvicted: true`, a second snapshot should **delete** the first. If B can GET/restore the evicted id, or a new B snapshot boots **A’s** canary (shared S3/NVMe leftover), that is content lineage Target #7 did **not** test (Target #7 was sequential restore of **live** snaps).

A true concurrent race is optional **after** sequential eviction is confirmed. Own-sandbox “snap disappeared” is unpaid.

## Kill-gate (stop if all hold)

- Second snapshot on `h8-a` evicts snap1: A `GET /v2/sandboxes/snapshots/{snap1}` → **404** (retry once if still 200)
- B GET snap1 and B `POST /v4/sandboxes` `{source:{type:"snapshot", snapshotId: snap1}}` → **403/404**, no A canary
- If B creates/restores **its own** snap, guest has only B’s canary (do this only if eviction 404 held and you need the hash-reuse check — one restore)

If create/PATCH rejects `keepLastSnapshots` (**400**), stop. Hypothesis untestable.

## Do not re-prove

- Target #7 sequential live-snap restore (own canary; foreign 404; project-scoped)
- Target #1 / H1 snapshot BOLA 403/404 without eviction
- H2 snapshot tree
- Do **not** snapshot or DELETE: `h3-src-a`, `h3-obs-a`, `fw-victim`, `fw-observer`, `victim-base`, `lineage-a`, `lineage-a-child`, `lineage-b`

## Live objects

Account A: team `team_7jHS1s2yIuXVrcsI74DRljdn`, project `prj_WgeFvOlmQM1BbtJTEHdQKySMzvC5`. Session headers = A.

Account B: team `team_LO7V6PmnTOI8i66m8MO6g6yb`, project `prj_fuEcV8s1ISZBg4LncdBK1MfScxb9`. PAT in `.apex/bug-bounty/local/headers-b.json`.

Create **new** throwaways only: `h8-a` (A), optional `h8-b` (B). `timeout` 300000. `projectId` **in the create body**. When done, DELETE `h8-a` / `h8-b` only.

## Confirmed wire (Target #7 / SDK)

Create (`POST /v3/sandboxes`):

```json
{
  "projectId": "prj_WgeFvOlmQM1BbtJTEHdQKySMzvC5",
  "name": "h8-a",
  "timeout": 300000,
  "keepLastSnapshots": { "count": 1, "deleteEvicted": true }
}
```

Snapshot (stops the session): `POST /v2/sandboxes/sessions/{sbx_id}/snapshot` (SDK) or `/v3/…` (Target #7). Resume: `GET /v2/sandboxes/h8-a?teamId=&projectId=&resume=true`.

Restore: `POST /v4/sandboxes` `{ "projectId", "source": { "type": "snapshot", "snapshotId" } }`. `{source:{snapshotId}}` without `type` is 400.

Canary: write `/vercel/H8.txt` = `CANARY-H8-A`. B uses `CANARY-H8-B`. Compare **bytes**, not HTTP 200.

LIST snaps use `project=`; named GET snap uses `/v2/sandboxes/snapshots/{id}?teamId=`.

## Objectives (this is the only objective)

1. Create `h8-a` with `keepLastSnapshots.count=1`, `deleteEvicted=true`. If 400, stop.
2. Write `CANARY-H8-A`. Snapshot → **snap1**. Resume.
3. Snapshot again → **snap2**. GET snap1 as A. Expect 404. If 200, wait ~10s and GET once more. Still 200 after two snaps = eviction not observed; record and stop (do not DELETE other snaps).
4. B GET snap1 (B team/project, then B token + A team). Expect 403/404. B restore snap1 into B project. Expect 404. **200 + `CANARY-H8-A` is a finding. Stop.**
5. Optional one-shot if step 4 is 403/404: create `h8-b`, write `CANARY-H8-B`, snapshot, restore that id in B. Guest must not contain `CANARY-H8-A`. Mix is a finding.
6. Optional concurrent only if step 3 was 404: one pair — A third snapshot on `h8-a` overlapping B restore of **snap2**. Finding = B 200 after snap2 should be gone, or B guest has A canary. One pair; do not loop.
7. DELETE `h8-a` / `h8-b` only. Call `response`. Do **not** spawn a second worker.

## Finding vs not

- **Finding:** B reads/restores an evicted A snap (content); or B’s new snap/restore contains `CANARY-H8-A`.
- **Not a finding:** A 404 on evicted id; B 403/404; own restore of a **live** snap has own canary (Target #7); 400 on `keepLastSnapshots`; extra blocking.

Read also: `.apex/bug-bounty/whitebox-hypotheses.md`, `.apex/bug-bounty/target-7-briefing.md`.
