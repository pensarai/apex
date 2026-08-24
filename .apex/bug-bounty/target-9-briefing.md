# Target #9 — Apex briefing (control-plane parameter confusion)

HackerOne program: vercel_sandbox. Sandbox REST only (`/v2|/v3|/v4/sandboxes*`). Cap 5 rps. Live PoC. Stop at confirmation. Session headers = Account A. Account B PAT in `.apex/bug-bounty/local/headers-b.json`. **Do not print tokens.**

Target #1 already proved unauth / invalid token / fake `teamId` → 403 and B→A session/fs/cmd/snapshot **403/404**. **Do not re-run that matrix.** This hunt is **server-side honoring of confused `teamId`/`projectId` pairs** (explicitly in scope per `business-context.md`: SDK OIDC refresh updating `teamId` but not `projectId` is unpaid; a **server** that accepts a stale or swapped pair is in scope). Also error-oracle enumeration that discloses another owned tenant’s objects.

## What to try (once each, record status + body class)

On a **victim** object (named `victim-base` or live `fw-victim` session — do not stop shared sandboxes):

1. B token + A `teamId` + B `projectId` on named GET/PATCH and on session cmd/fs.
2. B token + A `projectId` + B `teamId`.
3. A token + B `teamId` on A’s named sandbox (confused owner).
4. A token + A2 `projectId` on `victim-base` (same-team swap). Cross-project 404 for the owner is expected-secure.
5. Pagination `cursor` from A list replayed with B token (and reverse).
6. `project` vs `projectId` swap on named GET vs LIST (Target #1 already: LIST needs `project=`, named GET needs `projectId=` — only file if a swap **returns the other tenant’s object**).

## Finding vs oracle

- **Finding:** 200/101 that reads, modifies, or executes the **other** account’s object, or returns `victim-base` canary `CANARY-E1DE39E5-3F20-4243-8F71-3B7410EC73F9`.
- **Oracle (Low, only if new):** consistent 403 vs 404 that distinguishes “exists in another team” from “never existed” **beyond** the already-documented 403-with-victim-teamId / 404-otherwise pattern.

## API facts (Target #9 hybrid probe 20 Aug 2026 — do not rediscover)

Named GET `victim-base`: B+A team+A project → 403; B+B team+A project → 404 Could not find project; B+A team+B project → 403; A+B team+A project → 403; A+A team+B project → 404 Could not find project; A+A team+A2 project → 404 Named sandbox not found for this project; B+A team+A2 → 403.

Session cmd on `fw-victim`: B+A team → 403; B+B team or omitted team → 404 Vercel Sandbox not found; A+B team → 403. **No confused pair returned 200.**

`project` vs `projectId`: named GET with `project=` → 400 missing `projectId`; LIST with `projectId=` → 400 missing `project`. A LIST B’s project → 404; B LIST A’s project → 404.

Snapshot list cursor issued to A, replayed by B (snapshots or sandboxes list) → 400 `invalid_cursor`.

Oracle pattern matches Target #1: victim `teamId` on a foreign token → 403; other contexts → 404. Not a new class.

Do not DELETE. Do not POST `{}` network-policy. Do not snapshot shared sandboxes.

Read also: `.apex/bug-bounty/target-1-briefing.md` API facts, `.apex/threat-models/2026-08-19-vercel-sandbox-control-plane.md`.
