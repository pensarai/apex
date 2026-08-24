# Whitebox hypotheses — `@vercel/sandbox` 3.1.0

Source: vendored npm dist at [vendor/vercel-sandbox/](vendor/vercel-sandbox/). Client-only defects are out of scope; each hypothesis is a **server** behavior to prove or kill with one live probe.

Method: one hypothesis per run. First 1–2 probes that confirm fail-closed **stop the objective**. Do not reopen Targets #1/#3/#4/#5/#6/#7/#9/#10 authz matrices.

## Priority

### H1 — `PATCH …/sandboxes/{name}` `currentSnapshotId` swap — KILLED 24 Aug 2026

`updateSandbox` sends `currentSnapshotId` in the PATCH body ([api-client.js](vendor/vercel-sandbox/dist/api-client/api-client.js)). Live probe on `lineage-a-child` (pointer `snap_0AqYgNYgDtnCjPGKbyo0D4pqTnbV` unchanged):

- A PATCH B snap → 404 `Snapshot 'snap_…' not found`
- A PATCH A2 same-team other-project snap → 404 (project-scoped, same as Target #7 create-from-snap)
- B PATCH A name + A team/project → 403 Not authorized
- B PATCH A name + B team/project → 404 named sandbox not in this project

Do not re-prove. Do not resume after a 404.

### H2 — Snapshot tree leaks foreign nodes — KILLED 24 Aug 2026

`GET /v2/sandboxes/snapshots/tree?snapshotId=&project=` (`limit` must be `<= 10`). Live:

- A tree on A snap → 200, own lineage only (no B / A2 ids or sessions)
- A tree on B snap or A2 snap with A project → 200 `count=0` (empty, not a leak)
- A2 project tree → own A2 lineage only
- B tree on A snap + B project → 200 empty; B + A team/project → 403
- Fake `snap_` (32 chars) and foreign real id both 200 empty — no existence oracle

Do not re-prove.

### H3 — Request/response policy dialect mismatch — KILLED 24 Aug 2026

Throwaways `h3-src-a` / `h3-obs-a` (observer `https://sb-5rarngbmyb2q.vercel.run`). Controls still work: allow-map-only 200 (readback `forwardRules`); custom+`injectionRules` 200; `allow:[]` 200; deny-all 200.

Mixed dialects:

- allow-map + leftover `injectionRules` and/or `forwardRules` → 400 `additional property allow`
- same V2 rule `transform` + `forwardURL` → 400 `cannot set both` (server matches client `.refine`)
- `{mode:custom, injectionRules, forwardRules}` → 400 `additional property forwardRules`
- `{mode:allow-all, forwardRules}` → 400 `additional property forwardRules`
- `{mode:allow-all, injectionRules:[{domain:example.org}]}` → **200** persist. Guest curl observer (wrong host) and `example.com`: **no** `CANARY-H3-EXTRA`
- `{mode:deny-all, injectionRules}` → **200** persist; guest curl observer is DNS-fail (deny-all). Leftover inject is stored and inert

No extra inject/forward beyond the named host. Do not re-prove. Restore was `{mode:deny-all}`.

### H4 — `headerNames` secret-name binding — KILLED 24 Aug 2026

Apex `ses_fcbf6230bffeLEUYjZhZTGNT1R` (one worker, no exploratory spawn). Control `headers: {x-canary-h4: CANARY-H4-A}` injects on the owned observer (intended). Request-only `headerNames` → 400 `additional property headerNames` (readback-only). B stored `CANARY-H4-B` on a B session; A name-bind of that name still 400 / no B canary. Restored `{mode:deny-all}`. Do not re-prove.

### H5 — OIDC `aud` after `normalizeForwardUrl` path strip — KILLED 24 Aug 2026

Apex `ses_fcbec42d7ffeam4rYyEuQhtwen` (one worker). `forwardURL` observer+`/callback`: guest `/callback`, `/x/callback`, `/callback/extra`, `/` all mint `aud` = configured `/callback` and source (h3-src-a) claims. Same for `/a/b` vs `/x/a/b`. Matcher `startsWith /callback`: `/other` and `/` hit live example.com with no OIDC. Restored `{mode:deny-all}`. Guest path does not shrink `aud`. Do not re-prove.

### H6 — `match.regex` compiled on the host — KILLED 24 Aug 2026

Apex `ses_fcbe0bcacffenroDb7fPqPDthK` (one worker). Valid `^/h6-only$` accepted; canary only on `/h6-only` (scoped). Invalid `(` → 400. Restored `{mode:deny-all}`. Do not re-prove. Do not pursue ReDoS.

### H7 — `__` private params reach the control plane — KILLED 24 Aug 2026

Apex `ses_fcbd22106ffeOc4uYwRlw6Zcz3` (one worker). GET `h3-src-a` A pair + `__` B → 200 still A (ignored). A token + B pair + `__` A → 403 (did not repair). GET `fw-observer` A pair + `__` B → 404. POST `/v3/sandboxes` with body `__projectId`/`__teamId` of B → 400 unknown `__projectId`. Same 403/404 oracle as Target #9. Do not re-prove.

### H8 — Snapshot eviction / `keepLastSnapshots` TOCTOU — BLOCKED 24 Aug 2026 (Hobby quota)

Apex `ses_fcb61e0b0ffeqHw96nV15QZfP3` (one worker). `POST /v3/sandboxes` `h8-a` with `keepLastSnapshots: {count:1, deleteEvicted:true}` → **402** snapshot-storage quota (not a 400 on the field). Create without the policy and ephemeral/v2 retries also 402. Account A already has 9 persistent sandboxes, each with `keepLastSnapshots.count=1` and a ~642MB current snap (~12GB listed). Eviction/B-restore never ran. **Not killed.** Retry only after freeing leftover storage (not keep-list: `h3-*` / `fw-victim` / `victim-base` / `lineage-*`) or on Pro.

### H9 — `sudo` / `env` on `POST …/cmd` vs policy — KILLED 24 Aug 2026

Apex `ses_fcb343767ffeLSbS5v0CzoWnv2` (one worker). `h3-src-a` `sudo:true` `/usr/bin/id` → in-guest uid 0 (unpaid). `env.H9_CANARY` echoed `CANARY-H9-ENV` only. `host-probe` allow-all `sudo` curl `169.254.169.254` IMDS and IAM path → curl exit 7 (refused). No host path / no other-tenant canary. Do not re-prove.

## Retired / do not run

- Authz matrices for Targets #1, #3, #4, #6, #7, #9, #10.
- Drives (`/v2/sandboxes/drives*`) until Pro + waitlist (Target #8).
- Client OIDC refresh updating `teamId` (`owner_id`) but not `projectId` — documented client-side in `ensureValidToken`.
- `defineSandboxProxy` audience helper bugs that cannot be triggered by the Vercel broker.

## Next run

Listed H1–H7 and H9 are fail-closed. **H8** stays open (Hobby snapshot-storage 402). Retry H8 only after freeing leftover snaps (not keep-list), or hold for the next post-op. Stay on Grok until that evaluation; do not switch to GPT-5.6 Sol yet.
