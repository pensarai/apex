# Target #1 — Apex briefing (control-plane authorization)

HackerOne program: vercel_sandbox. Use only `https://api.vercel.com` sandbox REST routes (`/v2|/v3|/v4/sandboxes*`) plus inbound `*.vercel.run` hosts that `__includeSystemRoutes` or a ports PATCH discloses for **our** sandboxes. Do not hit dashboard, v0, billing, VCR, `openapi.vercel.sh`, or other Vercel APIs. Cap at 5 requests per second. One root cause per finding. Live PoC required. Stop at confirmation. Do not dump customer data. Do not encode/obfuscate URLs to dodge the scope guard. Prefer this briefing over `web_search`.

This engagement now has **two Vercel users**. Session HTTP headers inject **Account A** (victim). Account B’s PAT is in `.apex/bug-bounty/local/headers-b.json` — copy the `Authorization` value into `http_request` headers for attacker-principal tests. **Do not print either token.**

A 200 from a token on an object it owns is **not** a vulnerability. Same-team Account A project-A vs project-A2 404s are expected-secure. Document only if Account B reads, modifies, or executes on Account A’s sandbox/session/snapshot (or the reverse). Unauthenticated hits to a **published user port** that return `SANDBOX_NOT_LISTENING` are not findings. Interactive TTY / port 26661 without a minted token would be a finding.

## Tooling (this is why the last run struggled)

- Session HTTP headers already include **Account A** `Authorization: Bearer`. `http_request` and `curl` auto-inject it. **Do not print tokens.**
- Unauth tests: `'{"Authorization":""}'` or `'{"Authorization":"Bearer invalid"}'`. Account B tests: set `Authorization` from `.apex/bug-bounty/local/headers-b.json` (request overrides win). If you omit the headers argument, you are still Account A.
- Do not `POST /stop` on `victim-base` while other workers need it. Use `attacker-probe` / `attacker-b` if you must stop something.
- `*.vercel.run` is in session scope this run. Call it with `http_request` directly. Unauth tests on it still need the Authorization override, because the PAT is injected for in-scope hosts.
- Named sandboxes are PATCHed to `timeout: 2700000` (Hobby max). **First action in every worker:** `GET …?resume=true`. If `session.timeout` is 300000, `POST …/sessions/{id}/stop` then resume again so the new session inherits 45 minutes. `POST …/extend-timeout` `{"duration":60000}` works only up to the live session's remaining max — do not send 2700000 against a 5-minute session. Do not `POST /snapshot` (it stops the session). Do not `POST /network-policy` with `{}` (full replace to `mode=custom`). Do not DELETE. Do not PATCH port 26661 (system-reserved; rotates the session).
- Session/snapshot IDs rotate on resume. Look them up; do not trust IDs in this file. Pre-run live IDs (will rotate if you stop): victim `sbx_3YdYQTzFCxfcp9t7zw1JeK6iDsws` / `snap_mf8L0TgL1ackIrb17bMK8COTIja4`; attacker `sbx_u78v5eTCFl5P5Arb295GMtbJzU6A` / `snap_URxOgKbVu1aEWTrxLVhavn7eGjkQ`.

## API facts (already proven — do not rediscover)

- Live collection is `/v2/sandboxes*`. GET `/v3|/v4/sandboxes` as a list is generic 404. Create is `POST /v4/sandboxes` (and `/v2`). Session subresources live under `/v2/sandboxes/sessions/{sbx_id}/…`, not `/v2/sandboxes/{sbx_id}/…`.
- LIST requires query `project=` (id). `projectId` alone → 400. Named GET requires `projectId=`. `project` alone → 400. Project slugs are not resolved.
- `POST …/cmd` body is `{"command":"/bin/true"}` — `command` is a binary path string, not argv or a shell line. Args if needed are a separate field from the OpenAPI schema, not a shell string.
- Interactive is **`POST /v2/sandboxes/sessions/{sessionId}/interactive`**. `/v2/sandboxes/{id}/interactive` 404s (wrong slot). After a 200, hit the disclosed system `*.vercel.run` (port 26661) **without** the owner PAT. Owner-minted token used by the owner is not a finding.
- `GET ?__includeSystemRoutes=true` adds `{url: https://sb-….vercel.run, port: 26661, system: true}`. Without the flag, `routes=[]` unless user ports were PATCHed.
- v3/v4 `sessions/…/fs` and `/cmd` 404; use v2.
- Unauth / invalid token / fake `teamId` already 403. Same-user interactive TTY is token-gated (401 without `?token=`). Do not re-prove those. Spend this run on **Account B vs Account A** session/snapshot/interactive IDOR.

## Identities

Account A (victim, session default PAT) — user `Ini8xEkCg605GgClB8J4O1yT` / `yuvaa-7607`:
- Team: `team_7jHS1s2yIuXVrcsI74DRljdn` (slug `test11-ad11`)
- Victim project: `prj_WgeFvOlmQM1BbtJTEHdQKySMzvC5` (`sbx-h1-victim`)
- Same-team second project: `prj_7uASgsVYJvWLTU8aWVtm059LlSoZ` (`sbx-h1-attacker`)
- Victim sandbox: `victim-base` — canary `/vercel/SECRET.txt` = `CANARY-E1DE39E5-3F20-4243-8F71-3B7410EC73F9`
- Same-team sandbox: `attacker-probe`

Account B (attacker, headers-b.json) — user `LWgYUj0PGJ0ncS5cB55mxUmM`:
- Team: `team_LO7V6PmnTOI8i66m8MO6g6yb`
- Project: `prj_fuEcV8s1ISZBg4LncdBK1MfScxb9` (`nextjs-boilerplate1`) — token cannot create additional projects
- Sandbox: `attacker-b` (persistent, 45 min). Live session IDs rotate; look up before use. Last known `sbx_4rlO4IUVRDYnoLgWLQQKsW8teBkM`

Baseline already observed (do not refile): A GET B `attacker-b` → 403 Not authorized; B GET A `victim-base` → 403; foreign `sessionId` GET/fs/read → 404 Vercel Sandbox not found. A finding is a **200/101** from the other account on cmd/fs/interactive/snapshot/fork/stop.

Resume: `GET /v2/sandboxes/{name}?projectId=…&teamId=…&resume=true` then extend-timeout.

Read program context if needed: `.apex/bug-bounty/scope.md`, `.apex/bug-bounty/engagement.md`, `.apex/threat-models/2026-08-19-vercel-sandbox-control-plane.md`. Those markdown files are engagement docs, not application source — reading them is allowed.
