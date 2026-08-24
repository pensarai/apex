# Target #4 — Apex briefing (inbound `*.vercel.run` route lifetime)

HackerOne program: vercel_sandbox. Use only `https://api.vercel.com` sandbox REST routes (`/v2|/v3|/v4/sandboxes*`) plus inbound `*.vercel.run` hosts that `__includeSystemRoutes` or a ports PATCH discloses for **our** sandboxes. Do not hit dashboard, v0, billing, VCR, `openapi.vercel.sh`, or other Vercel APIs. Cap at 5 requests per second. One root cause per finding. Live PoC required. Stop at confirmation. Do not dump customer data. Do not encode/obfuscate URLs to dodge the scope guard. Prefer this briefing over `web_search`.

This engagement has **two Vercel users**. Session HTTP headers inject **Account A** (victim). Account B’s PAT is in `.apex/bug-bounty/local/headers-b.json` — copy the `Authorization` value into `http_request` headers for attacker-principal tests. **Do not print either token.**

Target #1 (session/snapshot/fork/interactive IDOR) and Target #3 (firewall enforcement / persist / policy IDOR) are **exhausted**. Do not reopen them. Target #3 left `forwardURL`/OIDC for Target #6 (SDK allow-map, not `{allow:[{host,forwardURL}]}`). Target #6 is now also closed. This hunt is inbound lifetime only.

This hunt is **binding over time**. Compare **canary body**, not just HTTP 200.

## Dual loop

1. **Mutate** via `http_request` to `api.vercel.com`: `PATCH /v2/sandboxes/{name}?projectId=` `ports` (full replace; omitted ports deregister), `POST …/sessions/{id}/stop`, `GET …?resume=true`, fork, `POST /v2/sandboxes/sessions/{sessionId}/interactive`. Session IDs rotate — re-GET.
2. **Observe inbound** from the Apex host (not in-guest curl): `http_request` to the disclosed `https://sb-….vercel.run` URL. **Override Authorization empty** (`{"Authorization":""}`) because the session PAT is auto-injected for in-scope hosts. Unauth published-port 200 with the **correct** canary is expected, not a finding.
3. Account B tests: Authorization from `.apex/bug-bounty/local/headers-b.json`. Python urllib needs `allow_unprotected: true`. If you omit headers, you are still Account A.
4. `*.vercel.run` is in session scope. Do **not** enumerate or guess other `sb-` labels (other tenants are out of scope).
5. Restart a dead listener with `POST …/cmd` `{"command":"/usr/bin/python3","args":["/tmp/observer.py"],"wait":false}` — omit `logs` when `wait` is false. `command` is a binary path.

## Hard constraints

- Named sandboxes are `timeout: 2700000`. If a live session is still 300000, stop **that** sandbox only if it is not the sibling’s shared canary (`inbound-a` / `inbound-b`), then resume. `extend-timeout` cannot exceed the live session max.
- **Do not `POST /stop` on `inbound-a` or `inbound-b`** while siblings still need those URLs. Lifetime/stop tests use a **throwaway fork/copy**. Do not `PATCH` port **26661** on a shared sandbox (system-reserved; rotates the session).
- Do not `POST /snapshot`. Do not DELETE keep-list sandboxes. Do not print tokens. `{host}` in Python format strings trips the scope guard. ≤5 rps.

## Live objects (IDs and URLs rotate)

Account A (victim, session default PAT) — user `Ini8xEkCg605GgClB8J4O1yT` / `yuvaa-7607`:
- Team: `team_7jHS1s2yIuXVrcsI74DRljdn` (slug `test11-ad11`)
- Victim project: `prj_WgeFvOlmQM1BbtJTEHdQKySMzvC5` (`sbx-h1-victim`)
- Same-team second project: `prj_7uASgsVYJvWLTU8aWVtm059LlSoZ` (`sbx-h1-attacker`)
- **Inbound canary:** `inbound-a`, published port **8080**, body/header `CANARY-INBOUND-A`. Pre-run session `sbx_v9m4eYbz2IPpI2e7PC7QcRlFgwNO`. URL (rotates): `https://sb-1o5vk5aml7ra.vercel.run`. Look up with `GET /v2/sandboxes/inbound-a?projectId=…&teamId=…` — `routes[].url` for port 8080.
- Leave `victim-base` / `attacker-probe` / `fw-victim` / `fork-same-project` alone. Filesystem canary on `victim-base`: `/vercel/SECRET.txt` = `CANARY-E1DE39E5-3F20-4243-8F71-3B7410EC73F9`.

Account B (attacker, headers-b.json) — user `LWgYUj0PGJ0ncS5cB55mxUmM`:
- Team: `team_LO7V6PmnTOI8i66m8MO6g6yb`
- Project: `prj_fuEcV8s1ISZBg4LncdBK1MfScxb9` (`nextjs-boilerplate1`)
- **Inbound canary:** `inbound-b`, published port **8080**, body/header `CANARY-INBOUND-B`. Pre-run session `sbx_M8prt4uYJlMFHzomg4os81LHlCCn`. URL (rotates): `https://sb-5eipaht02uqq.vercel.run`.
- Keep `attacker-b` / `fw-observer` (stopped is fine). Do not delete.

LIST uses query `project=`. Named GET uses `projectId=`. Interactive is **`POST /v2/sandboxes/sessions/{sessionId}/interactive`** — `/v2/sandboxes/{name}/interactive` 404s.

## API facts (Target #4 run `ses_fe3fc74f7ffe3J1S2GWwOUNgrx` — do not rediscover)

- At rest, `inbound-a` / `inbound-b` bind A→A and B→B. Host-header vhost on the shared edge follows `Host` (expected); it does not poison the matching-Host URL.
- `PATCH ports=[]` or omitted-port replace fail-closed: old URL becomes `SANDBOX_NOT_FOUND` / `SANDBOX_NOT_LISTENING`, even if the guest listener is still running. Session stop → `410 SANDBOX_STOPPED`.
- User-port hostnames are sticky per named sandbox across resume; system 26661 host rotates. Forks get a new `sb-…` while the parent is live. Stopped hosts do not serve another live canary.
- TTY: current mint → 101; no token → 401. After stop, old token/old host → 502. After resume (session+26661 host rotate), stale token on the new listener → 401; old host → 502. Cross-session tokens → 401. B cannot mint A (403).
- First 502 after resume/unpublish then fail-closed is not a finding. Wrong-canary / stopped-VM-still-serving was not observed.

## Documented non-findings (do not “discover” these)

- Unauthenticated GET of a **currently published** user port on an owned sandbox (or the other owned account while that port is live). Account B hitting Account A’s live `inbound-a` URL and seeing `CANARY-INBOUND-A` is **expected**.
- `SANDBOX_NOT_LISTENING` on a published URL when nothing listens.
- TTY 401 without `?token=`; 101 with a **currently minted** owner token used by the owner; B cannot mint A’s token (Target #1). Empty auth + A-minted token is intended capability-token semantics.
- Scanning or guessing other tenants’ `sb-*` hosts.
- SDK-only bugs; own-sandbox DoS; Target #3 firewall / empty `{}` network-policy / rejected `{allow,forwardURL}` dialect.
- First request after resume 502 then success (documented sandbox-router cache briefly stale) — **only** file if the wrong canary or a stopped VM is served.

## What counts as a finding

- After `PATCH ports=[]`, stop, timeout, or delete of a **throwaway**, the **old** URL still returns that sandbox’s canary (stale route to a guest that should be unreachable).
- A’s live URL returns **B’s** canary (or reverse) — hostname mixed across tenants.
- Fork parent and child share one live `sb-…` that serves both canaries, or inbound to parent hits child.
- `PATCH ports` full replace leaves an omitted port/URL still serving the canary.
- Interactive: 101 **without** a current mint, or old token / old `wss://` host attaches to a **different** session after stop/resume.
- B opens A’s TTY without A’s minted token.

## Objectives (one worker each)

1. Published-port lifetime on a **throwaway** copy of `inbound-a` (do not stop shared `inbound-a` if siblings need it): live GET canary → unpublish or stop → old URL must not keep returning the canary.
2. Hostname uniqueness / resume: stop+resume only a throwaway (or `inbound-a` if you restore the listener before siblings finish). Old host must not serve a different live canary. Fork must not share the parent hostname while both are live.
3. Interactive TTY lifetime: mint on `POST …/sessions/{sessionId}/interactive`, confirm 101 with token, then stop/resume a throwaway and retry old token + old `wss://` host. Do not PATCH 26661 on shared sandboxes.
4. Cross-account binding: B GET A’s published URL while live is expected (`CANARY-INBOUND-A`). Finding = B’s GET of A’s URL returns `CANARY-INBOUND-B`, or A’s URL still serves A after unpublish/stop, or B opens A’s TTY without A’s token. Reverse A on B. Stop at confirmation.
5. Port replace + fork routes: `PATCH ports` deregisters omitted ports. Fork with different ports must not alias parent and child. Residual: HTTP vs WS on 26661 without token (401 expected).

Chain worker: router-cache race immediately after resume **only if** the wrong canary or a stopped VM is served.

Read also: `.apex/bug-bounty/scope.md`, `.apex/bug-bounty/engagement.md`, `.apex/threat-models/2026-08-19-vercel-sandbox-inbound-routes.md`. Those markdown files are engagement docs, not application source — reading them is allowed.
