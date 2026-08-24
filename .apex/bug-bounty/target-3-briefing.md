# Target #3 — Apex briefing (firewall + credential brokering)

HackerOne program: vercel_sandbox. Use only `https://api.vercel.com` sandbox REST routes (`/v2|/v3|/v4/sandboxes*`) plus inbound `*.vercel.run` hosts that `__includeSystemRoutes` or a ports PATCH discloses for **our** sandboxes. Do not hit dashboard, v0, billing, VCR, `openapi.vercel.sh`, or other Vercel APIs. Cap at 5 requests per second. One root cause per finding. Live PoC required. Stop at confirmation. Do not dump customer data. Do not encode/obfuscate URLs to dodge the scope guard. Prefer this briefing over `web_search`.

This engagement has **two Vercel users**. Session HTTP headers inject **Account A** (victim). Account B’s PAT is in `.apex/bug-bounty/local/headers-b.json` — copy the `Authorization` value into `http_request` headers for attacker-principal tests. **Do not print either token.**

A 200 from a token on an object it owns is **not** a vulnerability. Same-team Account A project-A vs project-A2 404s are expected-secure. File only if (1) policy said X and the guest actually reached Y, or (2) a brokered/OIDC secret left the intended identity, or (3) Account B replaced/inherited Account A’s network policy (or the reverse). Unauthenticated hits to a **published user port** that return `SANDBOX_NOT_LISTENING` are not findings.

Target #1 (control-plane session/snapshot/fork/interactive IDOR) is **exhausted**. Do not re-prove B→A 403/404 on cmd/fs/interactive/snapshot. Spend this run on **host-side firewall enforcement vs API readback**, **session replace vs named-sandbox persist**, **cross-account network-policy IDOR**, **owned `forwardURL` / OIDC identity**, and **deny-all inheritance across fork/resume**.

## Dual loop (this is how you test)

1. **Mutate policy** via `http_request` to `api.vercel.com`: create-time `networkPolicy`, `POST /v2/sandboxes/sessions/{sessionId}/network-policy` (full replace of the **running session**), or PATCH the named sandbox (supposed to apply to **current and future** sessions).
2. **Observe enforcement** from **inside our sandbox** with `POST /v2/sandboxes/sessions/{sessionId}/cmd` — not from the Apex host. Body is `{"command":"/usr/bin/curl","args":["-sS","--max-time","8","https://example.com"],"wait":true,"logs":true}`. `command` is a **binary path**, not a shell string. `wait:true` + `logs:true` returns NDJSON; `wait:false` must omit `logs`.
3. **Account B** tests must override `Authorization` from `.apex/bug-bounty/local/headers-b.json`. Python urllib needs `allow_unprotected: true` so Account A is not auto-injected. If you omit the headers argument, you are still Account A.
4. `*.vercel.run` is in session scope this run. Call it with `http_request` directly. Unauth tests still need an Authorization override, because the PAT is injected for in-scope hosts.
5. **Owned observer only.** Never webhook.site / requestbin / other third-party sinks. Third-party sites reflecting brokered headers are unpaid.

## Hard constraints (learned — do not fight them)

- Named sandboxes are PATCHed to `timeout: 2700000` (Hobby max). **First action in every worker:** `GET …?resume=true` on **fw-observer** if its listener is down. **Do not `POST /stop` on `fw-victim`** while siblings are observing. Do not stop `fw-observer` either. If you must stop something, use `attacker-probe` / `attacker-b`.
- If a live session is still 5 minutes (`timeout: 300000`), stop **that** sandbox only if it is not `fw-victim` / `fw-observer`, then resume so the new session inherits 45 minutes. `POST …/extend-timeout` `{"duration":60000}` works only up to the live session's remaining max — do not send 2700000 against a 5-minute session.
- Do not `POST /snapshot` (it stops the session). Do not `POST /network-policy` with `{}` (full replace to `mode=custom` / empty custom = deny-all; **documented, not a finding**). Do not DELETE. Do not PATCH port 26661 (system-reserved; rotates the session).
- Session IDs rotate on resume. Look them up; do not trust IDs in this file.
- Do not print tokens. `{host}` in Python format strings trips the scope guard — use concatenation or `%` formatting.
- ≤5 rps.

## Live objects (IDs rotate)

Account A (victim, session default PAT) — user `Ini8xEkCg605GgClB8J4O1yT` / `yuvaa-7607`:
- Team: `team_7jHS1s2yIuXVrcsI74DRljdn` (slug `test11-ad11`)
- Victim project: `prj_WgeFvOlmQM1BbtJTEHdQKySMzvC5` (`sbx-h1-victim`)
- Same-team second project: `prj_7uASgsVYJvWLTU8aWVtm059LlSoZ` (`sbx-h1-attacker`)
- **Policy-under-test sandbox:** `fw-victim` — created with `networkPolicy.mode=deny-all`, `timeout: 2700000`, persistent. Pre-run session `sbx_AsewtwPvHy29Z3Dt8vQas5lVQz92`. Guest curl to `https://example.com` under deny-all already failed with curl exit 6 (`Could not resolve host`) — that is expected enforcement, not a finding.
- Leave `victim-base` / `attacker-probe` / `fork-same-project` alone unless you need the canary filesystem. Canary `/vercel/SECRET.txt` on `victim-base` = `CANARY-E1DE39E5-3F20-4243-8F71-3B7410EC73F9`.

Account B (attacker, headers-b.json) — user `LWgYUj0PGJ0ncS5cB55mxUmM`:
- Team: `team_LO7V6PmnTOI8i66m8MO6g6yb`
- Project: `prj_fuEcV8s1ISZBg4LncdBK1MfScxb9` (`nextjs-boilerplate1`) — token cannot create additional projects
- Sandbox `attacker-b` (persistent, 45 min). Do not delete.
- **Owned observer:** named sandbox `fw-observer`, published port **8080**. Pre-run session `sbx_m7rMArDBnAdU5g9qY9JS8Ny7kZuI`. Public URL (rotates on resume): `https://sb-2ypsmd08kfks.vercel.run`. Listener echoes request path + headers as `text/plain`. Look up the live URL with `GET /v2/sandboxes/fw-observer?projectId=…&teamId=…` — `routes[].url` for port 8080. If the listener is dead (`SANDBOX_NOT_LISTENING`), resume and re-start `/usr/bin/python3 /tmp/observer.py` with `wait:false` (omit `logs`). Do **not** use this URL as a third-party bin substitute for anything other than `forwardURL` / transform tests.

LIST uses query `project=` (id). Named GET uses `projectId=`. Session subresources live under `/v2/sandboxes/sessions/{sbx_id}/…`.

## Documented non-findings (do not “discover” these)

- CIDR allow bypasses SNI / credential brokering / `forwardURL`.
- CIDR-only policies leave the default DNS resolver open (data over DNS).
- Catch-all `*` lets domain-less traffic (TLS without SNI, SSH, etc.) through unmodified.
- Plaintext HTTP and plaintext Postgres are not domain-filterable; use IP ranges.
- Empty custom policy (`{}`, `{ allow: {} }`, `{ subnets: {} }`, deny-only subnets) behaves as `deny-all`.
- `POST /network-policy` is a **full replace**. Sending `{}` is operator error, not a bypass.
- Third-party sites reflecting brokered headers / OIDC.
- SDK-only bugs (client sending the wrong body). The **server** accepting a confused identity is in scope.
- Blocking *more* traffic than configured (fail-closed) is not a finding. Extra **egress** or **secret injection** is.
- `getOrCreate` ignoring create parameters when the named sandbox already exists.
- Target #1 results: B cannot mint A’s interactive token; empty auth + A-minted `?token=` on TTY is intended capability-token semantics; B→A session/fs/cmd 403 (A teamId) / 404 otherwise.

## API facts (Target #3 run `ses_fe432ca99ffef9ybjXtCKOJkwm` — do not rediscover)

- Dual loop works. `deny-all` → in-guest `/usr/bin/curl https://example.com` exit 6 (DNS). Live `{mode:allow-all}` or `{mode:custom, allowedDomains:["example.com"]}` takes effect **without restart**; GET readback matches guest reachability. Disallowed hosts stay blocked. Restore with session `{mode:deny-all}`.
- Live control plane **rejects** the docs `{allow:[{host, forwardURL}]}` array-of-objects dialect and `{allow, subnets}` on session POST / named PATCH / v2/v4 create / v3 fork (`additional property allow`). `injectionRules` only accepts `{domain, headers}` (transform-style headers), **not** `forwardURL`. Direct guest curls to `fw-observer` without an L7 forward rule did not include `vercel-sandbox-oidc-token` (inbound published port, expected). **This was not a server rejection of forwarding.** The live custom dialect is `{mode:"custom", allowedDomains, injectionRules, forwardRules}`. Target #3 never sent top-level `forwardRules`. **OIDC `aud` / claim binding is Target #6, not closed.**
- Session `POST /network-policy` is the live full replace **and** writes named persist. Named `PATCH` updates persist only; the running session stays at its last session-POST policy. GET reports the split honestly. Resume/fork after named `deny-all` boot `deny-all` (fail-closed). Judge rejected “PATCH does not lock the current session” as documented persist-vs-session semantics (SDK `sandbox.update()` vs REST PATCH).
- Cross-account `POST /network-policy`: B→A and A→B never 200. Victim `teamId` → 403 Not authorized; other contexts → 404 Vercel Sandbox not found.
- Residual matchers/first-wins/SNI vs dest-IP/wildcards/races: no extra egress, no secret injection. Interceptor uses SNI. Wildcards are segment-scoped.

## Policy API shape

Bodies that **work today** on `POST /v2/sandboxes/sessions/{sessionId}/network-policy`:

- `{ "mode": "allow-all" | "deny-all" | "custom", "allowedDomains": [...], "allowedCIDRs": [...], "deniedCIDRs": [...], "injectionRules": [{ "domain": "…", "headers": {…} }] }`

Docs also describe `{ "allow": [ { "host": "example.com", "forwardURL": "https://…" } ], "subnets": {…} }`. That shape was **400 additional property** on this account during Target #3 — do not treat a 400 as a finding, and do not spend later hunts retrying **that** dialect.

The untested L7 body is top-level `forwardRules: [{ domain, forwardURL }]` on `{mode:"custom"}` (and, if that 400s, the SDK record form `{ allow: { "<host>": [{ forwardURL }] } }`). See Target #6. A rule may have **either** `transform` **or** `forwardURL`, not both. `forwardURL` must be an HTTP/1.1 URL with **no query string or fragment**. Forwarded requests add `vercel-forwarded-host/scheme/port/path` and `vercel-sandbox-oidc-token`. OIDC `aud` **must equal** that `forwardURL`. Claims `team_id`, `project_id`, `sandbox_id`, `sandbox_name` must bind to **this** sandbox. Account B’s observer must not receive Account A’s token unless the policy on A explicitly forwarded to B’s URL.

Creation-time `networkPolicy` must be on before guest code runs. Live updates must take effect **without restart**. After stop/resume/fork, enforcement and GET readback must still agree.

## What counts as a finding

- Guest reached a destination the configured policy forbids (example: deny-all or allow-list without `example.com`, yet curl to example.com succeeds).
- After live `allow-all` / allow `example.com`, traffic still denied **and** readback says allow — only if that is a **readback lie** that would cause an operator to believe the VM is locked when it is open, or vice versa with extra egress. Fail-closed (blocks more) without extra egress is not a finding.
- Session `POST /network-policy` vs named-sandbox PATCH disagree such that a **future** session boots `allow-all` after the operator set `deny-all` on the named object (unauthorized egress).
- Account B `POST /network-policy` on Account A’s `sessionId` returns **200** and changes A’s egress (or the reverse). 403/404 is expected-secure.
- `forwardURL` to `fw-observer` mints OIDC whose `aud` is **not** that observer URL, or whose `team_id`/`project_id`/`sandbox_id` belong to a different sandbox, or B receives A’s token on a request B did not configure A to send.
- Fork/resume of a `deny-all` source boots with `allow-all` (or otherwise extra egress).

Matcher / first-wins residual: only file if they cause **extra egress** or **secret injection**, not if they block more.

## Objectives for this run (one worker each)

1. Convergence: `fw-victim` deny-all → cmd to example.com fails → live allow-all or allow `example.com` → cmd succeeds **without** restart. Then stop/resume/fork **copies** (not the shared `fw-victim` if siblings still need it — prefer fork to a throwaway name on project A) and re-check enforcement vs readback.
2. Replace vs persist: session `POST /network-policy` vs named-sandbox update; after resume, which policy is live. Empty `{}` is known-dangerous replace, not a finding.
3. Cross-account policy IDOR: B `POST /network-policy` on A’s `fw-victim` sessionId (expect 403/404). Reverse A on B `fw-observer` / `attacker-b`. Finding = 200 that changes the other tenant’s egress. Stop at confirmation.
4. Owned L7 identity: `forwardURL` from `fw-victim` **only** to the live `fw-observer` `*.vercel.run` URL. Check OIDC `aud` equals that URL and claims match this sandbox’s team/project/id. B must not receive A’s token except as the forwarded request under test. Decode the JWT payload (base64url) on the observer echo; do not print the raw token in findings — redact, keep `aud` / `team_id` / `project_id` / `sandbox_id`.
5. Inheritance: fork/resume must not boot `allow-all` when source was `deny-all`. `getOrCreate` ignoring create params is documented, not a finding.

Chain worker: residual matchers / first-wins **only** if extra egress or secret injection.

Read also: `.apex/bug-bounty/scope.md`, `.apex/bug-bounty/engagement.md`, `.apex/threat-models/2026-08-19-vercel-sandbox-firewall.md`. Those markdown files are engagement docs, not application source — reading them is allowed.
