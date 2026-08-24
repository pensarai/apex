# Target #6 — Apex briefing (forwardRules L7 + OIDC identity)

HackerOne program: vercel_sandbox. Use only `https://api.vercel.com` sandbox REST routes (`/v2|/v3|/v4/sandboxes*`) plus inbound `*.vercel.run` hosts disclosed for **our** sandboxes. Do not hit dashboard, v0, billing, VCR, `openapi.vercel.sh`, or other Vercel APIs. Cap at 5 requests per second. One root cause per finding. Live PoC required. Stop at confirmation. Do not dump customer data. Do not encode/obfuscate URLs to dodge the scope guard. Prefer this briefing over `web_search`.

This engagement has **two Vercel users**. Session HTTP headers inject **Account A** (victim). Account B’s PAT is in `.apex/bug-bounty/local/headers-b.json` — copy the `Authorization` value into `http_request` headers for attacker-principal tests. **Do not print either token.** Python urllib needs `allow_unprotected: true`.

Targets #1, #3 (enforcement / persist / policy IDOR), #4, and #5 are **exhausted**. Do **not** re-prove deny-all DNS blocks, session-vs-named persist, or B→A 403/404 on `POST /network-policy`. This hunt exists because Target #3 **never sent** the live `forwardRules` body, then closed OIDC as “server rejects forwardURL.” That was a false negative.

## Dual loop

1. **Mutate** via `http_request` to `api.vercel.com`: `POST /v2/sandboxes/sessions/{sessionId}/network-policy` on **fw-victim** using the **SDK allow-map** body below. Look up the live session id; do not trust stale IDs.
2. **Observe L7 from inside fw-victim** with `POST /v2/sandboxes/sessions/{sessionId}/cmd`: `{"command":"/usr/bin/curl","args":["-sS","--max-time","12","-D-","https://example.com/oidc-probe"],"wait":true,"logs":true}`. `command` is a **binary path**. `wait:true` + `logs:true` returns NDJSON.
3. **Observe identity on the owned sink** `fw-observer` (Account B, published port 8080). The listener echoes request path + headers as `text/plain`. Look up `GET /v2/sandboxes/fw-observer?projectId=…&teamId=…` — `routes[].url` for port 8080. If `SANDBOX_NOT_LISTENING`, resume and start `/usr/bin/python3 /tmp/observer.py` with `wait:false` (omit `logs`).
4. Account B tests: Authorization from `.apex/bug-bounty/local/headers-b.json`. If you omit headers, you are still Account A.
5. **Owned observer only.** Never webhook.site / requestbin. Third-party reflection of brokered headers is unpaid.

## Correct wire shape (confirmed live 20 Aug 2026 — do not rediscover)

**Request** (session `POST /network-policy`) that **works**:

```json
{
  "allow": {
    "example.com": [{ "forwardURL": "https://<live-fw-observer-origin>" }]
  }
}
```

GET/readback then shows `{mode:"custom", allowedDomains:["example.com"], forwardRules:[{domain:"example.com", forwardURL:"https://…"}]}`. `forwardRules` is a **response** field.

**Do not send** `{mode:"custom", forwardRules:[…]}` on POST — live 400 `should NOT have additional property forwardRules`. Do **not** retry `{ "allow": [{ "host": "…", "forwardURL": "…" }] }` (Target #3 400). Do **not** put `forwardURL` inside `injectionRules`. `transform` and `forwardURL` cannot share a rule.

`<live-fw-observer-origin>` is the origin of the live `fw-observer` URL (no query, no fragment). Pre-run: `https://sb-2ypsmd08kfks.vercel.run` — look it up; it can rotate.

Optional matcher on a forward rule:

```json
{ "domain": "example.com", "forwardURL": "https://<observer>", "match": { "path": { "startsWith": "/oidc-probe" }, "method": ["GET"] } }
```

Intended binding (from `@vercel/sandbox` `proxy.ts`): forwarded requests add `vercel-forwarded-host/scheme/port/path` and `vercel-sandbox-oidc-token`. Verify JWT against `https://oidc.vercel.com` JWKS. `aud` **must equal** the `forwardURL` origin, plus pathname if the forwardURL is not `/`. Claims `team_id`, `project_id`, `sandbox_id`, `sandbox_name` must bind to **fw-victim** (Account A), not `fw-observer` (Account B), not a sibling sandbox.

Decode the JWT **payload** (base64url) on the observer echo. **Do not print the raw token** in findings — redact, keep `aud` / `iss` / `team_id` / `project_id` / `sandbox_id` / `sandbox_name`.

## Hard constraints

- Named sandboxes are `timeout: 2700000`. **First action:** `GET …?resume=true` on `fw-victim` (Account A) and `fw-observer` (Account B). **Do not `POST /stop` on either** while siblings need them. Throwaways only for stop/resume experiments.
- Do not `POST /snapshot`. Do not `POST /network-policy` with `{}`. Do not DELETE keep-list sandboxes. Do not PATCH port 26661.
- Restore `fw-victim` to `{ "mode": "deny-all" }` when done. ≤5 rps. `{host}` in Python format strings trips the scope guard.

## Live objects (IDs and URLs rotate)

Account A (victim, session default PAT) — user `Ini8xEkCg605GgClB8J4O1yT` / `yuvaa-7607`:
- Team: `team_7jHS1s2yIuXVrcsI74DRljdn` (slug `test11-ad11`)
- Victim project: `prj_WgeFvOlmQM1BbtJTEHdQKySMzvC5` (`sbx-h1-victim`)
- Same-team second project: `prj_7uASgsVYJvWLTU8aWVtm059LlSoZ` (`sbx-h1-attacker`)
- **Policy-under-test:** `fw-victim`. Live session `sbx_HwGX7AB4VY08tobU3bQxm38q4ntY` (timeout 2700000). Re-GET before use. Canary `/vercel/SECRET.txt` on `victim-base` = `CANARY-E1DE39E5-3F20-4243-8F71-3B7410EC73F9` (not this hunt).

Account B (attacker, headers-b.json) — user `LWgYUj0PGJ0ncS5cB55mxUmM`:
- Team: `team_LO7V6PmnTOI8i66m8MO6g6yb`
- Project: `prj_fuEcV8s1ISZBg4LncdBK1MfScxb9` (`nextjs-boilerplate1`)
- **Owned observer:** `fw-observer`, published port **8080**. Live session `sbx_mECf5RI9mJtP2nCAsTpjDrv9VNzs`, URL `https://sb-2ypsmd08kfks.vercel.run`. Listener `/tmp/observer.py` already started (echoes path + headers). If `SANDBOX_NOT_LISTENING`, resume and re-start it.

LIST uses `project=`. Named GET uses `projectId=`. Session policy is `POST /v2/sandboxes/sessions/{sbx_id}/network-policy`.

## API facts (Target #6 hybrid probe 20 Aug 2026 — do not rediscover)

- **Request** that works: `POST …/network-policy` `{"allow":{"example.com":[{"forwardURL":"https://<observer-origin>"}]}}`. Readback: `{mode:"custom", allowedDomains:["example.com"], forwardRules:[{domain, forwardURL}]}`.
- POST `{mode:"custom", forwardRules:[…]}` → 400 additional property `forwardRules` (response-only).
- Happy-path mint: `aud` = observer origin, `iss` = `https://oidc.vercel.com/<Account-A-team>`, claims = fw-victim. Intended.
- `forwardURL` origin+`/callback` → `aud` = that exact URL (guest path does not change `aud`). Trailing-slash `forwardURL` → `aud` includes `/`. Claims still fw-victim.
- Matcher `path.startsWith /oidc-probe` + GET: matched path forwards+mints; `/other` and `/` hit example.com **without** OIDC (no extra injection).
- Domain key = observer host, `forwardURL` = observer: still mints **A’s** claims, not B’s.
- B POST allow-map on A session: A `teamId` → 403 Not authorized; B `teamId` or omitted → 404 Vercel Sandbox not found.
- Apex residual session `ses_fe0754fd6ffePm0fN4JII5Ww5s` never left recon (looked for the briefing under `~/.pensar/sessions/…` instead of the repo). The hybrid probe above is the source of truth for this hunt.

Restore `fw-victim` to `{mode:deny-all}` after tests. Live ids this probe: fw-victim `sbx_HwGX7AB4VY08tobU3bQxm38q4ntY`, fw-observer `sbx_mECf5RI9mJtP2nCAsTpjDrv9VNzs`, `https://sb-2ypsmd08kfks.vercel.run`.

## Documented non-findings (do not “discover” these)

- Target #3: deny/allow/custom enforcement matches GET readback; live update without restart; session POST writes persist; named PATCH persist-only; B→A and A→B `POST /network-policy` is 403 (victim teamId) / 404 otherwise; empty `{}` = deny-all; `{allow:[{host,forwardURL}]}` 400; POST `{mode, forwardRules}` 400 additional property.
- **Happy-path mint (do not file):** SDK `{allow:{"example.com":[{forwardURL: observer origin}]}}` → guest curl `https://example.com/oidc-probe` returns observer echo with `Vercel-Forwarded-Host: example.com`, `Vercel-Forwarded-Path: /oidc-probe`, and OIDC `aud=https://sb-2ypsmd08kfks.vercel.run`, `iss=https://oidc.vercel.com/team_7jHS1s2yIuXVrcsI74DRljdn`, `team_id`/`project_id`/`sandbox_id`/`sandbox_name` = fw-victim (Account A). That is intended.
- Direct guest curl to `fw-observer` **without** an allow-map forward rule does **not** include `vercel-sandbox-oidc-token` (inbound published port, not L7 intercept).
- CIDR allow bypasses SNI / brokering; CIDR-only leaves DNS open; catch-all `*` passes domain-less traffic; plaintext HTTP not domain-filterable.
- Third-party sites reflecting brokered headers / OIDC. SDK-only bugs. Fail-closed (blocks more) without extra egress or a confused token.
- Account A **explicitly** forwarding to Account B’s observer, and B’s observer receiving A’s OIDC **with correct `aud` and A’s claims**, is the intended proxy. That is **not** a finding.

## What counts as a finding

- `forwardRules` accepted **and** the observer receives `vercel-sandbox-oidc-token` whose `aud` is **not** the configured `forwardURL` origin(+path).
- Claims `team_id` / `project_id` / `sandbox_id` / `sandbox_name` belong to a **different** sandbox, project, or team than `fw-victim`.
- Observer receives A’s OIDC (or transform secrets) on a request **A did not configure** to forward there (confused deputy / extra injection).
- `iss` is not `https://oidc.vercel.com/…` for this team, or the token verifies for a different audience than the sink.
- Account B `POST /network-policy` with `forwardRules` on A’s session returns **200** and mints A’s identity toward B (Target #3 was 403/404 on policy replace — only file if `forwardRules` changes that).
- Guest reaches a host the policy forbids **because** a forward rule was applied to the wrong domain (extra egress or secret injection).

## Objectives (focused — do not 5-worker sweep)

1. **`aud` mismatch matrix:** apply the confirmed SDK allow-map on `fw-victim` with `forwardURL` variants: observer origin, origin+`/callback`, origin with trailing slash. Guest curl `/oidc-probe` and `/`. Decode payload. Finding = minted `aud` does not match the configured forwardURL (origin+path rule in `proxy.ts`). Happy-path origin+correct aud is already proven — do not file it. Restore deny-all after each replace.
2. **Claim / tenant binding:** token claims must equal live `fw-victim` id and Account A team/project. Finding = observer’s team/project/sandbox, a sibling (`victim-base` / `host-probe`), or Account B’s ids appear as claims. Decode payload only; redact raw JWT.
3. **Cross-account forward:** (a) B tries SDK allow-map `forwardURL` to B’s observer on A’s session (expect 403/404 unless 200+mint — only then file). (b) A sets allow-map to B’s observer (intended) — file only if claims/aud are wrong. (c) A sets the **domain key** to B’s observer host while `forwardURL` is also B — confirm this does not mint a token a proxy would accept as B.
4. **Matcher residual:** allow-map rule with `match.path.startsWith` `/oidc-probe` (and/or GET-only). Curl `/other` — must **not** land on the observer with a token. Extra injection is a finding; extra blocking is not.

Chain: `injectionRules` / transform toward the observer **only** if it injects a secret at a host the rule did not name. Do not re-run Target #3 wildcard/SNI/CIDR. Do not re-prove happy-path mint.

Read also: `.apex/bug-bounty/scope.md`, `.apex/bug-bounty/engagement.md`, `.apex/threat-models/2026-08-20-vercel-sandbox-forward-oidc.md`. Those markdown files are engagement docs, not application source — reading them is allowed.
