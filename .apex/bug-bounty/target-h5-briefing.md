# H5 — Apex briefing (OIDC `aud` after `normalizeForwardUrl` path strip)

HackerOne: vercel_sandbox. Only `https://api.vercel.com` `/v2|/v3|/v4/sandboxes*` plus owned `*.vercel.run`. Cap 5 rps. Stop at confirmation. Do not print tokens. Python urllib needs `allow_unprotected: true`. `{host}` in Python format strings trips the scope guard.

**One hypothesis. One worker. No exploratory spawn. Stop at the kill-gate.**

Absolute path: `/Users/yuvaneshanand/Documents/Github/apex-bug-bounty-auto-triage-patch/.apex/bug-bounty/target-h5-briefing.md`

## Hypothesis

Vendored `proxy.js` `normalizeForwardUrl` strips `vercel-forwarded-path` as a **suffix** of the current URL before computing `aud` (`origin`, or `origin+pathname` if not `/`). If the **broker** mints `aud` from a different construction than that rule — or a guest path that is a suffix of the configured `forwardURL` path shrinks `aud` to a prefix origin — a token minted for path P can verify at path P′.

This is a **server mint** bug. Decode JWT **payload only**. Redact the raw token. Keep `aud` / `iss` / `team_id` / `project_id` / `sandbox_id` / `sandbox_name`.

## Kill-gate (stop if all hold)

- For each accepted `forwardURL`, every minted token’s `aud` equals that configured `forwardURL` (origin, or origin+pathname with no trailing slash except when the configured URL itself ends with `/` — Target #6: trailing-slash `forwardURL` keeps `/` in `aud`)
- Guest path does **not** change `aud`
- Matcher miss (`/other`) does **not** mint / does **not** land on the observer with a token
- Claims bind to **h3-src-a** (Account A team/project/session), not the observer

## Do not re-prove (Target #6)

- Happy-path `{allow:{"example.com":[{forwardURL: observer origin}]}}` → `aud` = observer origin, claims = source sandbox. **Intended. Do not file.**
- `forwardURL` origin+`/callback` → `aud` = that exact URL; guest path does not change `aud`
- Matcher `path.startsWith /oidc-probe`: match forwards; `/other` and `/` hit example.com without OIDC
- B POST allow-map on A session: 403/404
- Direct guest curl to observer **without** a forward rule has no OIDC (inbound publish)

## Live objects (re-GET; resume; do not `POST /stop` or snapshot)

Account A: team `team_7jHS1s2yIuXVrcsI74DRljdn`, project `prj_WgeFvOlmQM1BbtJTEHdQKySMzvC5`.

Throwaways (not `fw-victim`):

- Source `h3-src-a` last session `sbx_CJ2wENwidC9YzSyD5zSU943qcM7S`
- Observer `h3-obs-a` last session `sbx_H1pzP1sskjEth6O2EJjoCer0KgWs`, URL `https://sb-5rarngbmyb2q.vercel.run`

Session headers = Account A. Restore `{mode:deny-all}` on `h3-src-a` when done.

## Confirmed wire

```json
{ "allow": { "example.com": [{ "forwardURL": "https://sb-5rarngbmyb2q.vercel.run/callback" }] } }
```

Guest: `POST …/cmd` `{"command":"/usr/bin/curl","args":["-sS","--max-time","12","-D-","https://example.com/…"],"wait":true,"logs":true}`. Observer echoes path + headers. Decode `vercel-sandbox-oidc-token` payload (base64url).

Do not POST top-level `forwardRules` (400). Do not mix leftover arrays (H3). Do not `POST /network-policy` `{}`.

## Objectives (this is the only objective)

1. Resume `h3-obs-a` / `h3-src-a`. Observer echo on :8080.
2. **Suffix-strip matrix** (the Target #6 gap): set `forwardURL` to observer+`/callback`. Guest curl:
   - `https://example.com/callback` (exact)
   - `https://example.com/x/callback` (path **ends with** configured path)
   - `https://example.com/callback/extra`
   - `https://example.com/`
   Decode `aud` each time a token appears. Finding = `aud` ≠ `https://sb-5rarngbmyb2q.vercel.run/callback` (or the live observer origin+`/callback`).
3. Optional one-shot: `forwardURL` observer+`/a/b` and guest `/a/b` vs `/x/a/b`. Same rule.
4. Matcher miss: allow-map with `match.path.startsWith` `/callback` (or `/oidc-probe`). Curl `/other` — no token on observer.
5. Restore `{mode:deny-all}`. Call `response`. Do **not** spawn a second worker.

## Finding vs not

- **Finding:** minted `aud` is not the configured `forwardURL` origin(+path); claims belong to the observer or another sandbox; token on a matcher-miss / unconfigured path.
- **Not a finding:** Target #6 happy-path origin/`/callback`/trailing-slash with matching `aud`; intended A→observer forward with A’s claims; extra blocking.

Read also: `.apex/bug-bounty/whitebox-hypotheses.md`, `.apex/bug-bounty/target-6-briefing.md`.
