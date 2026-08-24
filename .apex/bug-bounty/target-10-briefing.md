# Target #10 — Apex briefing (L7 transform / injectionRules)

HackerOne program: vercel_sandbox. Sandbox REST (`/v2|/v3|/v4/sandboxes*`) plus owned `*.vercel.run` only. Cap 5 rps. Live PoC. Stop at confirmation. Do not dump customer data. Prefer this briefing over `web_search`.

Session headers = **Account A**. Account B PAT is `.apex/bug-bounty/local/headers-b.json`. **Do not print tokens.** Python urllib needs `allow_unprotected: true`. `{host}` in Python format strings trips the scope guard.

Targets #1, #3 (deny/allow/persist/policy IDOR), #4, #5, #6 (forwardURL/OIDC), #7, #9 are **exhausted**. Do not re-prove 403/404, deny-all DNS, or OIDC `aud`. Target #8 Drives is retired (Hobby 403). This hunt is **header injection**: operator-configured secrets must attach only to the named domain/matcher, never leak to a host the rule did not name.

**Absolute briefing path (Apex cwd is the session dir — read this file by absolute path):** `/Users/yuvaneshanand/Documents/Github/apex-bug-bounty-auto-triage-patch/.apex/bug-bounty/target-10-briefing.md`

## Dual loop

1. **Mutate** `POST /v2/sandboxes/sessions/{sessionId}/network-policy` on **fw-victim**.
2. **Observe** from inside fw-victim: `POST …/cmd` `{"command":"/usr/bin/curl","args":["-sS","--max-time","12","-D-","https://<observer-origin>/transform-probe"],"wait":true,"logs":true}`.
3. **Sink** is owned `fw-observer` (Account B, port 8080). Listener echoes path + headers. Look up live URL. If `SANDBOX_NOT_LISTENING`, resume and `/usr/bin/python3 /tmp/observer.py` with `wait:false` (omit `logs`).
4. Canary secret to inject: `CANARY-TRANSFORM-A` on header `x-canary-broker`. **Owned observer only** — never webhook.site.

## Wire (confirmed live 20 Aug 2026 — do not rediscover)

**Request that works** (legacy custom — unlike `forwardRules`, `injectionRules` **is** a request field):

```json
{
  "mode": "custom",
  "allowedDomains": ["sb-2ypsmd08kfks.vercel.run"],
  "injectionRules": [{
    "domain": "sb-2ypsmd08kfks.vercel.run",
    "headers": { "x-canary-broker": "CANARY-TRANSFORM-A" }
  }]
}
```

Readback strips values: `injectionRules: [{ domain, headerNames: ["x-canary-broker"] }]`.

**Happy-path (do not file):** guest curl `https://sb-2ypsmd08kfks.vercel.run/transform-probe` returns observer echo with `X-Canary-Broker: CANARY-TRANSFORM-A`. Intended.

SDK `{allow:{host:[{transform:[{headers}]}]}}` was not needed. Do **not** POST `forwardRules`. Do not combine transform + forwardURL on one rule. Do not retry `{allow:[{host,…}]}`.

## API facts (Target #10 hybrid probe 20 Aug 2026 — do not rediscover)

- Matcher `path.startsWith /transform-probe` + GET: matched path injects canary; `/other` and `example.com` do **not**.
- Rule domain = observer host: observer gets canary; `example.com` does not.
- Reverse (rule domain = `example.com`): observer does **not** get canary.
- B POST injectionRules on A session: A `teamId` → 403; B `teamId` or omitted → 404. Same as Target #3 policy IDOR.

Apex `ses_fe06feb4affeOfU2Wl4yQ1IGiz` died at Grok capacity during recon. Hybrid probe is the source of truth.

## Live objects (IDs rotate — re-GET)

Account A: team `team_7jHS1s2yIuXVrcsI74DRljdn`, project `prj_WgeFvOlmQM1BbtJTEHdQKySMzvC5`, sandbox **fw-victim**. Last session `sbx_HwGX7AB4VY08tobU3bQxm38q4ntY`. Resume; do not `POST /stop`.

Account B: team `team_LO7V6PmnTOI8i66m8MO6g6yb`, project `prj_fuEcV8s1ISZBg4LncdBK1MfScxb9`, sandbox **fw-observer**. Last session `sbx_mECf5RI9mJtP2nCAsTpjDrv9VNzs`, URL `https://sb-2ypsmd08kfks.vercel.run`. Headers-b.json for B.

## What counts as a finding

- `CANARY-TRANSFORM-A` appears on a request to a **host or path the rule did not name** (extra injection).
- Injected secret is visible on a destination A did not configure (confused deputy).
- Matcher (`path.startsWith`, method, regex) still injects on non-matching requests.
- Wildcard / SNI miss that attaches the secret to the wrong name. Fail-closed (blocks more, no secret) is **not** a finding.
- B `POST` injectionRules on A’s session returns **200** and changes A’s injection (Target #3 was 403/404 on generic policy — only file if this body differs).

Happy-path: A configures inject-to-observer, guest curl observer, echo contains `x-canary-broker: CANARY-TRANSFORM-A`. **Intended. Do not file.**

## Objectives (focused)

1. Accept + happy-path inject toward observer host. Confirm canary on matching curl. Restore deny-all after.
2. Matcher residual: inject only `/transform-probe`. Curl `/other` and `https://example.com/` — must **not** carry the canary. Extra injection is a finding.
3. Wrong-host: rule names observer host; curl `example.com` (if allowed) or a second allowed domain without a transform — no canary. Optional: rule names `example.com` while curling observer — observer must **not** see the canary.
4. Cross-account: B POST SDK/legacy inject on A’s fw-victim session. 403/404 expected. 200 that injects is a finding. Stop at confirmation.

Do not `POST /snapshot`. Do not `POST /network-policy` `{}`. Do not DELETE keep-list. Restore `{mode:deny-all}`. ≤5 rps.

Read also: `/Users/yuvaneshanand/Documents/Github/apex-bug-bounty-auto-triage-patch/.apex/bug-bounty/scope.md`
