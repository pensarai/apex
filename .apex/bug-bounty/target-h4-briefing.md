# H4 — Apex briefing (`headerNames` secret-name binding)

HackerOne: vercel_sandbox. Only `https://api.vercel.com` `/v2|/v3|/v4/sandboxes*` plus owned `*.vercel.run`. Cap 5 rps. Stop at confirmation. Do not print tokens. Python urllib needs `allow_unprotected: true`. `{host}` in Python format strings trips the scope guard.

**One hypothesis. One worker. No exploratory spawn. Stop at the kill-gate.**

Absolute path: `/Users/yuvaneshanand/Documents/Github/apex-bug-bounty-auto-triage-patch/.apex/bug-bounty/target-h4-briefing.md`

## Hypothesis

`InjectionRuleValidator` accepts `headerNames: string[]` (see vendored `@vercel/sandbox` 3.1.0 `validators.js`). Target #10 POST used `headers: {name: value}` and readback became `headerNames: [name]` with values stripped. If a **request** `headerNames` list (no values) is resolved against a **global or cross-tenant** secret store, A can inject a header B stored.

## Kill-gate (stop if all of these hold)

- Unknown `headerNames` entry → 400/403, or 200 with **no** extra header on the observer
- A `headerNames` that only B stored → 400/403, or 200 with **no** B canary on A’s guest curl
- Observed inject is only a name+value **A** just wrote via `headers: {…}` on this session

## Live objects (re-GET; resume; do not `POST /stop` or snapshot)

Account A: team `team_7jHS1s2yIuXVrcsI74DRljdn`, project `prj_WgeFvOlmQM1BbtJTEHdQKySMzvC5`.

Throwaways from H3 (prefer these, not `fw-victim`):

- Source `h3-src-a` last session `sbx_CJ2wENwidC9YzSyD5zSU943qcM7S`
- Observer `h3-obs-a` last session `sbx_H1pzP1sskjEth6O2EJjoCer0KgWs`, URL `https://sb-5rarngbmyb2q.vercel.run`

Account B: team `team_LO7V6PmnTOI8i66m8MO6g6yb`, project `prj_fuEcV8s1ISZBg4LncdBK1MfScxb9`. PAT in `.apex/bug-bounty/local/headers-b.json`.

Session headers inject Account A. Restore `{mode:deny-all}` on `h3-src-a` when done.

## Confirmed wire (H3 / Target #10 — do not rediscover)

Working inject:

```json
{
  "mode": "custom",
  "allowedDomains": ["sb-5rarngbmyb2q.vercel.run"],
  "injectionRules": [{
    "domain": "sb-5rarngbmyb2q.vercel.run",
    "headers": { "x-canary-h4": "CANARY-H4-A" }
  }]
}
```

Readback: `headerNames: ["x-canary-h4"]` (values redacted). Happy-path echo of `CANARY-H4-A` on guest curl to the observer is **intended**. Do not file.

**Request `headerNames` is rejected** (pre-flight 24 Aug 2026): `{injectionRules:[{domain, headerNames:[…]}]}` → 400 `injectionRules[0] should NOT have additional property headerNames`. `headerNames` is **readback-only**, same class as `forwardRules`. Confirm once; if still 400, the kill-gate is met. Do not loop.

Do not POST `forwardRules`. Do not mix allow-map + leftover arrays (H3: 400). Do not `POST /network-policy` `{}`.

## Objectives (this is the only objective)

1. Resume `h3-obs-a` / `h3-src-a` (or re-GET routes). Ensure observer echo is listening (python on :8080).
2. Control: POST the working `headers` dict with `CANARY-H4-A`. Guest curl observer — canary present (intended).
3. POST `injectionRules` with **only** `headerNames: ["x-canary-h4-unknown"]` (no `headers` map). Expect 400/403, or 200 and observer has **no** unknown/platform secret.
4. On a B session, store `headers: {"x-canary-h4-b":"CANARY-H4-B"}` then POST on **A’s** `h3-src-a` `headerNames: ["x-canary-h4-b"]`. Expect 400/403, or 200 and observer has **no** `CANARY-H4-B`.
5. Restore `{mode:deny-all}`. Call `response`. Do **not** spawn a second worker.

## Finding vs not

- **Finding:** observer (or any host) receives a secret A did not just set on this session — especially `CANARY-H4-B` or a platform/broker header A did not name in `headers: {…}`.
- **Not a finding:** 400/403; 200 that injects only `CANARY-H4-A` after A set it; readback redaction; H3 400s; Target #10 matcher/wrong-host.

Read also: `.apex/bug-bounty/whitebox-hypotheses.md`, `.apex/bug-bounty/scope.md`.
