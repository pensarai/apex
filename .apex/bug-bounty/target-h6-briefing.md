# H6 — Apex briefing (`match.regex`)

HackerOne: vercel_sandbox. Only `https://api.vercel.com` `/v2|/v3|/v4/sandboxes*` plus owned `*.vercel.run`. Cap 5 rps. Stop at confirmation. Do not print tokens. Python urllib needs `allow_unprotected: true`. `{host}` in Python format strings trips the scope guard.

**One hypothesis. One worker. No exploratory spawn. Stop at the kill-gate.**

Absolute path: `/Users/yuvaneshanand/Documents/Github/apex-bug-bounty-auto-triage-patch/.apex/bug-bounty/target-h6-briefing.md`

## Hypothesis

`RuleMatcherValidator` accepts `path.regex` (also query/header matchers) in vendored `validators.js`. If the L7 proxy compiles that string and an **invalid** regex is treated as `*` — or a valid regex matches more than the intended path — an operator-configured inject/forward attaches to a host/path the rule did not name.

ReDoS that only hangs **this** sandbox is own-sandbox DoS (**unpaid**). Do not pursue ReDoS. Finding only if extra inject/forward is observed, or invalid regex is accepted **and** fires as a wildcard.

## Kill-gate (stop if all hold)

- Invalid regex (`(`, `*`, `[`) → 400, or 200 with **no** extra canary on `/other`
- Valid `^/h6-only$` injects `CANARY-H6-A` on `/h6-only` only
- `/other` and `/` do **not** carry the canary

## Do not re-prove

- Target #10 `path.startsWith` matcher residual (already fail-closed)
- H3 dialect 400s; H4 `headerNames` request 400; H5 `aud` suffix-strip
- Happy-path inject to the named observer host/path (intended)

## Live objects (re-GET; resume; do not `POST /stop` or snapshot)

Account A: team `team_7jHS1s2yIuXVrcsI74DRljdn`, project `prj_WgeFvOlmQM1BbtJTEHdQKySMzvC5`.

- Source `h3-src-a` last session `sbx_CJ2wENwidC9YzSyD5zSU943qcM7S`
- Observer `h3-obs-a` last session `sbx_H1pzP1sskjEth6O2EJjoCer0KgWs`, URL `https://sb-5rarngbmyb2q.vercel.run`

Restore `{mode:deny-all}` on `h3-src-a` when done.

## Confirmed wire (Target #10 / H3)

```json
{
  "mode": "custom",
  "allowedDomains": ["sb-5rarngbmyb2q.vercel.run"],
  "injectionRules": [{
    "domain": "sb-5rarngbmyb2q.vercel.run",
    "headers": { "x-canary-h6": "CANARY-H6-A" },
    "match": { "path": { "regex": "^/h6-only$" } }
  }]
}
```

Guest curl observer `/h6-only` vs `/other`. Do not POST `forwardRules`. Do not `POST /network-policy` `{}`.

## Objectives (this is the only objective)

1. Resume throwaways. Observer echo on :8080.
2. POST the valid `^/h6-only$` rule. Curl `/h6-only` (expect canary — intended). Curl `/other` and `/` (must **not** have `CANARY-H6-A`). Extra inject is a finding.
3. One-shot invalid regex: `match.path.regex` = `(` or `*`. Expect 400. If 200, curl `/other` — canary on `/other` is a finding (wildcard). Stop; do not fuzz ReDoS.
4. Restore `{mode:deny-all}`. Call `response`. Do **not** spawn a second worker.

## Finding vs not

- **Finding:** `CANARY-H6-A` on a path the regex did not name; invalid regex accepted and treated as `*`.
- **Not a finding:** 400 on bad regex; extra blocking; intended inject on `/h6-only`; own-sandbox hang.

Read also: `.apex/bug-bounty/whitebox-hypotheses.md`, `.apex/bug-bounty/target-10-briefing.md`.
