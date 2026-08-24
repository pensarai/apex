# H9 — Apex briefing (`sudo` / `env` on cmd)

HackerOne: vercel_sandbox. Only `https://api.vercel.com` `/v2|/v3|/v4/sandboxes*`. Cap 5 rps. Stop at confirmation. Do not print tokens. Python urllib needs `allow_unprotected: true`. `{host}` in Python format strings trips the scope guard.

**One hypothesis. One worker. No exploratory spawn. Stop at the kill-gate.**

Absolute path: `/Users/yuvaneshanand/Documents/Github/apex-bug-bounty-auto-triage-patch/.apex/bug-bounty/target-h9-briefing.md`

## Hypothesis

Vendored `runCommand` sends `sudo` and `env` on `POST /v2/sandboxes/sessions/{sbx_id}/cmd` (`api-client.js`). If `sudo: true` (or an `env` override) lets the command reach **EC2 IMDS/MMDS**, a **host** path, or **another tenant’s** canary, that is Target #5 with a new cmd flag. Target #5 already fail-closed those paths **without** `sudo`/`env`.

`sudo: true` that only becomes uid 0 **inside this guest** is unpaid DX. Do not invent exploit payloads, custom kernels, or VMM patches.

## Kill-gate (stop if all hold)

- `sudo: true` `/usr/bin/id` stays in the guest (uid 0 in-guest is **not** a finding)
- `sudo: true` + short curl of link-local/metadata on **allow-all** `host-probe` is timeout / 404 / empty / refused — **no** host instance or IAM material
- No host filesystem path; no other-tenant canary
- `env` is applied in-guest only (echo/printenv of a dummy key)

## Do not re-prove

- Target #5 IMDS/host inventory **without** `sudo`/`env`
- vsock 2050 / container→guest / virtio inventory
- H1–H7; H8 quota
- Do **not** snapshot, `POST /stop`, or DELETE. Do **not** create sandboxes (Hobby snapshot quota is full)

## Live objects (re-GET; resume; do not snapshot)

Account A: team `team_7jHS1s2yIuXVrcsI74DRljdn`, project `prj_WgeFvOlmQM1BbtJTEHdQKySMzvC5`. Session headers = A.

- `h3-src-a` — deny-all. Last known session `sbx_QJIL6QMhVVAenQ9oyVBlO4mcg52t` (re-GET). For `id` / `env` only.
- `host-probe` — allow-all. For `sudo` + link-local only. Do not change its policy.

Account B: team `team_LO7V6PmnTOI8i66m8MO6g6yb`, project `prj_fuEcV8s1ISZBg4LncdBK1MfScxb9`. Do **not** resume `inbound-b` unless a host/IMDS hit appears.

## Confirmed wire (SDK)

```json
{
  "command": "/usr/bin/id",
  "args": [],
  "sudo": true,
  "wait": true,
  "logs": true
}
```

```json
{
  "command": "/usr/bin/curl",
  "args": ["-sS", "--max-time", "5", "-D-", "http://169.254.169.254/latest/meta-data/"],
  "sudo": true,
  "wait": true,
  "logs": true
}
```

`command` is a **binary path**. `{host}` in Python format strings trips the scope guard. Do not `POST /network-policy` `{}`.

## Objectives (this is the only objective)

1. Resume `h3-src-a`. POST `/usr/bin/id` without sudo, then with `"sudo": true`. Record uids. Guest root is unpaid.
2. One `env` check on `h3-src-a`: `"env": {"H9_CANARY": "CANARY-H9-ENV"}` and `/usr/bin/printenv` `H9_CANARY`. Expect the value in-guest. Finding = host/other-tenant content in the env dump.
3. Resume `host-probe`. `sudo: true` curl `http://169.254.169.254/latest/meta-data/` (`--max-time` 5). Optional one-shot `http://169.254.169.254/latest/meta-data/iam/security-credentials/` and MMDS `http://169.254.169.254/latest/meta-data/` is enough — do not fuzz. Finding = host instance/IAM JSON. Timeout/404/refused = kill-gate.
4. If and only if step 3 returns host identity: one `cat` of a suspected host path or compare to B. Otherwise **stop**.
5. Leave policies as found. Do not snapshot. Call `response`. Do **not** spawn a second worker.

## Finding vs not

- **Finding:** host IMDS/MMDS identity, host filesystem, or another tenant’s canary via `sudo`/`env`.
- **Not a finding:** in-guest uid 0; env echo; IMDS refused (Target #5); virtio/Firecracker guest inventory; vsock 2050.

Read also: `.apex/bug-bounty/whitebox-hypotheses.md`, `.apex/bug-bounty/target-5-briefing.md`.
