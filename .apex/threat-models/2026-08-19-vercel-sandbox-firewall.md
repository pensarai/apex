# Threat model — Target #3: Host-side sandbox firewall and credential brokering

Generated for Apex `/triage` and `pensar pentest --threat-model`. Scope is the Vercel-operated **host-side** sandbox firewall and L7 credential brokering / `forwardURL` identity, plus the control-plane routes that mutate that policy. Not guest Linux namespaces (known unpaid). Not inbound `*.vercel.run` route lifetime (later target). Not Firecracker/VMM (later target).

Target #1 (control-plane session/snapshot/fork/interactive IDOR) is closed for this engagement: two-account 403/404 was fail-closed. Do not reopen it unless a **network-policy** verb on a foreign session returns 200.

## System

Each Firecracker guest’s outbound TCP and DNS is intercepted on the host. Operators set a network policy at create time and can replace it on a live session without restart. Named-sandbox updates are supposed to apply to the current session **and** future sessions after stop/resume. Optional L7 rules terminate TLS for matching domains and either inject headers (`transform`) or reverse-proxy to a researcher-controlled `forwardURL`, minting a Vercel OIDC token whose audience is that URL.

Documented hosts: `api.vercel.com` for policy mutation; enforcement is observed via `POST …/cmd` **inside** an owned guest; L7 identity is observed only on an **owned** published `*.vercel.run` listener (`fw-observer`).

## Trust boundaries

1. **Configured policy ↔ live enforcement.** What create / live-update / GET readback say must match what the guest can actually reach. Creation-time policy must be active before guest code runs.
2. **Session replace ↔ named persist.** `POST /v2/sandboxes/sessions/{id}/network-policy` is a full replace of the **running** session. Named-sandbox PATCH must not silently revert a future session to `allow-all` after the operator set `deny-all`.
3. **Token → tenant policy.** Account B must not replace, read secrets from, or inherit Account A’s policy. Session IDs are unscoped in the public SDK; the **server** must still bind them.
4. **L7 identity ↔ this sandbox.** `transform` / `forwardURL` destination, SNI, matcher, `vercel-forwarded-*`, and OIDC `aud` / `team_id` / `project_id` / `sandbox_id` / `sandbox_name` must bind to the sandbox that originated the request — not a sibling, not the other team.
5. **Fail-closed vs extra egress.** Blocking more than configured is not a break. Extra egress or injecting a secret toward the wrong identity is.

## Assets (Target #3)

| Asset | Attacker goal | Impact if broken |
|---|---|---|
| Host firewall enforcement | Reach the public Internet (or a forbidden host) under `deny-all` / a tight allow-list | High with data/credential exfil; Medium if the boundary is wrong without secrets; Critical only if it becomes cross-tenant read/modify |
| Live policy replace | Flip another tenant’s session from `deny-all` to `allow-all` without owning it | High–Critical (cross-tenant egress / stolen brokering config) |
| Named-sandbox policy persist | Resume/fork boots open after the operator locked the named object | High if unauthorized egress; Medium if readback lies without extra egress |
| `forwardURL` OIDC | Mint a token whose `aud` is a different URL, or whose claims are another sandbox/team | High (credential retrieval via Vercel-side defect) |
| `transform` header injection | Inject operator secrets toward an unintended host / tenant | High |
| Matcher / first-wins ordering | A later restrictive rule is skipped so extra hosts get brokering or egress | High if secrets or extra egress; not a finding if only extra blocking |

## Relevant API shape

- `POST /v4/sandboxes` with `networkPolicy` (must be on before code runs)
- `POST /v2/sandboxes/sessions/{sessionId}/network-policy` — full replacement; empty `{}` → custom/deny-all (documented)
- `PATCH /v2/sandboxes/{name}?projectId=` — named policy for current **and** future sessions
- Observe: `POST /v2/sandboxes/sessions/{sessionId}/cmd` with `command` = binary path (`/usr/bin/curl`) and `args` array
- Observe L7: owned `fw-observer` `https://sb-….vercel.run` (port 8080), never a third-party request bin

Live custom dialect that Target #3 exercised: `{mode, allowedDomains, allowedCIDRs, deniedCIDRs, injectionRules}`. Top-level `forwardRules: [{domain, forwardURL}]` was **not** sent (false-negative close). SDK `{allow: {host: [{forwardURL}]}}` record form was not tried; `{allow:[{host,forwardURL}]}` **was** 400. Target #6 reopens L7/OIDC only. A domain rule may set `transform` **or** `forwardURL`, not both.

## Threats in scope for this hunt

T1. Convergence miss: deny-all on create but guest has Internet; or live update to allow-all that does not take effect without restart **and** readback claims it did (or the reverse: readback deny-all, guest still egresses).
T2. Replace vs persist: session replace does not survive resume while named update does (or vice versa) in a way that yields **unauthorized** egress.
T3. Cross-account policy IDOR: B `POST /network-policy` on A’s sessionId returns 200 and changes A’s egress (or reverse).
T4. OIDC / forwardURL binding miss: `aud` ≠ configured `forwardURL`; claims are another team/project/sandbox; B’s listener receives A’s token without A forwarding to it.
T5. Inheritance: fork/resume of deny-all boots allow-all (or otherwise extra egress).
T6. Matcher residual: first-wins / missing match dimensions cause extra egress or secret injection (not extra blocking).

## Threats explicitly not this hunt

- Documented limitations: CIDR allow bypasses SNI/brokering; CIDR-only leaves DNS open; `*` passes domain-less traffic; plaintext HTTP/Postgres not domain-filterable; empty custom = deny-all
- Third-party reflection of brokered headers
- SDK-only validation bugs
- Guest container escapes, vsock 2050, MMDS, Firecracker virtio
- Inbound `*.vercel.run` unauthenticated published ports / TTY capability tokens (Target #1 closed; Target #4 later)
- Control-plane snapshot/fork BOLA already proven fail-closed
- `getOrCreate` ignoring create params

## Test identities

- Account A: `team_7jHS1s2yIuXVrcsI74DRljdn`, victim project `prj_WgeFvOlmQM1BbtJTEHdQKySMzvC5`, sandbox `fw-victim` (deny-all, 45 min)
- Account B: `team_LO7V6PmnTOI8i66m8MO6g6yb`, project `prj_fuEcV8s1ISZBg4LncdBK1MfScxb9`, observer sandbox `fw-observer` (published port 8080)
- Two owned accounts required for T3. Stop at confirmation. ≤5 qps. No customer data. No exploit PoCs in git.

## Apex alignment

Accepted findings require a live PoC: policy said X, guest reached Y, or a brokered/OIDC secret left the intended identity. Close as out-of-scope: documented firewall quirks, third-party bins, SDK-only issues, known guest primitives. Close as duplicate: same policy-convergence miss on a different verb unless impact is materially new (session replace vs named persist may share one root cause — one report).
