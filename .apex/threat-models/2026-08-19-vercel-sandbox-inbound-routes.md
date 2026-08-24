# Threat model — Target #4: Inbound `*.vercel.run` route lifetime

Generated for Apex `/triage` and `pensar pentest --threat-model`. Scope is the Vercel **edge / sandbox-router** that maps `sb-….vercel.run` to a Firecracker session: published user ports and the system interactive port (26661). Not guest namespaces. Not host-side egress firewall (Target #3). Not control-plane session/snapshot IDOR (Target #1). Not Firecracker/VMM (later).

## System

Each running session may publish up to 15 TCP ports. The control plane returns `routes[]` with `{url, subdomain, port}`. User ports are reachable on `https://sb-….vercel.run` **without** platform auth. The system interactive port is disclosed only with `GET ?__includeSystemRoutes=true` and is consumed as `wss://…/ws/interactive?token=` after `POST /v2/sandboxes/sessions/{sessionId}/interactive`.

`PATCH /v2/sandboxes/{name}` `ports` is a **full replace**: omitted ports must deregister. Fork copies `ports` but must mint **new** hostnames. The CLI documents a sandbox-router cache that can be briefly stale after named-sandbox resume.

Observe only **owned** hosts. Two canaries: Account A `inbound-a` → `CANARY-INBOUND-A`; Account B `inbound-b` → `CANARY-INBOUND-B`.

## Trust boundaries

1. **Hostname → one live session.** A given `sb-…` must map to at most one running session. After stop, unpublish, timeout, or delete, the old URL must fail closed — not keep serving that guest, and not attach to a different tenant’s guest.
2. **Resume / fork → new or rebound route.** Resume may reuse or rotate the hostname; either way it must not serve another sandbox’s canary. Parent and child forks must not share a live hostname that aliases both guests.
3. **Interactive token → that session.** A minted TTY token must not open a different session after stop/resume. Connecting without a current mint must 401.
4. **Published port ≠ TTY.** Unauthenticated HTTP on a user port is intended. Unauthenticated TTY on 26661 is not.
5. **Two owned accounts only.** Do not probe other tenants’ `sb-*` labels.

## Assets (Target #4)

| Asset | Attacker goal | Impact if broken |
|---|---|---|
| Published-port hostname | Reach a stopped/unpublished/deleted guest, or another tenant’s canary on the same URL | Critical if cross-tenant; Low/unpaid if only own stopped VM |
| Router cache after resume | First requests after resume hit the wrong VM | Critical if wrong tenant; expected 502-then-OK is not a finding |
| Fork / port-replace routes | Parent and child aliased, or omitted port still live | Critical if cross-tenant; Medium if same-tenant extra inbound |
| Interactive token / `wss://` host | 101 without mint, or old token on a new session | High–Critical if it reaches another tenant’s new VM |

## Relevant API shape

- `POST /v4/sandboxes` with `ports: [8080]`
- `PATCH /v2/sandboxes/{name}?projectId=` `{ "ports": […] }` — full replace
- `GET /v2/sandboxes/{name}?projectId=&__includeSystemRoutes=true`
- `POST /v2/sandboxes/sessions/{sessionId}/stop` and `GET …?resume=true`
- `POST /v3/sandboxes/{name}/fork` (and v2 if live)
- `POST /v2/sandboxes/sessions/{sessionId}/interactive` → `{url, token}`
- Observe: `https://sb-….vercel.run` with empty Authorization; compare canary body

## Threats in scope

T1. Stale published route after unpublish/stop/delete still returns the canary.
T2. Hostname uniqueness miss: A’s URL returns B’s canary (or reverse); fork parent/child share one live host.
T3. Interactive token or old `wss://` host attaches to a different session after stop/resume; TTY without current mint.
T4. Port replace leaves omitted ports reachable.
T5. Resume router-cache serves the wrong canary or a stopped VM (not a transient 502).

## Threats explicitly not this hunt

- Unauthenticated access to a currently published user port
- `SANDBOX_NOT_LISTENING`
- TTY 401 without token / 101 with current owner mint / B cannot mint (Target #1)
- Other tenants’ `sb-*` hosts
- Firewall / `forwardURL` (Target #3)
- Guest escapes, vsock, Firecracker/VMM

## Test identities

- Account A: `team_7jHS1s2yIuXVrcsI74DRljdn`, `prj_WgeFvOlmQM1BbtJTEHdQKySMzvC5`, sandbox `inbound-a`
- Account B: `team_LO7V6PmnTOI8i66m8MO6g6yb`, `prj_fuEcV8s1ISZBg4LncdBK1MfScxb9`, sandbox `inbound-b`

Stop at confirmation. ≤5 qps. No customer data. No exploit PoCs in git.

## Apex alignment

Accepted findings require a live PoC: old hostname reached a guest it should not (wrong canary, stopped VM still executing, TTY on another session). Close as out-of-scope: unauth published ports, `SANDBOX_NOT_LISTENING`, Target #1 TTY mint semantics, other-tenant enumeration. Close as duplicate: same stale-route miss on stop vs delete unless impact is materially new.
