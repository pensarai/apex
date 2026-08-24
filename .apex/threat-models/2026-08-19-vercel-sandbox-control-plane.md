# Threat model — Target #1: Sandbox control-plane authorization

Generated for Apex `/triage` and `pensar pentest --threat-model`. Scope is the Vercel-operated REST API behind `@vercel/sandbox`, not the Firecracker guest and not the host firewall (those are later targets).

## System

Researchers authenticate with a Vercel OIDC JWT or personal access token. Every sandbox call is supposed to be bound to a team (`teamId`) and, for named resources, a project (`projectId` or `project`). Inside a project, sandbox **names** are unique. Running work is a **session**. Disk checkpoints are **snapshots**. Fork creates a new named sandbox from a source name or snapshot.

Documented hosts: `api.vercel.com`. Public SDK also targets `https://vercel.com/api` with `Authorization: Bearer` and `?teamId=`.

## Trust boundaries

1. **Token → team.** A token for team A must not act on team B's objects.
2. **Token → project.** A token (or OIDC `project_id`) for project A must not act on project B's named sandboxes, even in the same team.
3. **Opaque IDs → owner.** `sessionId` and `snapshotId` must resolve only if the caller owns the parent project/team. The public client omits `projectId` on these routes; the **server** must still bind them.
4. **Name → project.** `GET/PATCH/DELETE /v2/sandboxes/{name}` and `POST /v3/sandboxes/{name}/fork` must not honor a victim name plus an attacker `projectId`.
5. **Snapshot pointer.** `source.snapshotId` on create and `PATCH currentSnapshotId` must reject foreign snapshots.
6. **Interactive token.** The WebSocket token from `POST …/interactive` must be bound to that session and that principal; not replayable across sessions, teams, or after stop.

## Assets (Target #1)

| Asset | Attacker goal | Impact if broken |
|---|---|---|
| Session cmd / fs / interactive | Run commands or read/write files on a VM the caller does not own | Critical (cross-tenant RCE / disk) |
| Snapshot get / delete / restore | Read or boot another principal's filesystem | Critical |
| Fork | Clone another principal's sandbox (config, snapshot, possibly env) | Critical |
| Network-policy on foreign session | Weaken or steal another principal's egress / brokering config | High–Critical |
| List / pagination cursor | Enumerate foreign sandboxes or sessions | Medium–High depending on content |
| Private query flags (`__interactive`, `__includeSystemRoutes`) | Extra routes or tokens if the server honors them across principals | Medium–High |

## Relevant API shape (from public SDK 3.0.0)

High-risk because **no `projectId` in the client request**:

- `GET/POST /v2/sandboxes/sessions/{sessionId}` and `/cmd`, `/cmd/{cmdId}`, `/logs`, `/kill`
- `POST …/fs/read`, `/fs/write`, `/fs/mkdir`
- `POST …/stop`, `/extend-timeout`, `/network-policy`, `/interactive`
- `POST /v3/sandboxes/sessions/{sessionId}/snapshot`
- `GET/DELETE /v2/sandboxes/snapshots/{snapshotId}`

Named resources (do send project):

- `POST /v4/sandboxes` (image path) and `POST /v2/sandboxes` (legacy runtime)
- `GET/PATCH/DELETE /v2/sandboxes/{name}?projectId=`
- `POST /v3/sandboxes/{name}/fork?projectId=`
- List endpoints use query `project=` (not `projectId=`) — server must treat both as the same ACL

## Threats in scope for this hunt

T1. Session BOLA: attacker token + victim `sessionId` succeeds on cmd/fs/interactive/stop/policy.
T2. Snapshot BOLA: attacker token + victim `snapshotId` succeeds on get/delete/create-from-snapshot.
T3. Snapshot graft: `PATCH` attacker sandbox `currentSnapshotId` = victim snapshot.
T4. Fork confused deputy: victim sandbox name + attacker `projectId` / `teamId`.
T5. Parameter confusion: `project` vs `projectId`, OIDC claims vs query `teamId` override, pagination cursor replay.
T6. Interactive token replay or binding miss.
T7. Resume (`GET …?resume=true`) or `getOrCreate` acting on a foreign name.

## Threats explicitly not this hunt

- Guest container escapes, vsock 2050, MMDS, Firecracker virtio
- Firewall matcher/CIDR/DNS quirks
- Client-only SDK bugs (still useful as hints if the **server** accepts the confused inputs the client can send)
- VCR / build / dashboard APIs

## Test identities (required before live work)

- Account A (victim): `team_A`, `prj_A`, sandbox name, `sessionId`, `snapshotId`, marker file
- Account B (attacker): `team_B`, `prj_B`
- Optional same-team pair: `prj_A1` and `prj_A2` under `team_A` (faster IDOR signal; Critical still needs two teams)

Rules: two owned accounts, stop at confirmation, ≤5 qps, no customer data.

## Apex alignment

Accepted findings for Target #1 require a live HTTP PoC against the control plane showing another owned principal's object was read, modified, or executed. Close as out-of-scope: dashboard/non-sandbox APIs, SDK-only issues, known guest primitives. Close as duplicate: same authorization miss on a different verb of the same object class unless impact is materially new (e.g. session read vs snapshot restore may share one root cause — one report).
