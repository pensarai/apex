# Business Context — Vercel Sandbox

## Why this product exists

Vercel Sandbox runs untrusted or AI-generated code in Firecracker microVMs on shared bare-metal EC2. Operators (agent products, code interpreters) treat the guest as fully hostile. The payable boundary is: do not reach the EC2 host, another tenant, or operator-configured firewall/credential controls.

## Asset criticality for Target #1

| Surface                                                                                      | Tier   | Notes                                                                                                   |
| -------------------------------------------------------------------------------------------- | ------ | ------------------------------------------------------------------------------------------------------- |
| Sandbox control plane (create/get/patch/delete, session cmd/fs/interactive, snapshots, fork) | Tier 0 | Broken authorization here is cross-tenant RCE or disk read without a VM escape                          |
| Snapshot store + `currentSnapshotId`                                                         | Tier 0 | Snapshots outlive sandboxes and can boot arbitrarily many children                                      |
| Interactive PTY token (`POST …/interactive`)                                                 | Tier 0 | Full shell on a running VM                                                                              |
| Network-policy replace on a live session                                                     | Tier 0 | Can disable another tenant's egress controls or steal a policy that contains brokered-credential config |
| Public port routes (`*.vercel.run`)                                                          | Tier 1 | Inbound to guest; no platform auth by default — Target #4, not this hunt                                |
| Host-side firewall / credential brokering                                                    | Tier 0 | Target #3                                                                                               |
| Guest Linux namespaces / vsock 2050                                                          | Known  | Not Target #1; only unpaid unless new host/cross-tenant impact                                          |

## Accepted / documented non-findings

Reports that only reproduce these should be closed Informative or Duplicate:

- Container → Firecracker guest OS namespace escapes (listed on the program page)
- Unauthenticated vsock 2050 RPCs, `containerd.sock`, `ipc.sock`, sibling-container spawn still Firecracker-bounded, sandbox-init Ed25519 extraction
- Platform injection of `x-vercel-oidc-token`, `x-vercel-protection-bypass`, `x-vercel-proxy-signature` captured via third-party reflection
- Documented firewall limitations (see `scope.md`)
- SDK/client defects, including OIDC refresh updating `teamId` but not `projectId` **in the client**. A **server** that honors a stale or confused `teamId`/`projectId` pair is in scope.
- `getOrCreate` ignoring create parameters when the named sandbox already exists (documented)
- Multi-agent Linux users inside one sandbox (same-tenant DX isolation)

## Data sensitivity

- Another tenant's filesystem, env, snapshots, command logs, interactive shell → Critical
- Brokered credentials and OIDC tokens minted for `forwardURL` → High minimum if retrieved via a Vercel-side defect
- Sandbox/session/snapshot identifiers with low entropy and no demonstrated use → Low
- Evidence of another tenant's existence/timing on a shared host with no content → Low

## Duplicate / race notes

As of 24 August 2026 the program had **884 reports received and 0 resolved** (live capture; the earlier “124 as of 19 Aug” note is stale). Internal duplicates still close as Duplicate. Prefer two-account confirmation of a **new** authorization miss over rediscovering listed guest primitives. See [post-op-2026-08-24.md](post-op-2026-08-24.md).

Closed on this engagement (do not reopen as “new”): Targets #1, #3, #4, #5, #6, #7, #9, #10 fail-closed; #8 Drives untestable on Hobby. See `scope.md` closed-hunt table.

24 Aug 2026 post-op: black-box breadth is exhausted **on the routes that were sent** (`api.vercel.com`, mixed `/v3`/`/v4`). H1–H7 and H9 fail-closed those inputs; they are not current-SDK-surface closes. H8 blocked on Hobby snapshot-storage 402 (not killed). Remaining: current-SDK host/route first, then H8 only after the retain/delete manifest. Still Grok; GPT-5.6 Sol later. See [post-op-2026-08-24.md](post-op-2026-08-24.md). Do not default back to 5-worker sweeps. Do not delete keep-list sandboxes from the narrative.
