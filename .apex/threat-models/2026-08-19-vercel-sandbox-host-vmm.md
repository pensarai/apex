# Threat model — Target #5: Host / Firecracker / VMM

Generated for Apex `/triage` and `pensar pentest --threat-model`. Scope is the **compute isolation boundary**: guest kernel → Firecracker/KVM → jailed VMM → EC2 bare-metal host → sibling microVMs. Not control-plane IDOR (Target #1). Not host-side egress firewall (Target #3). Not inbound `*.vercel.run` lifetime (Target #4).

## System

Vercel Sandbox runs untrusted code in Firecracker microVMs on shared bare-metal EC2. Linux namespaces inside the guest are developer ergonomics, not the rewarded boundary. Firecracker exposes a small device surface (virtio block, net, vsock). The VMM is jailed (chroot, cgroups, namespaces, dropped privileges, seccomp). The host runs orchestration, snapshot/cache, firewall/credential brokering, and sibling VMs.

Observe from **owned** guests via `POST …/cmd` (binary path + args). Do not supply custom kernels or a custom VMM.

## Trust boundaries

1. **Guest kernel ↛ EC2 host.** Reaching the host OS, jailer jail, or host IMDS/MMDS is Critical/High. Staying in the guest is unpaid.
2. **This microVM ↛ sibling microVM.** Another owned account’s canary or disk appearing in this guest is Critical.
3. **Drive/mount ↛ foreign project/team.** Drive APIs if present must bind to the caller’s project.
4. **Resource isolation.** Cross-tenant host DoS is High; own-sandbox crash and volumetric flooding are unpaid / prohibited.

## Assets (Target #5)

| Asset | Attacker goal | Impact if broken |
|---|---|---|
| EC2 host OS / jailer | Execute or read on the host | Critical |
| Host IMDS / MMDS | Host instance or IAM identity | High (populated MMDS) |
| Sibling VM disk / snapshot cache | Read or write another tenant | Critical |
| Drives (beta) | Mount another tenant’s drive | Critical |
| Shared-host stability | Cross-tenant DoS without volumetric flood | High |

## Threats in scope

T1. Link-local/metadata from the guest returns **host** identity (allow-all or deny-all).
T2. `/proc`, mounts, `/dev`, or virtio expose **host** paths or another tenant’s volume.
T3. Two owned VMs leak each other’s canary/session via a host/VMM channel.
T4. Drive list/get-or-create/mount honors a foreign drive or project id.
T5. New host write/RPC beyond listed vsock-2050 guest primitives.

## Threats explicitly not this hunt

- Container→guest escapes; vsock 2050 RPCs; `containerd.sock` / `ipc.sock`; sibling containers still in the same microVM; sandbox-init Ed25519
- Guest virtio/Firecracker inventory without host/cross-tenant impact
- Custom kernel/VMM the operator cannot supply
- Public CVE version-matching without a live host PoC
- Target #1/#3/#4 closed results
- Own-sandbox DoS; volumetric host flood
- SDK-only bugs

## Test identities

- Account A: `team_7jHS1s2yIuXVrcsI74DRljdn`, `prj_WgeFvOlmQM1BbtJTEHdQKySMzvC5`, sandbox `host-probe` (allow-all, 45 min)
- Account B: `team_LO7V6PmnTOI8i66m8MO6g6yb`, `prj_fuEcV8s1ISZBg4LncdBK1MfScxb9`, sandbox `inbound-b` (second live VM)

Stop at confirmation. ≤5 qps. No customer data. No exploit PoCs in git. No volumetric DoS.

## Apex alignment

Accepted findings require a live PoC that the guest reached the **EC2 host**, another owned tenant, or a populated host metadata service. Close as out-of-scope/duplicate: listed guest primitives, virtio inventory, Target #1–#4 results, custom VMM, CVE-only reports.
