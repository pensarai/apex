# Target #5 — Apex briefing (host / Firecracker / VMM)

HackerOne program: vercel_sandbox. Use only `https://api.vercel.com` sandbox REST routes (`/v2|/v3|/v4/sandboxes*`) plus inbound `*.vercel.run` hosts disclosed for **our** sandboxes. Do not hit dashboard, v0, billing, VCR, `openapi.vercel.sh`, or other Vercel APIs. Cap at 5 requests per second. One root cause per finding. Live PoC required. Stop at confirmation. Do not dump customer data. Do not encode/obfuscate URLs to dodge the scope guard. Prefer this briefing over `web_search`.

This engagement has **two Vercel users**. Session HTTP headers inject **Account A**. Account B’s PAT is in `.apex/bug-bounty/local/headers-b.json`. **Do not print either token.** Python urllib needs `allow_unprotected: true`.

Targets #1, #3, #4, and #6 are **exhausted**. Do not reopen control-plane IDOR, firewall/OIDC, or inbound route lifetime.

The payable boundary is **Firecracker / jailer / EC2 host**, not Linux namespaces inside the guest. File only if you show **EC2 host** identity/credentials/filesystem, **another tenant’s** VM, or **cross-tenant host DoS** without volumetric flooding. Container→guest and listed vsock primitives are **unpaid** unless chained to that new impact.

## Dual loop

1. **Mutate** via `http_request` to `api.vercel.com` only when needed: resume `host-probe`, create a throwaway, `POST …/network-policy` `{mode:deny-all}` vs `allow-all` to see if link-local/metadata changes. Do not `POST {}` network-policy. Do not snapshot mid-run.
2. **Observe from inside our guest** with `POST /v2/sandboxes/sessions/{sessionId}/cmd`: `command` is a **binary path** (`/bin/cat`, `/usr/bin/curl`, `/bin/ip`, `/usr/bin/python3`), `args` is an array, `wait:true`, `logs:true`. Do **not** invent exploit payloads, custom kernels, or VMM patches.
3. Compare two owned VMs when looking for co-tenant signals: Account A `host-probe` vs Account B `inbound-b` (headers-b.json). A finding is B’s canary or host identity appearing in A’s guest (or reverse), not “both VMs have similar /proc/cpuinfo”.
4. Drive endpoints (`/v2|/v3|/v4` drives/mounts) if they exist on this account — foreign drive mount is in scope. 404 on the whole family is expected if the account has no beta.

## Hard constraints

- `host-probe` is `timeout: 2700000`, `allow-all`. **Do not `POST /stop` on `host-probe` or `inbound-b`** while siblings need them. Throwaways only for stop/deny-all experiments.
- Do not PATCH port 26661. Do not DELETE keep-list sandboxes. Do not print tokens. `{host}` in Python format strings trips the scope guard. ≤5 rps.
- **No volumetric DoS.** Do not stress the shared host. Own-sandbox crash/hang is unpaid.
- Custom-kernel / custom-VMM attacks the operator cannot supply are out of scope. Public Firecracker CVE version-matching without a live host PoC is unpaid.

## Live objects (IDs rotate)

Account A — user `Ini8xEkCg605GgClB8J4O1yT` / team `team_7jHS1s2yIuXVrcsI74DRljdn` / victim project `prj_WgeFvOlmQM1BbtJTEHdQKySMzvC5`:
- **`host-probe`** — persistent, allow-all, 45 min. Pre-run session `sbx_R4sfoMuxLZMnDVJNe5uKtqW6Z0Nx`. Re-GET before use.
- Leave `victim-base` / `inbound-a` / `fw-victim` / `attacker-probe` / `fork-same-project` alone unless you need the filesystem canary `/vercel/SECRET.txt` = `CANARY-E1DE39E5-3F20-4243-8F71-3B7410EC73F9`.

Account B — user `LWgYUj0PGJ0ncS5cB55mxUmM` / team `team_LO7V6PmnTOI8i66m8MO6g6yb` / project `prj_fuEcV8s1ISZBg4LncdBK1MfScxb9`:
- **`inbound-b`** resumed for this hunt (second live VM). Pre-run session `sbx_6XjbZaNZPulK1YI0sObnVG4403ZC`. Canary body if the listener is up: `CANARY-INBOUND-B`. Look up `GET /v2/sandboxes/inbound-b?projectId=…&teamId=…`.
- Keep `attacker-b` / `fw-observer` (stopped is fine).

LIST uses `project=`. Named GET uses `projectId=`. Session cmds are `/v2/sandboxes/sessions/{sbx_id}/cmd`.

## Documented non-findings (do not “discover” these)

- Container → Firecracker **guest** namespace escapes (capabilities, `/dev`, sysctls, seccomp gaps, shared mounts still inside the microVM).
- Unauthenticated vsock **2050** RPCs, `containerd.sock`, `ipc.sock`, sibling-container spawn that stays Firecracker-bounded, sandbox-init Ed25519 extraction.
- Guest can see virtio / `lscpu` / a Firecracker-like cmdline — that is expected microVM inventory, not host escape.
- Deny-all blocking link-local / DNS (fail-closed). Target #3 already showed deny-all blocks example.com DNS.
- Target #1 403/404 IDOR; Target #3 empty `{}` policy / rejected `{allow,forwardURL}`; Target #4 unauth published ports / TTY token semantics.
- SDK-only bugs; own-sandbox DoS; scanning other tenants’ hosts.

## What counts as a finding

- Guest reaches **EC2 IMDS/MMDS** (or equivalent) and receives **host** instance/IAM/identity — not a guest-local 404/timeout. Policy lists populated MMDS disclosure as High.
- Guest reads or writes **host** filesystem, jailer jail, or another tenant’s virtio disk / snapshot cache.
- Two owned accounts: A’s guest observes B’s canary or session via a **host** channel (not `*.vercel.run` inbound, which is Target #4).
- Foreign **drive** mount / get-or-create succeeds on the other team’s drive id.
- Cross-tenant **host** instability without volumetric flooding (stop at confirmation). Do not attempt to take the host down.

If you only reproduce a listed guest primitive, write memory “expected-secure / unpaid” and move on. Do not file it.

## Objectives (one worker each)

1. **Link-local / metadata:** From `host-probe` (allow-all) and a deny-all throwaway, `curl` link-local/metadata endpoints with short `--max-time`. Finding = host instance or IAM material. Timeout/404/deny-all block is expected-secure.
2. **Guest inventory vs host leak:** `cat` `/proc/cmdline`, mounts, `/dev`, DMI if present. Finding = host paths, other tenants’ disks, jailer chroot of the VMM. Virtio/Firecracker guest inventory is not a finding.
3. **Two-VM co-tenant signal:** Compare `host-probe` (A) vs `inbound-b` (B). Finding = one guest sees the other’s canary or unique session id via a host/VMM channel. Similar CPU model on both is not a finding.
4. **Drives / mounts:** Probe documented drive list/get-or-create/delete/mount on both tokens. Finding = 200 that attaches or reads the other tenant’s drive. Whole-family 404 = no beta, not a finding.
5. **Jailer / device grant residual:** Only if a **new** host write, host RPC, or cross-tenant effect appears. Do not spend the run re-documenting vsock 2050. Do not write exploit code.

Chain worker: leftover host-identity oracles only if they produce host credentials or cross-tenant content — not another `/proc/cpuinfo` dump.

Read also: `.apex/bug-bounty/scope.md`, `.apex/bug-bounty/engagement.md`, `.apex/threat-models/2026-08-19-vercel-sandbox-host-vmm.md`. Those markdown files are engagement docs, not application source — reading them is allowed.
