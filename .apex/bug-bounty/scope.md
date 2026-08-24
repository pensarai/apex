# Scope — Vercel Sandbox (HackerOne)

Program: [https://hackerone.com/vercel_sandbox](https://hackerone.com/vercel_sandbox)
Window: 18 August 2026 – 1 September 2026 23:59 UTC (or when the $1,000,000 pool is exhausted).
CSV asset: `Vercel sandbox` (`OTHER`), bounty-eligible, max severity Critical.

This file is the Apex triage source of truth. When a report disagrees with the live HackerOne policy, the live policy wins.

## In-scope assets

| Asset                             | Type     | Notes                                                                                                                                                                                 |
| --------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --- | ---------------- |
| Vercel Sandbox isolation boundary | Other    | Firecracker microVM, jailer, host-side sandbox firewall, credential brokering, sandbox control-plane API                                                                              |
| Sandbox control plane             | REST API | Whatever `@vercel/sandbox` / the `sandbox` CLI consume. Documented under `/v2                                                                                                         | /v3 | /v4/sandboxes\*` |
| Control-plane hosts               | URL      | `api.vercel.com` and `vercel.com/api` sandbox routes only                                                                                                                             |
| Inbound sandbox routes            | URL      | Disclosed `*.vercel.run` hosts for **researcher-owned** sandboxes (system interactive port 26661 and operator-published ports). Other tenants' `*.vercel.run` hosts are out of scope. |

A finding is in scope when it does one of:

- Escapes the Firecracker microVM to the EC2 host OS
- Reads, modifies, or executes code in a sandbox the researcher does not own (use two owned accounts)
- Bypasses the operator-configured sandbox firewall, especially with credential or data exfiltration via a Vercel-side defect
- Retrieves credentials configured through credential brokering via a Vercel-side defect
- Breaks authorization on the sandbox control plane (IDOR / BOLA / auth bypass that acts on another tenant's sandboxes, sessions, snapshots, files, commands, interactive shells, or network policy)
- Causes cross-tenant denial of service on the shared host

## Current hunt: whitebox logic bugs (not another authz sweep)

Targets #1, #3, #4, #5, #6, #7, #9, and #10 are **fail-closed** with live PoCs. Target #8 (Drives) is **retired** on Hobby (403 private beta; Pro + waitlist required).

**Decision (24 Aug 2026 post-op):** stay on this program and escalate to **whitebox-anchored logic bugs** on the remaining `@vercel/sandbox` surface. Do **not** reallocate to another program while H1–H8 in [whitebox-hypotheses.md](whitebox-hypotheses.md) are untested. Do **not** spend another 5-worker breadth sweep re-proving 403/404.

Method: one falsifiable hypothesis per run; first 1–2 fail-closed probes **stop the objective**. Source of truth for wire shape is the vendored SDK at [vendor/vercel-sandbox/](vendor/vercel-sandbox/) (`@vercel/sandbox@3.1.0`). H1–H7 and H9 are **fail-closed** 24 Aug 2026. H8 is **blocked** on Hobby snapshot-storage 402 (not killed). Next: retry H8 after freeing leftover snaps, or the next post-op.

Do **not** reopen:

| Target                         | Closed as                                                                                                                  | Do not re-prove                                                                                             |
| ------------------------------ | -------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| #1 control-plane IDOR          | B→A session/fs/cmd/interactive/snapshot 403 (victim teamId) / 404 otherwise                                                | Unauth/fake-team 403 matrix                                                                                 |
| #3 firewall                    | deny/allow/custom matches guest; persist-vs-session split honest; B policy POST 403/404                                    | Empty `{}` = deny-all; CIDR/SNI/DNS docs                                                                    |
| #4 inbound `*.vercel.run`      | unpublish/stop fail-closed; TTY token bound; no cross-tenant hostname mix                                                  | Unauth published-port 200 with correct canary                                                               |
| #5 host/VMM                    | IMDS refused; no host paths; no cross-guest canary                                                                         | vsock 2050 / container→guest / virtio inventory                                                             |
| #6 `forwardRules`/OIDC         | SDK `{allow:{host:[{forwardURL}]}}` mints `aud`=forwardURL and **fw-victim** claims; matcher no extra injection; B 403/404 | POST `{mode,forwardRules}` 400; `{allow:[{host,forwardURL}]}` 400; intended A→B forward with correct claims |
| #7 snapshot lineage            | own fork/restore keeps own canary; foreign snapshot 404; no A/B cache mix; snapshots **project-scoped**                    | Target #1 snapshot BOLA without content                                                                     |
| #8 Drives                      | 403 private beta on Hobby                                                                                                  | Re-hitting `/v2/sandboxes/drives*`                                                                          |
| #9 param confusion             | no `teamId`/`projectId` pair returns 200 on a foreign object; cursor replay 400 `invalid_cursor`                           | Same 403/404 oracle as #1                                                                                   |
| #10 `injectionRules`/transform | matcher/wrong-host no extra canary; B policy POST 403/404                                                                  | Happy-path inject to named host; Target #3 persist                                                          |

Wire facts that burned runs when missing:

- LIST uses `project=`; named GET uses `projectId=`. Session subresources are `/v2/sandboxes/sessions/{sbx_id}/…`.
- L7 **request** is SDK allow-map `{allow:{domain:[{forwardURL}]}}`. `forwardRules` is **readback-only**.
- Create-from-snapshot: `{source:{type:"snapshot", snapshotId}}`.

Re-open only if: Drives beta lands on a Pro account; a new control-plane verb appears; or a live token/`aud` mismatch is observed that contradicts Target #6 API facts.

## Out-of-scope assets

| Asset                                                                        | Reason                                                     |
| ---------------------------------------------------------------------------- | ---------------------------------------------------------- |
| `vercel.com` dashboard, v0, billing, account, team, project, deployment APIs | Different Vercel HackerOne programs                        |
| `@vercel/sandbox` / `sandbox` CLI client bugs                                | Client-side; use them to reach the API, do not report them |
| Vercel Container Registry (auth, blob push, OIDC, control plane)             | Explicitly out                                             |
| Dockerfile / Containerfile build-phase issues                                | Different product boundary                                 |
| Third-party sites, Datadog, AWS (except Vercel-side reachability)            | Report the Vercel defect, not the third-party bug          |
| Linux container namespace escapes that only reach the Firecracker guest OS   | Known; not the security boundary                           |

## Out-of-scope / unpaid classes (even on in-scope assets)

- Own-sandbox DoS (crash, hang, or exhaust a sandbox you own)
- Credential capture via a third-party site reflecting brokered headers
- Documented firewall limitations (CIDR allow bypassing SNI/brokering; CIDR-only leaving DNS open; catch-all `*` passing domain-less traffic; plaintext HTTP/Postgres not domain-filterable)
- Public Firecracker/CVE version-matching without a live PoC against Vercel Sandbox
- Custom-kernel or custom-VMM attacks the operator cannot supply
- Static-analysis-only reports; scanner output without a working live PoC
- AI-generated reports without personal verification of a live PoC
- Known container→guest and listed post-escape primitives **unless** chained to a new host-compromise, cross-tenant, or firewall-exfil impact
