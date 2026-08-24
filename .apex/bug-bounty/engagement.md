# Rules of Engagement — Vercel Sandbox

Source: HackerOne program policy, last reviewed 19 August 2026.

## Accounts

- Sign up at vercel.com with a HackerOne alias (`username@wearehackerone.com`).
- Hobby is enough. Pro has higher sandbox quotas.
- Test only in accounts the researcher owns.
- Cross-tenant tests: **two accounts the researcher owns** (attacker and victim). Prefer also two projects on the same team for same-team IDOR.

## Permitted

- Creating, configuring, and destroying sandboxes in owned accounts.
- Calling sandbox control-plane endpoints (`/v2|/v3|/v4/sandboxes*`) with owned tokens.
- Cross-account authorization tests that stop at confirmation.
- Network-policy, snapshot, fork, and filesystem tests against owned sandboxes.
- Scanners against Vercel-operated endpoints at **≤ 5 queries per second**. No volumetric DoS.

## Strictly prohibited

- Testing accounts, projects, or sandboxes the researcher does not own, except the two-account confirmation above.
- Continuing after a successful cross-tenant bypass: no enumerate, dump, persist, or further explore.
- Accessing more data than needed to prove the issue. If third-party data appears, stop, redact, report.
- Persistent backdoors; maintaining access after a PoC; modifying host or tenant state beyond demonstration.
- Social engineering of Vercel employees, customers, or researchers.
- Public disclosure of embargoed details or working exploits (embargo through 1 December 2026, with possible Critical/High extension).
- Uploading PoCs to public GitHub, pastebins, or video hosts. Keep material on HackerOne.

## Safe Harbor

Gold Standard Safe Harbor applies to research that follows this policy. It does **not** cover out-of-scope assets, retaining another tenant's data beyond a single confirmation, volumetric DoS, social engineering, or public disclosure of embargoed details.

## Submission requirements

A report is eligible only if the initial submission includes:

1. A zip of working PoC code
2. Vercel Team ID (`team_…`) used during testing
3. Vercel Project ID (`prj_…`) used during testing
4. Vercel Sandbox ID (`sbx_…`) where reproduced
5. Vulnerability class: Cross-Tenant data access / Networking and Firewall / Denial of Service / Other
6. Severity rationale that matches the program bounty table (not CVSS alone)
7. Acknowledgement of the 25% severity-inflation penalty

One root cause per report. First valid fully reproducible report of a root cause is paid; later reports are duplicates. New impact from a known primitive is paid at the new impact's tier.

## Severity table (do not inflate)

| Severity | Bounty            | Typical impact                                                     |
| -------- | ----------------- | ------------------------------------------------------------------ |
| Critical | $25,000 – $50,000 | MicroVM → EC2 host escape, or cross-tenant read / modify / RCE     |
| High     | $10,000 – $25,000 | Firewall bypass with credential or data exfil, or cross-tenant DoS |
| Medium   | $5,000 – $10,000  | Policy boundary violation without demonstrated secret exfil        |
| Low      | $1,000 – $5,000   | Hardening gaps, oracles                                            |

Target #1 (control-plane authorization): success that reads, modifies, or runs code in another owned account's sandbox/session/snapshot is **Critical**. Same-team cross-project IDOR that cannot reach another team still needs a demonstrated impact; do not self-score Critical without cross-tenant (two-team) confirmation.

Target #3 (firewall / credential brokering): firewall bypass **with** credential or data exfil via a Vercel-side defect is **High**. A wrong policy boundary without secrets is **Medium**. Cross-tenant read/modify of another account's policy or brokered identity is **Critical**. Do not self-score High for fail-closed (blocks more than configured) or for documented CIDR/SNI/DNS limitations.

Target #4 (inbound `*.vercel.run`): cross-tenant inbound to another owned account's guest is **Critical**. A stale route that only hits your own stopped VM is own-sandbox / hardening (Low or unpaid DoS). Unauthenticated access to a currently published user port is **not** a finding. Interactive without a current mint, or a token that opens a different session, is High–Critical if it reaches another tenant's new VM.

Target #5 (host / Firecracker / VMM): microVM → EC2 host escape is **Critical**. Populated host MMDS/IMDS disclosure is **High**. Cross-tenant host DoS is **High**. Listed container→guest and vsock-2050 primitives that stay in the guest are **unpaid**. Custom kernels/VMMs and CVE-only reports are out of scope. Do not volumetric-DoS the shared host. Target #5 observational probes were fail-closed (IMDS refused; no host paths; no cross-guest canary). Do not reopen.

Target #6 (`forwardRules` / OIDC): a Vercel-minted token whose `aud` is not the configured `forwardURL`, or whose claims are another team/project/sandbox, is **High**. Cross-tenant mint or policy write that harvests another account’s OIDC is **Critical**. Intended A→B forward with correct `aud` and A’s claims is not a finding. Third-party bins reflecting the token are unpaid. Hybrid probe 20 Aug 2026: happy-path mint, path/`aud` binding, matcher, and B policy POST were fail-closed. Do not reopen.

Target #7 (snapshot/fork content lineage): wrong-disk restore (canary of another owned tenant or project) is **Critical**. Same-sandbox fork inheriting its own parent canary is expected. Cross-account snapshot GET/create 403/404 without content is Target #1. Hybrid probe: own canary only; foreign snapshot 404; project-scoped even same-team; no A/B cache mix. Do not reopen.

Target #8 (Drives): foreign drive mount/read is **Critical**. On this engagement Hobby 403 private beta — **untestable** until Pro + waitlist. Do not spend runs on 403/404.

Target #9 (parameter confusion): server honoring a swapped `teamId`/`projectId` that acts on another tenant is **Critical**. 403 vs 404 existence oracle is **Low** and already documented (victim teamId → 403, else 404). Hybrid probe: no confused pair returned 200; cursor replay 400. Do not reopen.

Target #10 (`injectionRules` / transform): extra injection of an operator-configured secret toward a host/path the rule did not name is **High**. Cross-tenant policy write that injects another account’s secret is **Critical**. Happy-path inject to a destination the operator named is not a finding. Third-party bins are unpaid. Hybrid probe 20 Aug 2026: matcher and wrong-host fail-closed; B POST 403/404. Do not reopen.

## Hunt method (post-op, 24 Aug 2026)

Black-box 5–6-worker authz sweeps on this program are exhausted (0 findings / ~1,800 tool calls confirming documented fail-closed). Going forward:

1. **Source first.** Read the vendored `@vercel/sandbox` 3.1.0 dist ([vendor/vercel-sandbox/](vendor/vercel-sandbox/)) and [whitebox-hypotheses.md](whitebox-hypotheses.md) before launching Apex. A wrong wire shape costs a whole target (see Target #3 `forwardURL` miss).
2. **One hypothesis per run.** One worker, one falsifiable claim, one kill-gate. No exploratory “chain & explore” worker unless the hypothesis hits.
3. **Triage gate.** If the first 1–2 live probes confirm fail-closed, stop. Do not spend 300–500 tool calls re-confirming 403/404.
4. **Hybrid is fine.** Manual Python against the control plane for the kill-gate; Apex only if the hypothesis is still open after the first probe.
5. **CLI.** `pensar targeted-pentest` now defaults `--cwd` to the repo root (so `.apex/bug-bounty/…` resolves) and accepts `@file` on `--objective` plus `--fallback-model`.
6. **Model.** Stay on `x-ai/grok-4.6` (fallback `claude-sonnet-4-5`) until the next major post-op. GPT-5.6 Sol is registered and the OpenAI key is saved; **do not switch hunts to it yet**.

Decision: stay on Vercel Sandbox; escalate to H1–H9. Reallocate only after those are killed or Drives beta lands. H1–H7 and H9 killed 24 Aug 2026. H8 blocked on Hobby snapshot quota (see [whitebox-hypotheses.md](whitebox-hypotheses.md)). Next: H8 retry after freeing leftover snaps, or the next post-op. Stay on Grok until that evaluation.
