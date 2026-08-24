# Threat model — Target #6: forwardRules L7 proxy + OIDC identity

Generated for Apex `/triage` and `pensar pentest --threat-model`. Scope is the Vercel-operated **L7 request proxy** (`forwardRules` / `forwardURL`) and the OIDC token it mints (`vercel-sandbox-oidc-token`). Not host-firewall deny/allow convergence (Target #3, closed). Not inbound `*.vercel.run` lifetime (Target #4). Not Firecracker/VMM (Target #5). Not session/snapshot BOLA (Target #1).

## Why this hunt exists

Target #3 closed `forwardURL` after the live API rejected `{allow:[{host,forwardURL}]}` and `forwardURL` nested in `injectionRules`. The SDK/server wire shape is a **top-level `forwardRules` array** on the legacy custom policy (`mode: "custom"`), distinct from `injectionRules`. That body was never sent. OIDC `aud` / claim binding is therefore untested.

**Confirmed 20 Aug 2026:** session POST **request** must be the SDK record form:

```json
{ "allow": { "example.com": [{ "forwardURL": "https://<owned-observer>" }] } }
```

POST `{mode:"custom", forwardRules:[…]}` is 400 additional property (`forwardRules` is response-only). Array-of-objects `{allow:[{host,forwardURL}]}` is also 400.

Readback: `{mode:"custom", allowedDomains:["example.com"], forwardRules:[{domain, forwardURL}]}`. Happy-path mint: `aud` = observer origin, claims = fw-victim (Account A). That is intended, not a finding. This hunt is mismatch / extra injection / cross-account write only.

## System

Host interceptor terminates TLS for matching domains and reverse-proxies the request to `forwardURL` (HTTP/1.1, no query/fragment). It adds:

- `vercel-forwarded-host` / `vercel-forwarded-scheme` / `vercel-forwarded-port` / `vercel-forwarded-path`
- `vercel-sandbox-oidc-token` — RS256 JWT, issuer host `oidc.vercel.com`, `aud` = forwardURL origin (+ pathname if not `/`)

`@vercel/sandbox` `defineSandboxProxy` verifies `aud` against the incoming URL and requires claims `team_id`, `project_id`, `sandbox_id`, `sandbox_name`.

Observe only on an **owned** published port (`fw-observer` on Account B).

## Trust boundaries

1. **Configured forwardURL ↔ minted `aud`.** Token audience must be exactly that URL’s origin(+path), not the guest destination, not a sibling sink.
2. **Claims ↔ originating sandbox.** `team_id` / `project_id` / `sandbox_id` / `sandbox_name` must be the sandbox that egressed, not the observer, not another session.
3. **Token → tenant.** Account B must not mint or steal Account A’s OIDC by writing `forwardRules` on A’s session.
4. **Matcher → injection.** A rule for `/oidc-probe` must not attach a token to `/other` or to a domain the rule did not name.
5. **Fail-closed vs confused identity.** Blocking the forward is not a break. A verifiable token with the wrong `aud` or wrong tenant claims is.

## Assets

| Asset | Attacker goal | Impact if broken |
|---|---|---|
| OIDC `aud` | Present a token a different proxy will accept | High (credential retrieval via Vercel-side defect) |
| OIDC claims | Impersonate another team/project/sandbox at a proxy | High–Critical if cross-tenant |
| `forwardRules` on foreign session | Point another tenant’s egress at attacker sink and harvest their identity | Critical |
| Matcher / domain binding | Extra injection of OIDC or transform secrets | High |

## Threats in scope

T1. `forwardRules` accepted; minted `aud` ≠ configured forwardURL.
T2. Claims bind to observer / sibling / other team.
T3. Cross-account policy write with `forwardRules` returns 200 and mints victim identity.
T4. Confused deputy: observer receives a token for a request the victim did not configure to forward there.
T5. Matcher miss: path/method restriction still forwards (extra injection).

## Threats explicitly not this hunt

- Target #3 enforcement, persist-vs-session, empty `{}`, rejected `{allow:[{host,forwardURL}]}`
- B→A 403/404 on generic `POST /network-policy` already proven — reopen **only** if `forwardRules` changes the status
- Documented CIDR/SNI/DNS limitations
- Third-party request bins
- Inbound published-port unauth GET (no OIDC expected)
- SDK-only validation

## Test identities

- Account A: `team_7jHS1s2yIuXVrcsI74DRljdn`, project `prj_WgeFvOlmQM1BbtJTEHdQKySMzvC5`, sandbox `fw-victim`
- Account B: `team_LO7V6PmnTOI8i66m8MO6g6yb`, project `prj_fuEcV8s1ISZBg4LncdBK1MfScxb9`, observer `fw-observer` port 8080

Stop at confirmation. ≤5 qps. Redact raw JWTs in reports; keep `aud` / claim names.

## Apex alignment

Accepted findings require a live PoC: observer echo of a token whose `aud` or tenant claims are wrong, or a cross-account policy write that mints identity. Close as out-of-scope: intended A→B forward with correct `aud` and A’s claims; third-party bins; Target #3 fail-closed results.
