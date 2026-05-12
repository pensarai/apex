# Business Context — Acme Shop

> This document captures business-level decisions that affect triage outcomes — what we treat as accepted risk, what's load-bearing, and what the blast radius of various surfaces looks like.

## Asset Criticality

| Surface | Tier | Notes |
|---|---|---|
| `api.acme-shop.example.com` | Tier 0 — Critical | Payment flow, account API, checkout. Findings here are accepted at lower severity thresholds. |
| `*.acme-shop.example.com` (storefront) | Tier 1 — High | Customer-facing storefront and authenticated UI. |
| `staging.acme-shop.example.com` | Tier 1 — High | Mirrors production; treated as production-equivalent for triage. |
| Internal admin dashboard | Tier 0 — Critical | Not exposed to the public internet — out of program scope. |

## Accepted Risks

These are decisions the security team has made deliberately. Reports that hit one of these should be closed as **Informative** with a pointer to this section.

- **Email enumeration on `/signup` and `/forgot-password`** — by design. The product needs to tell users whether an account already exists during signup. Accepted because the email address is not a secret in our threat model.
- **Lack of CAPTCHA on `/login`** — we use server-side rate limiting + WebAuthn-eligible accounts as our primary control. CAPTCHA was removed in Q3 2025 after measured conversion impact.
- **No CSP on the marketing site** (`marketing.acme-shop.example.com`) — the marketing site is a static export, no auth, no user data, third-party hosted. CSP is on the roadmap for Q4 2026 but not gating.
- **`Server:` and `X-Powered-By:` headers visible** — operational visibility tradeoff; we monitor for known CVEs in the underlying stack rather than trying to hide it.

## Data Sensitivity

- **Order history, payment methods, addresses** — high sensitivity. Any IDOR / authorization bypass touching these is treated as Critical.
- **Wishlists, product reviews, public profile** — low sensitivity, public by design.
- **Session cookies (`acme_session`)** — high sensitivity. XSS that can read them is treated as High minimum.

## Out of Scope for Remediation

Even when valid, the security team will not invest engineering time on:

- Vulnerabilities in deprecated mobile app versions older than 18 months — users have been notified to upgrade.
- Theoretical attacks against soon-to-be-decommissioned surfaces (the `/legacy/*` API path is scheduled for removal on 2026-09-01).
