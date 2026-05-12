# Scope — Acme Shop Public Bug Bounty

## In-Scope Assets

| Asset | Type | Eligible for Bounty |
|---|---|---|
| `*.acme-shop.example.com` | URL | Yes |
| `api.acme-shop.example.com` | URL | Yes |
| `com.acme.shop` (iOS / Android) | Mobile App | Yes |

## Out-of-Scope Assets

| Asset | Reason |
|---|---|
| `marketing.acme-shop.example.com` | Hosted by a third-party CMS; rules of engagement do not apply |
| `*.acme-shop-staging.internal` | Internal staging — VPN only, not part of the program |
| Anything not on the in-scope list above | — |

## Out-of-Scope Vulnerability Classes

- **Self-XSS** that requires the victim to paste a payload into their own DevTools console
- **Missing security headers** without a demonstrated impact (CSP, X-Frame-Options, HSTS, etc.)
- **Rate-limit absence** on public, idempotent, unauthenticated endpoints without a demonstrated brute-force success
- **Email enumeration** on the `/signup` and `/forgot-password` flows — known and accepted
- **Disclosure of public information** (e.g. usernames visible in product reviews, version banners on intentionally-public assets)
- **Cookie attribute** findings (`Secure` / `HttpOnly` / `SameSite`) on non-session cookies
- **Clickjacking** on pages without sensitive state-changing actions
- Vulnerabilities in **third-party software** we do not host or control
- **Reports from automated scanners** without manual validation and a working PoC
