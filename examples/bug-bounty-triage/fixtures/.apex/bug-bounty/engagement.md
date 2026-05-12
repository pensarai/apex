# Rules of Engagement — Acme Shop Bug Bounty

## Permitted Testing

- Authenticated and unauthenticated testing against the in-scope assets defined in `scope.md`.
- Functional testing using your own accounts. You may create up to 5 test accounts per email domain.
- Reading of your own data — including session cookies, JWTs, and account preferences — to demonstrate impact.

## Strictly Prohibited

- **Accessing another user's data** beyond the minimum needed to prove the vulnerability. If you read someone else's data accidentally, stop and report it.
- **Destructive actions** of any kind: data deletion, account deletion, payment manipulation, brute-force at production rates, denial-of-service.
- **Social engineering** of Acme Shop employees, customers, or vendors.
- **Physical attacks** against Acme Shop offices, data centers, or staff.
- **Use of automated scanners** (Nuclei, Nessus, Burp Active Scan, etc.) against production assets without prior written approval. Scanner-only reports are ineligible.

## Required for Submission

A report is eligible only if it includes ALL of:

1. A **reproducible PoC** — exact request(s), parameters, account context, and expected vs. observed response.
2. A **realistic attack scenario** — who the attacker is, what they need, and what they gain.
3. **No more than one vulnerability per report.** Chained vulnerabilities should be split into individual reports referencing each other.

Reports missing any of the above will be moved to **Needs More Info** and auto-close after 30 days per HackerOne policy.

## Severity Guidance

- **Critical / High** reports must include a working exploit demonstrating real impact (data exfiltration, account takeover, RCE, etc.).
- **Medium** reports must include a clear, exploitable scenario — not theoretical risk.
- Reports that demonstrate only the *absence* of a control (e.g. "no rate limiting"), without showing how that absence is exploitable, will be assessed at Low or Informative.
