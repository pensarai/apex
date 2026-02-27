# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it responsibly. **Do not open a public GitHub issue for security vulnerabilities.**

Email: **security@pensarai.com**

Please include:

- A description of the vulnerability
- Steps to reproduce the issue
- Any potential impact you've identified
- Your suggested fix (if you have one)

## What to Expect

- We will acknowledge receipt of your report within 48 hours.
- We will work with you to understand and validate the issue.
- We will keep you informed of our progress toward a fix.
- Once the vulnerability is resolved, we will publicly acknowledge your contribution (unless you prefer to remain anonymous).

## Scope

This policy applies to the latest version of the project on the `main` branch.

### In Scope

The following components are considered security-relevant and fully in scope:

- **Shipped CLI and TUI** — the distributed command-line interface and terminal UI (`build/`, `bin/`)
- **Published npm package** — artifacts distributed via the `@pensar/apex` npm package
- **Authentication, authorization, and session logic**
- **Components that process untrusted external input as part of normal product usage**

### Limited Scope

The following components are evaluated under a **restricted threat model** with contextual severity:

- Developer tooling and internal scripts (`scripts/`, benchmark runners, CI utilities)
- Test harnesses and local development utilities
- Components that are present in the repository but **not distributed** as part of the packaged product (i.e., excluded by `package.json` `files` field and `.npmignore`)

Issues in limited-scope components are evaluated based on realistic threat models aligned with their intended usage. Severity classifications for these components reflect their actual product exposure and blast radius — not theoretical worst-case impact.

### Out of Scope

The following are generally considered **out of scope** and may be closed as informational:

- Issues requiring local source code modification by the reporter
- Self-compromise scenarios (e.g., a user injecting into their own locally authored files)
- Attacks requiring existing repository write access or local filesystem access beyond normal tool usage
- Theoretical vulnerabilities without a practical, realistic exploitation path
- Security best-practice suggestions without demonstrable impact
- Findings in non-shipped experimental, example, or scaffolding code
- Issues that require violating documented operational assumptions or intended usage patterns

We reserve the right to classify reports as **informational** if they do not present meaningful security impact within the intended product threat model.

## Threat Model

Apex assumes the following trust boundaries:

- **The user running the CLI has full control over their local machine.** Local developer tooling and service scripts operate in a trusted-user context.
- **Files within the repository are trusted.** Internal scripts, benchmark utilities, and CI tooling assume trusted inputs from the repository itself.
- **The CLI and hosted services are the primary security boundary.** These are the components through which untrusted external input enters the system during normal product usage.
- **Non-shipped components are not part of the product attack surface.** Code excluded from the npm package (`src/core/benchmark/`, `scripts/`, etc.) is internal tooling and is not designed to be executed by end users or against adversarial inputs as part of product functionality.

Issues that require a user to execute internal development scripts against malicious inputs outside their intended workflow, or that require modification of local configurations or files outside documented usage, may be classified as out of scope.

## Severity & Impact

Severity is determined based on:

- **Product exposure** — Is the affected component shipped to users?
- **Realistic attack surface** — Does the vulnerability arise during normal, intended usage?
- **Blast radius** — What is the scope of potential impact?
- **Alignment with intended usage** — Does exploitation require deviating from documented workflows?

Local-only code execution within internal developer tooling does not automatically equate to production remote code execution. Severity classifications reflect the actual deployment context and user exposure of affected components.

## Acknowledgment

We appreciate responsible security research. Valid, in-scope reports will be acknowledged in accordance with this policy. We follow a consistent, process-driven approach to disclosure and do not provide additional recognition beyond our standard acknowledgment process.

## Thank You

Thank you for helping keep Apex and its users safe.
