# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it responsibly. **Do not open a public GitHub issue for security vulnerabilities.**

Instead, please email us at **[security@pensarai.com](mailto:security@pensarai.com)** with the following details:

- A description of the vulnerability
- Steps to reproduce the issue
- Any potential impact you've identified
- Your suggested fix (if you have one)

## What to Expect

- We will acknowledge receipt of your report within **48 hours**.
- We will work with you to understand and validate the issue.
- We will keep you informed of our progress toward a fix.
- Once the vulnerability is resolved, we will publicly acknowledge your contribution (unless you prefer to remain anonymous).

## Threat Model

### Overview

Apex is an AI-powered penetration testing CLI/TUI that runs locally on your machine. It uses an agentic system to perform blackbox and whitebox security testing — executing shell commands, sending HTTP requests, automating browsers, reading files, and generating exploit PoCs. By design, it performs potentially dangerous offensive security operations against targets you are authorized to test.

### No Sandbox

Apex includes an Operator mode with tiered approvals (T1 passive through T5 exploit) that prompts before executing actions. This is a **UX feature for operator awareness**, not a security boundary. It does not provide isolation from the agent.

For true isolation, run Apex inside the included Kali Linux Docker container or another VM.

### Out of Scope

| Category | Rationale |
| --- | --- |
| Operator mode bypasses | Not a security boundary — it is a UX feature |
| LLM provider data handling | Governed by your provider's policies |
| Actions on authorized targets | Offensive security operations are the intended purpose |
| Container privileges | The Kali container intentionally uses elevated network capabilities |
| Malicious local config | `~/.pensar/config.json` is user-controlled |
| MCP server / remote sandbox behavior | External services you configure are outside our trust boundary |

## Scope

This policy applies to the latest version of the project on the `canary` branch.

Thank you for helping keep Apex and its users safe.
