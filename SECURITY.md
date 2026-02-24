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

Apex is an AI-powered penetration testing tool that runs locally on your machine. It provides an agent system with access to powerful tools including shell execution (e.g., nmap), file operations, and network scanning — directly in your terminal.

### No Sandbox

Apex does not sandbox the agent. The permission system exists as a UX feature to help users stay aware of what actions the agent is taking — it prompts for confirmation before executing commands, writing files, etc. However, it is not designed to provide security isolation.

If you need true isolation, run Apex inside the included Kali Linux Docker container or another VM.

### Out of Scope

| Category | Rationale |
| --- | --- |
| Sandbox escapes | The permission system is not a sandbox (see above) |
| LLM provider data handling | Data sent to your configured LLM provider is governed by their policies |
| MCP server behavior | External MCP servers you configure are outside our trust boundary |
| Malicious config files | Users control their own config; modifying it is not an attack vector |
| Actions on authorized targets | Apex is designed to perform security testing on targets you are authorized to test |

## Scope

This policy applies to the latest version of the project on the `canary` branch.

Thank you for helping keep Apex and its users safe.
