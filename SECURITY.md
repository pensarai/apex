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

Apex is an AI-powered penetration testing CLI/TUI that runs locally on your machine. It provides an agentic system with 30+ tools for offensive security testing, including:

- **Shell execution** — runs commands like `nmap`, `sqlmap`, `gobuster`, `nikto`, `hydra`, and arbitrary shell commands
- **HTTP requests** — sends crafted requests to targets with custom methods, headers, and payloads
- **Browser automation** — controls a headless browser via Playwright MCP for authenticated crawling, form filling, and JavaScript evaluation
- **File operations** — reads files, lists directories, and greps the local filesystem
- **PoC creation** — generates and writes proof-of-concept exploit scripts to disk
- **Authentication flows** — probes auth endpoints, manages sessions, and stores credentials
- **Specialized sub-agents** — spawns focused agents for attack surface discovery, targeted pentesting, code analysis, and CVSS scoring

Apex is designed to perform security testing on targets you are authorized to test. By nature, it executes potentially dangerous operations — that is its intended purpose.

### Operator Mode (Not a Sandbox)

Apex includes an **Operator mode** with three settings — `plan`, `manual`, and `auto` — and a five-tier permission classification system:

| Tier | Name | Examples |
| --- | --- | --- |
| T1 | Passive | DNS lookups, scratchpad notes, report generation |
| T2 | Low-risk Active | GET/HEAD requests, crawling, endpoint discovery |
| T3 | Probing | Parameter fuzzing, auth probing, form filling |
| T4 | Intrusive | Shell commands, heavy fuzzing, JavaScript evaluation |
| T5 | Exploit | RCE attempts, data modification, state-changing actions |

Tool calls are dynamically classified — for example, an `http_request` starts at T2 but escalates to T5 if the payload contains exploit patterns (command injection, SQL injection, path traversal, etc.).

**This system is a UX feature for operator awareness, not a security sandbox.** In `auto` mode, actions up to the configured tier are executed without confirmation. In `manual` mode, the operator approves each action. In `plan` mode, the agent can only propose — not execute — network actions. None of these modes provide security isolation from the agent.

If you need true isolation, run Apex inside the included **Kali Linux Docker container** or another VM.

### Credential Storage

- **LLM provider API keys** are stored in `~/.pensar/config.json` or read from environment variables (env vars take precedence). Supported providers: Anthropic, OpenAI, OpenRouter, AWS Bedrock, and local models via vLLM.
- **Target credentials** (usernames, passwords, tokens, cookies) discovered or provided during a session are stored per-session in `~/.pensar/session/{id}.json`.
- **Daytona/Runloop API keys** for remote sandbox execution are stored alongside provider keys in the config file or environment.

Config files are user-controlled and not synced or transmitted beyond the local machine (aside from API calls to the configured LLM provider).

### Kali Linux Container

The included Docker container runs Kali Linux with `NET_ADMIN`, `NET_RAW` capabilities and `seccomp:unconfined`. These elevated privileges are intentional — they enable the full range of network scanning and penetration testing tools. The container runs as a non-root `pentest` user with sudo access.

### Out of Scope

| Category | Rationale |
| --- | --- |
| Operator mode bypasses | Operator mode is a UX feature, not a security boundary (see above) |
| LLM provider data handling | Data sent to your configured LLM provider is governed by their policies |
| Playwright MCP behavior | Browser automation via MCP is an integral tool; its actions are classified by the operator tier system |
| Malicious config files | `~/.pensar/config.json` is user-controlled; local modification is not an attack vector |
| Actions on authorized targets | Apex is designed to execute offensive security operations — that is its core function |
| Container privilege escalation | The Kali container intentionally runs with elevated network capabilities |
| Daytona/remote sandbox access | Remote execution sandboxes are opt-in; access is governed by your API keys |

## Scope

This policy applies to the latest version of the project on the `canary` branch.

Thank you for helping keep Apex and its users safe.
