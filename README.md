<h1 align="center">Pensar Apex</h1>

<p align="center">
AI-powered penetration testing using autonomous agents — directly in your terminal. Run blackbox and whitebox pentests that explore, reason, and surface real vulnerabilities.

</p>

<p align="center">
Want to run from the cloud or integrate it with your CI/CD? See <a href="https://docs.pensar.dev/console">Pensar Console</a>.
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/@pensar/apex"><img src="https://img.shields.io/npm/v/@pensar/apex?label=latest" alt="npm version"></a>
  <a href="https://www.npmjs.com/package/@pensar/apex"><img src="https://img.shields.io/npm/v/@pensar/apex/canary?label=prerelease&color=yellow" alt="npm prerelease version"></a>
  <!-- <a href="https://www.npmjs.com/package/@pensar/apex"><img src="https://img.shields.io/npm/dm/@pensar/apex" alt="npm downloads"></a> -->
  <a href="./LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue" alt="Apache 2.0 License"></a>
  <a href="https://docs.pensar.dev/apex"><img src="https://img.shields.io/badge/docs-docs.pensar.dev/apex-purple?logo=readthedocs&logoColor=white" alt="Documentation"></a>
  <a href="https://discord.gg/pensar"><img src="https://img.shields.io/badge/Discord-Join%20Us-5865F2?logo=discord&logoColor=white" alt="Discord"></a>
</p>

<!-- <p align="center">
  <img src="screenshot.png" alt="Pensar Apex Screenshot" width="800">
</p> -->
## What is Apex?

Apex is an autonomous penetration testing agent that runs directly in your terminal.

It doesn't wrap existing scanners or chain shell scripts. Apex deploys a **swarm of specialized AI agents** — each with domain expertise in reconnaissance, authentication analysis, exploitation, and code review — that coordinate a real penetration test against your application. Each agent follows a structured methodology: plan, verify, prepare, test, exploit, and document. Every finding comes with CVSS 4.0 scoring, CWE classification, evidence, and a validated proof-of-concept.

The result is a pentest that runs like `npm test` — but thinks like a red team.

## Why Apex?

Traditional scanners execute signatures. Apex executes a methodology.

- **Swarm architecture** - Specialized agents run in parallel across your attack surface, the same way a real red team divides and conquers. Up to 10 concurrent agents, each scoped to a specific objective.
- **Structured, auditable output** - Every vulnerability is automatically scored (CVSS 4.0), classified (CWE), and documented with evidence and remediation steps. No raw tool dumps.
- **Real exploitation, not guesswork** - Apex writes, runs, and validates proof-of-concept scripts. If the PoC doesn't succeed, it pivots to a different technique.
- **Blackbox and whitebox** - Test a live target with no source access, or analyze your codebase to map endpoints and test them against a running instance.
- **30+ built-in tools** - Browser automation, shell execution, HTTP requests, file analysis, web search for CVE lookups, authenticated crawling, and more. Optional Kali Linux container adds 25+ offensive security tools (nmap, sqlmap, hydra, hashcat, gobuster, and others).

## Two Modes

### `/pentest` — Autonomous

Fire and forget. Apex runs a full engagement end-to-end: attack surface discovery, parallel swarm testing, and a structured report with findings in Markdown and JSON. No security expertise required.

### `/operator` — Interactive

Full control. Steer the agent step by step, approve each action, chain exploits manually, and dig deep into specific targets. Every tool is available. The approval gate holds until you say go.

Start with `/pentest` to get coverage, then reopen the session in `/operator` to investigate specific findings — all context carries over.

## Use Cases

### Developers
- Run `/pentest` before merging a PR — catch vulnerabilities as naturally as running tests
- Get actionable findings with severity scores, evidence, and suggested fixes — no security background needed
- Integrate into CI/CD via headless CLI commands or Pensar Console

### Security Engineers
- Deploy agent-driven swarm testing across large attack surfaces
- Use `/operator` mode for manual investigation, exploit chaining, and validation
- Automate repetitive testing workflows with persistent memory that accumulates across engagements
- Scale across teams and projects through Pensar Console


## Installation

#### macOS / Linux (Quick Install)

```bash
curl -fsSL https://pensarai.com/install.sh | bash
```

#### Homebrew

```bash
brew tap pensarai/tap
brew install apex
```

#### npm

```bash
npm install -g @pensar/apex
```

#### Windows (PowerShell)

```powershell
irm https://www.pensarai.com/apex.ps1 | iex
```


## Usage

Open the Apex TUI:

```bash
pensar
```

## Kali Linux Container (Optional)

For **best performance**, run Apex in the included Kali Linux container with preconfigured pentest tools:

```bash
cd container
cp env.example .env  # add your API keys
docker compose up --build -d
docker compose exec kali-apex bash
```

Inside the container, run:

```bash
pensar
```

---

### ⚠️ Responsible Use

This repository contains tools for **authorized security testing** only.  
Before use, please read and agree to the [Responsible Use Disclosure](./RESPONSIBLE_USE.md).
