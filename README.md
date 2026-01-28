<h1 align="center">Pensar Apex</h1>

<p align="center">
  <a href="https://www.npmjs.com/package/@pensar/apex"><img src="https://img.shields.io/npm/v/@pensar/apex?label=latest" alt="npm version"></a>
  <a href="https://www.npmjs.com/package/@pensar/apex"><img src="https://img.shields.io/npm/v/@pensar/apex/canary?label=prerelease&color=yellow" alt="npm prerelease version"></a>
  <!-- <a href="https://www.npmjs.com/package/@pensar/apex"><img src="https://img.shields.io/npm/dm/@pensar/apex" alt="npm downloads"></a> -->
  <a href="https://github.com/pensarai/homebrew-tap"><img src="https://img.shields.io/github/v/release/pensarai/apex?label=homebrew&logo=homebrew&color=orange" alt="Homebrew"></a>
  <a href="./LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue" alt="Apache 2.0 License"></a>
  <a href="https://docs.pensar.dev/apex"><img src="https://img.shields.io/badge/docs-docs.pensar.dev/apex-purple?logo=readthedocs&logoColor=white" alt="Documentation"></a>
</p>

<p align="center">
  <img src="screenshot.png" alt="Pensar Apex Screenshot" width="800">
</p>

**Pensar Apex** is an AI-powered penetration testing CLI tool that enables you to use an AI agent to perform comprehensive black box testing.

## Installation

### Prerequisites

- **API Key** for your chosen AI provider

#### Optional: Install nmap (recommended)

The AI agent uses nmap for network reconnaissance. Install it for full scanning capabilities:

<details>
<summary>Installation instructions</summary>

**macOS:**
```bash
brew install nmap
```

**Debian/Ubuntu:**
```bash
sudo apt-get update && sudo apt-get install -y nmap
```

**Fedora/RHEL:**
```bash
sudo dnf install -y nmap
```

**Windows:**
Download installer from https://nmap.org/download.html and ensure `nmap` is on your PATH.

</details>

### Install Apex

#### macOS / Linux (Quick Install)

```bash
curl -fsSL https://pensarai.com/install.sh | bash
```

#### Homebrew

```bash
brew tap pensarai/tap
brew install apex
```

#### Windows (PowerShell)

```powershell
irm https://pensarai.com/apex.ps1 | iex
```

#### npm

```bash
npm install -g @pensar/apex
```

### Configuration

Set your AI provider API key as an environment variable:

```bash
export ANTHROPIC_API_KEY="your-api-key-here"
# or for other providers:
# export OPENAI_API_KEY="your-api-key-here"
# export AWS_ACCESS_KEY_ID="..." and AWS_SECRET_ACCESS_KEY="..."
```

## Usage

### Interactive Mode

Run Apex interactively:

```bash
pensar
```

### Programmatic API

Apex provides a programmatic API for integration into your security testing workflows.

#### Blackbox Pentest

Test a target without source code access. The AI performs full attack surface mapping, endpoint enumeration, and vulnerability testing:

```typescript
import { runBlackboxPentest } from '@pensar/apex/api';

const result = await runBlackboxPentest({
  target: 'https://example.com',
  model: 'claude-sonnet-4-5',
  concurrency: 10,
  callbacks: {
    onPhaseChange: (phase) => console.log('Phase:', phase),
    onSubagentStart: (id, endpoint, vulnClass) =>
      console.log(`Testing ${vulnClass} on ${endpoint}`),
    onFindingDiscovered: (finding) =>
      console.log(`Found: [${finding.severity}] ${finding.title}`),
  },
});

console.log(`Findings: ${result.findings.length}`);
```

**How Blackbox Mode Works:**

1. **Enumeration Phase** (optional): Runs katana + feroxagent to discover endpoints
2. **Attack Surface Mapping**: AI agent explores the target, documents endpoints, parameters, and authentication
3. **Orchestrator Phase**: Analyzes attack surface and spawns targeted sub-agents
4. **Testing Phase**: Sub-agents test for vulnerabilities across all discovered endpoints

**Input Options:**

| Field | Type | Description |
|-------|------|-------------|
| `target` | `string` | Target URL or domain |
| `model` | `AIModel` | AI model (default: `claude-sonnet-4-5`) |
| `concurrency` | `number` | Max parallel sub-agents (default: 10) |
| `skipEnumeration` | `boolean` | Skip katana+feroxagent enumeration |
| `callbacks` | `PentestCallbacks` | Event callbacks |
| `authCredentials` | `AuthCredentials?` | Authentication credentials |
| `scopeConstraints` | `ScopeConstraints?` | Limit testing scope |
| `blockedPaths` | `string[]?` | Paths to block from agent access |
| `blockDocker` | `boolean?` | Block Docker commands |
| `sessionId` | `string?` | Resume existing session |
| `sessionName` | `string?` | Custom session name |
| `timeout` | `number?` | Sub-agent timeout in ms (default: 20 min) |

**Phases:**

| Phase | Description |
|-------|-------------|
| `enumeration` | Running katana + feroxagent endpoint discovery |
| `attack-surface` | AI mapping endpoints, parameters, auth flows |
| `orchestrator` | Analyzing attack surface, planning sub-agents |
| `testing` | Sub-agents actively testing for vulnerabilities |

**Resume a Session:**

```typescript
import { resumePentest } from '@pensar/apex/api';

const result = await resumePentest({
  sessionId: 'pentest-abc123',
  model: 'claude-sonnet-4-5',
  callbacks: { /* ... */ },
});
```

#### Whitebox Pentest

Test a specific endpoint with source code access. The AI orchestrator analyzes your source code to intelligently determine which vulnerability classes to test:

```typescript
import { runWhiteboxPentest } from '@pensar/apex/api';

const result = await runWhiteboxPentest({
  endpoint: 'http://localhost:3000/api/users/:id',
  sourceCodePath: '/path/to/your/source',
  model: 'claude-sonnet-4-5',
  callbacks: {
    onPhaseChange: (phase) => console.log('Phase:', phase),
    onSubagentStart: (id, endpoint, vulnClass) =>
      console.log(`Testing ${vulnClass} on ${endpoint}`),
    onFindingDiscovered: (finding) =>
      console.log(`Found: [${finding.severity}] ${finding.title}`),
  },
});

console.log(`Findings: ${result.findings.length}`);
```

**How Whitebox Mode Works:**

1. The AI orchestrator analyzes your source code using pattern matching and code search
2. It locates route handlers, controllers, and related files for your target endpoint
3. It identifies vulnerability patterns in the code (SQL queries, exec calls, file operations, etc.)
4. It spawns targeted sub-agents only for vulnerabilities with evidence in the code
5. Each sub-agent tests for its assigned vulnerability class with full source code context

### CLI Script

For direct command-line usage:

```bash
# Blackbox pentest
bun run scripts/pentest.ts https://example.com

# Whitebox pentest (single endpoint with source code)
bun run scripts/pentest.ts http://localhost:3000/api/users \
  --whitebox \
  --source-path /path/to/source \
  --focus /api/users/:id

# With options
bun run scripts/pentest.ts https://example.com \
  --model claude-sonnet-4-5 \
  --concurrency 10 \
  --verbose
```

**CLI Options:**

| Option | Description |
|--------|-------------|
| `--model <model>` | AI model to use (default: claude-sonnet-4-5) |
| `--whitebox` | Enable whitebox mode with source code access |
| `--source-path <path>` | Path to source code (required with --whitebox) |
| `--workspace <name>` | Workspace name for memory |
| `--focus <endpoint>` | Focus testing on a specific endpoint |
| `--concurrency <n>` | Max parallel sub-agents (default: 10) |
| `--skip-attack-surface` | Skip attack surface mapping phase |
| `--skip-enum` | Skip katana+feroxagent enumeration |
| `--verbose` | Show detailed output |
| `--quiet` | Minimal output |
| `--block-source <path>` | Block access to path (for sandboxing) |
| `--block-docker` | Block Docker commands |

## AI Provider Support

Apex supports **OpenAI**, **Anthropic**, **AWS Bedrock**, and **vLLM** (local models). **Anthropic models provide the best performance** and are recommended for optimal results.

## Kali Linux Container (Recommended)

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

**Note:** On Linux hosts, consider using `network_mode: host` in `docker-compose.yml` for comprehensive network scanning.

## vLLM Local Model Support

To use a local vLLM server:

1. Set the vLLM endpoint:

```bash
export LOCAL_MODEL_URL="http://localhost:8000/v1"
```

2. In the Apex Models screen, enter your model name in the "Custom local model (vLLM)" input.

---

### ⚠️ Responsible Use

This repository contains tools for **authorized security testing** only.  
Before use, please read and agree to the [Responsible Use Disclosure](./RESPONSIBLE_USE.md).
