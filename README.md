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

| Method                          | Command                                              |
| ------------------------------- | ---------------------------------------------------- |
| **Quick Install** (macOS/Linux) | `curl -fsSL https://pensarai.com/install.sh \| bash` |
| **Homebrew**                    | `brew tap pensarai/tap && brew install apex`         |
| **npm**                         | `npm install -g @pensar/apex`                        |
| **Windows** (PowerShell)        | `irm https://www.pensarai.com/apex.ps1 \| iex`       |

## Usage

Open the Apex TUI:

```bash
pensar
```

### Headless CLI

Run pentests without the TUI for scripting, CI, or evalgate integration:

```bash
# Basic pentest
pensar pentest --target https://example.com

# With extended thinking and task-driven mode
pensar pentest --target https://example.com --extended-thinking --task-driven

# Whitebox (with source code access)
pensar pentest --target https://example.com --cwd ./my-app

# Targeted pentest with specific objectives
pensar targeted-pentest --target https://example.com --objective "Test authentication bypass"
```

| Flag                           | Command                   | Description                                    |
| ------------------------------ | ------------------------- | ---------------------------------------------- |
| `--target <url>`               | pentest, targeted-pentest | Target URL (required)                          |
| `--cwd <path>`                 | pentest                   | Source code path for whitebox mode             |
| `--mode <mode>`                | pentest                   | `exfil` for pivoting and flag extraction       |
| `--model <model>`              | pentest, targeted-pentest | AI model (default: auto-selected)              |
| `--extended-thinking`          | pentest                   | Enable extended thinking for supported models  |
| `--task-driven`                | pentest                   | Enable task-driven architecture (experimental) |
| `--prompt <text\|@file>`       | pentest                   | Custom guidance for the agent                  |
| `--threat-model <text\|@file>` | pentest                   | Threat model to guide testing                  |
| `--objective <text>`           | targeted-pentest          | Testing objective (repeatable)                 |

### W&B Weave Tracing

Stream step-level agent traces to Weights & Biases Weave for analysis and fine-tuning:

```bash
export WANDB_API_KEY=your-key
export WANDB_ENTITY=your-entity
# WANDB_PROJECT defaults to "apex-traces"
pensar pentest --target https://example.com
```

Traces include reasoning steps, tool calls, token usage, and state checkpoints. When credentials are not set, tracing is silently disabled.

### OpenTelemetry (Observability)

Apex emits OpenTelemetry spans for agent runs, LLM calls, and tool executions through `@opentelemetry/api`. The spans are **no-ops unless your process registers an OpenTelemetry SDK** as the global tracer provider — Apex itself depends only on the small, vendor-neutral OTel API surface and ships no SDK.

To capture Apex spans in your observability backend, register an SDK before importing Apex code:

- **Sentry**: install `@sentry/node` ≥ 9.27 and add `Sentry.vercelAIIntegration()` to your `Sentry.init` integrations. Sentry's AI Agents Monitoring dashboard classifies the spans automatically.
- **Any OTel-compatible backend** (Honeycomb, Tempo, Datadog, etc.): register `@opentelemetry/sdk-node` with the appropriate OTLP exporter.

Span attributes follow [OTel GenAI semantic conventions](https://opentelemetry.io/docs/specs/semconv/gen-ai/) — no vendor-specific keys leak from Apex.

By default, telemetry captures only span shape (model, token counts, latency, finish reason, tool names). Set `AI_TRACE_RECORD_PAYLOADS=true` to also capture prompts, tool inputs, model outputs, and tool results. Disabled by default so sensitive content stays out of any backend Apex is wired up to.

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
