<h1 align="center">Pensar Apex</h1>

<p align="center">AI-powered penetration testing tool that enables you to use an AI agent to perform comprehensive blackbox and whitebox pentesting - directly in your terminal.
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/@pensar/apex"><img src="https://img.shields.io/npm/v/@pensar/apex?label=latest" alt="npm version"></a>
  <a href="https://www.npmjs.com/package/@pensar/apex"><img src="https://img.shields.io/npm/v/@pensar/apex/canary?label=prerelease&color=yellow" alt="npm prerelease version"></a>
  <!-- <a href="https://www.npmjs.com/package/@pensar/apex"><img src="https://img.shields.io/npm/dm/@pensar/apex" alt="npm downloads"></a> -->
  <a href="./LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue" alt="Apache 2.0 License"></a>
  <a href="https://docs.pensar.dev/apex"><img src="https://img.shields.io/badge/docs-docs.pensar.dev/apex-purple?logo=readthedocs&logoColor=white" alt="Documentation"></a>
  <a href="https://discord.gg/pensar"><img src="https://img.shields.io/badge/Discord-Join%20Us-5865F2?logo=discord&logoColor=white" alt="Discord"></a>
</p>

<p align="center">
  <img src="screenshot.png" alt="Pensar Apex Screenshot" width="800">
</p>

## Installation

### Prerequisites

- **API Key** for your chosen AI provider

After installing, run `pensar doctor` to check for optional dependencies (like nmap) and install them.

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
export OPENAI_API_KEY="your-api-key-here"
export OPENROUTER_API_KEY="your-api-key-here"

# AWS Bedrock (bearer token auth):
export BEDROCK_API_KEY="your-bearer-token"
export AWS_REGION="us-east-1"

# AWS Bedrock (IAM credentials):
export AWS_ACCESS_KEY_ID="..."
export AWS_SECRET_ACCESS_KEY="..."
export AWS_SESSION_TOKEN="..."  # optional, for temporary credentials
export AWS_REGION="us-east-1"
```

## Usage

Run Apex:

```bash
pensar
```

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
