# Pensar Apex

<p align="center">
  <img src="screenshot.png" alt="Pensar Apex Screenshot" width="800">
</p>

**Pensar Apex** is an AI-powered penetration testing CLI tool that enables you to use an AI agent to perform comprehensive black box testing.

## Quick Start

### Prerequisites

- **Bun** v1.0+ (required - [install from bun.sh](https://bun.sh))
- **Anthropic API Key** (get one at [console.anthropic.com](https://console.anthropic.com/))

### Installation

#### Install Bun First

If you don't have Bun installed:

```bash
curl -fsSL https://bun.sh/install | bash
```

#### Option 1: Global Installation (Recommended)

```bash
# Install globally with bun
bun install -g @pensar/apex

# Or with npm (still requires bun to run)
npm install -g @pensar/apex
```

#### Option 2: Local Development

```bash
# Clone the repository
git clone https://github.com/your-org/apex.git
cd apex

# Install dependencies
npm install
# or
bun install

# Build the project
npm run build
# or
bun run build
```

### Configuration

Set your Anthropic API key as an environment variable:

```bash
export ANTHROPIC_API_KEY="your-api-key-here"
```

To make it permanent, add it to your shell profile (`~/.bashrc`, `~/.zshrc`, etc.):

```bash
echo 'export ANTHROPIC_API_KEY="your-api-key-here"' >> ~/.zshrc
source ~/.zshrc
```

## Usage

### Running Pensar

If installed globally:

```bash
pensar
```

If running locally:

```bash
npm start
# or
bun start
```
