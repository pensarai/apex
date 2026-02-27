# AGENTS.md

## Cursor Cloud specific instructions

### Overview

Pensar Apex is an AI-powered penetration testing CLI tool with a terminal UI (TUI). Single-package TypeScript project using Bun as the runtime and package manager.

### Key commands

| Task | Command |
|------|---------|
| Install deps | `bun install` |
| Dev (watch mode) | `bun run dev` |
| Start TUI directly | `bun run start` |
| Lint | `bun run lint` |
| Format check | `bun run format:check` |
| Type check | `bun run tsc` |
| Unit tests | `bun run test` |
| Build | `bun run build` |

See `package.json` `scripts` for the full list.

### Testing notes

- Unit tests (`src/core/installation/`) and AI stream tests (`src/core/ai/ai.test.ts`) run without API keys.
- Integration tests (`src/tests/auth.test.ts`, `src/tests/attackSurface.test.ts`, `src/core/api/attackSurface.test.ts`) require an `ANTHROPIC_API_KEY` (or other AI provider key) and make real network calls to external services with 2-minute timeouts. They will fail without API credentials.
- Some auth tests also require `TEST_AUTH_USERNAME` and `TEST_AUTH_PASSWORD` environment variables.

### TUI startup flow

On first launch, the TUI shows a "Responsible Use Disclosure" screen that must be accepted (press Enter). After acceptance, if no AI provider API key is configured, it routes to the Provider Manager screen. Config is stored in `~/.pensar/`.

### Environment

- Bun must be on `PATH`. After installing via `curl -fsSL https://bun.sh/install | bash`, add `$HOME/.bun/bin` to PATH.
- No database or Docker required for development or running the TUI.
- AI provider API key (e.g. `ANTHROPIC_API_KEY`) is needed for pentesting features and integration tests, but not for basic TUI operation or unit tests.
