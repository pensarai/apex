# AGENTS.md

## Cursor Cloud specific instructions

### Overview

Pensar Apex is an AI-powered penetration testing CLI tool with a terminal UI (TUI). Single-package TypeScript project using Bun as the runtime and package manager.

### Key commands

| Task               | Command                |
| ------------------ | ---------------------- |
| Install deps       | `bun install`          |
| Dev (watch mode)   | `bun run dev`          |
| Start TUI directly | `bun run start`        |
| Lint               | `bun run lint`         |
| Format check       | `bun run format:check` |
| Type check         | `bun run tsc`          |
| Unit tests         | `bun run test`         |
| Build              | `bun run build`        |

See `package.json` `scripts` for the full list.

### Testing notes

- Unit tests (`src/core/installation/`, `src/core/findings/`, `src/core/credentials/`) and AI stream tests (`src/core/ai/ai.test.ts`) run without API keys.
- Integration tests (`src/tests/auth.test.ts`, `src/tests/attackSurface.test.ts`, `src/core/api/attackSurface.test.ts`) require an `ANTHROPIC_API_KEY` (or other AI provider key) and make real network calls to external services with 2-minute timeouts. They are currently skipped via `describe.skip` because they depend on a live staging server and LLM API calls.
- Some auth tests also require `TEST_AUTH_USERNAME` and `TEST_AUTH_PASSWORD` environment variables.
- Tests use vitest with the `node` environment and a 120-second default timeout (see `vitest.config.ts`).
- When making code changes, always run `bun run test` — all tests should pass (or be skipped) before committing.

### Key directories

- `src/core/agents/` — Agent implementations (auth, attack surface, pentest, offensive security)
- `src/core/ai/` — AI SDK wrappers and streaming utilities
- `src/core/api/` — Public API surface for running agents
- `src/core/credentials/` — Credential management
- `src/core/findings/` — Vulnerability findings registry
- `src/core/session/` — Session management
- `src/tests/` — Integration tests (many require live services)
- `src/tui/` — Terminal UI components

### CI

The CI pipeline (`.github/workflows/ci.yml`) runs these jobs in parallel on every PR and push to `main`/`canary`:

- **Lint** — ESLint + Prettier
- **TypeCheck** — `tsc --noEmit`
- **Test** — `bun run test` (vitest)
- **Build** — full build + smoke test

### TUI startup flow

On first launch, the TUI shows a "Responsible Use Disclosure" screen that must be accepted (press Enter). After acceptance, if no AI provider API key is configured, it routes to the Provider Manager screen. Config is stored in `~/.pensar/`.

### Environment

- Bun must be on `PATH`. After installing via `curl -fsSL https://bun.sh/install | bash`, add `$HOME/.bun/bin` to PATH.
- No database or Docker required for development or running the TUI.
- AI provider API key (e.g. `ANTHROPIC_API_KEY`) is needed for pentesting features and integration tests, but not for basic TUI operation or unit tests.
