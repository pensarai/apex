# AGENTS.md

## Cursor Cloud specific instructions

### Overview

Pensar Apex is an AI-powered penetration testing CLI tool with a terminal UI (TUI). Single-package TypeScript project using Bun as the runtime and package manager.

For the rationale behind every major product and architecture decision (why TUI, why `/pentest` vs `/operator`, why the swarm/sub-agent architecture, etc.), see **[decisions/](./decisions/index.md)**. When proposing new features or making architectural decisions, consult these records to ensure changes align with the product direction.

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
- `src/core/auth/` — Centralized Pensar Console authentication (device flow, tokens, HMAC signing, workspaces)
- `src/core/credentials/` — Credential management
- `src/core/findings/` — Vulnerability findings registry
- `src/core/session/` — Session management
- `src/cli/` — Headless CLI commands (auth, uninstall)
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

### UI/UX conventions

**Reuse shared components.** Before building inline UI for controls, indicators, or dialog chrome, check `src/tui/components/shared/` for existing components. If you see the same pattern implemented inline in 2+ places, extract it into a shared component rather than duplicating it — duplication is how conventions silently diverge.

**Dialog shortcut controls.** Use the `DialogControls` component (`src/tui/components/shared/dialog-controls.tsx`) for keyboard hint bars at the bottom of dialogs. It supports three variants: `default` (muted — for secondary actions), `primary` (bright — for the main CTA), and `danger` (red — for irreversible actions like Delete/Disconnect). Ordering: primary action first, secondary actions next, danger actions after, Esc always last. `[Esc] Close` is rendered automatically by the `Dialog` component's top-right chrome — don't add it to the controls array. Only show non-obvious shortcuts; intuitive actions like ↑/↓ navigation don't need hints. Key capitalization: Title Case for named keys (`Enter`, `Esc`, `Tab`), uppercase for single letters (`D`, `R`, `M`), arrows as `↑/↓`.

**Consistency over novelty.** When adding a new dialog or view, match the patterns of existing ones. Don't invent new shortcut formatting, separator styles, color schemes, or layouts. Open a few existing dialogs as reference before starting — small inconsistencies compound quickly across a codebase.

**Dialogs, not routes.** Commands that show supplementary information (settings, model selection, help, credits, skills) must open as dialog overlays, not full-page route navigation. Full-page routes break the user's context and are reserved for primary workflows (pentest, operator mode). Use the `DialogLayout` component for consistent structure.

**Terminal size resilience.** Layouts must degrade gracefully on small terminals. All text containers must set `overflow="hidden"`. Fixed-height elements (headers, footers, control bars) must use `flexShrink={0}`. Use terminal dimensions (`stdout.columns`, `stdout.rows`) to compute available space and hide non-essential decorative elements (animations, verbose help text) when space is tight. Never assume a minimum terminal size.

**Theme-aware colors.** All color values must respect the current `ColorMode` (dark/light). Never hardcode RGBA values for a single theme. Use dual-palette maps keyed by `ColorMode` (see `syntax-highlight.ts` for the pattern). This applies to syntax highlighting, status indicators, and any styled text output.

**Stable React keys.** Never include mutable content (message text, streaming output) in React `key` props. Use stable identifiers like `role + timestamp`, tool call IDs, or array indices. Content-derived keys cause unmount/remount on every frame during streaming, which resets scroll position and causes visual flicker.

**No state toggling in streaming callbacks.** Avoid calling `setState` to toggle visual indicators (like "Thinking...") directly in high-frequency streaming callbacks (`onTextDelta`, `onToolCallStreaming`). This causes per-frame flicker. Instead, derive display state from the underlying data model (e.g., check if the last message is a tool result rather than toggling a boolean).

**Scrollbar visibility.** Scrollable content (lists, logs, long text) must have `scrollbarOptions={{ visible: true }}` so users can see their scroll position. Never hide scrollbars in scrollable regions.

### Code hygiene

**Clean up dead code.** When removing a feature or command, delete all associated code paths — route entries, component files, registry entries. Don't leave orphaned code "in case we need it later."

**Use typed enumerations.** Finite sets (command categories, provider types, agent phases) must use TypeScript union types or enums, not free-form strings. This catches invalid values at compile time and keeps ordering/grouping explicit.
