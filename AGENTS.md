# AGENTS.md

## Working in this repo

### Overview

Pensar Apex is an AI-powered penetration testing CLI tool with a terminal UI (TUI). Single-package TypeScript project using Bun as the runtime and package manager.

For the rationale behind every major product and architecture decision (why TUI, why `/pentest` vs `/operator`, why the swarm/sub-agent architecture, etc.), see **[decisions/](./decisions/index.md)**. When proposing new features or making architectural decisions, consult these records to ensure changes align with the product direction.

### Working principles

Bias to caution over speed on non-trivial work. Use judgment on trivial tasks.

**Think before coding.** State assumptions. If uncertain, ask. Present alternatives when ambiguous. Stop when confused — name what's unclear.

**Simplicity first.** Minimum code that solves the problem. No speculative abstractions. Would a senior engineer call this overcomplicated? Then simplify.

**Rule of three.** First time, just write it. Second time, hold your nose and repeat. Third time, extract. Two similar things aren't enough signal to know what the right abstraction is.

**Surgical changes.** Touch only what you must. Don't "improve" adjacent code, comments, or formatting. Don't refactor what isn't broken. Match existing style.

**Separate refactoring from feature work.** A change is either "make existing code better" or "add new behavior" — not both. If you need to refactor to land a feature cleanly, ship the refactor first.

**Don't accumulate tech debt.** Solve today's problem in a way that won't trap tomorrow's solver. Pick the abstraction that fits and avoid shortcuts that compound silently.

**Short-term fixes are okay if surfaced.** Sometimes a focused patch is the right call, not a migration — that's valid. But name what shortcut was taken and what the long-term path looks like, and ask whether to open a GitHub issue to track it.

**Goal-driven execution.** Define success, loop until verified. Don't blindly follow steps.

**Use the model only for judgment calls.** Classification, drafting, summarization, extraction. Not routing, retries, deterministic transforms. If code can answer, code answers.

**Surface conflicts, don't average them.** Two contradicting patterns? Pick one (more recent / more tested). Explain why. Flag the other for cleanup. Don't blend.

**Read before you write.** Read exports, immediate callers, shared utilities before adding code. "Looks orthogonal" is dangerous.

**Tests verify intent, not just behavior.** A test that can't fail when the business rule changes is wrong.

**Checkpoint after every significant step.** Summarize what's done, what's verified, what's left. If you lose track, stop and restate.

**Match the codebase's conventions, even if you disagree.** Conformance > taste. If a convention seems harmful, surface it — don't fork silently.

**Avoid verbose comments.** Code should speak for itself — well-named identifiers and small functions beat prose. If context is genuinely non-obvious (a hidden constraint, a workaround, surprising behavior), a brief one-liner is fine. Don't narrate what the code does or write multi-paragraph docstrings. The full standard is `.agents/skills/code-comments/SKILL.md`.

**Fail loud.** "Completed" is wrong if anything was silently skipped. Default to surfacing uncertainty.

### Closing the loop

At the end of a non-trivial session, reflect on what surfaced — surprises, recurring corrections, near-misses, missing guardrails, shortcuts you flagged. If anything stands out, propose a concrete way to prevent or address it next time:

- An entry in this `AGENTS.md` (a new gotcha, working principle, or convention).
- A new skill or slash command that codifies the workflow.
- A CI/CD check (lint rule, custom script, test) that catches the class of mistake automatically.
- A GitHub issue for follow-ups that won't land now — long-term refactors, the un-taken path behind a short-term fix, guardrails to consider.

Prefer the cheapest mechanism that actually closes the gap — a CI gate beats a written rule, a written rule beats hoping you remember. If a fix can land in this PR, propose it; otherwise, ask whether to open an issue so the follow-up stays visible. Don't ship the change without confirmation.

The bar is: future agents shouldn't hit the same wall. Trust compounds when guardrails do.

### Key commands

| Task                             | Command                |
| -------------------------------- | ---------------------- |
| Install deps                     | `bun install`          |
| Dev (watch mode)                 | `bun run dev`          |
| Start TUI directly               | `bun run start`        |
| Lint                             | `bun run lint`         |
| Lint (auto-fix)                  | `bun run lint:fix`     |
| Format check                     | `bun run format:check` |
| Format (write)                   | `bun run format`       |
| Lint + format + organize imports | `bun run check`        |
| Type check                       | `bun run tsc`          |
| Unit tests                       | `bun run test`         |
| Build                            | `bun run build`        |

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

- **Lint** — Biome (lint + format + organize imports for JS/TS/JSON/CSS) + Prettier (Markdown/YAML only)
- **TypeCheck** — `tsc --noEmit`
- **Test** — `bun run test` (vitest)
- **Build** — full build + smoke test
- **zizmor** — static analysis of the workflows themselves

### GitHub Actions — pinned to a commit SHA

A tag such as `@v4` can be repointed by whoever controls the action's repository, and the next run then executes their code with this repository's release credentials. So nothing a workflow runs is referenced by a movable name. The `zizmor` job in `.github/workflows/ci.yml` enforces this on every PR (config: `.github/zizmor.yml`).

- **Actions are pinned to a full commit SHA with the full version in a comment**: `uses: owner/repo@<40-character SHA> # v4.2.2`. This includes GitHub's own `actions/*`. The comment must be the release the SHA belongs to (`# v4` is rejected); upgrade tooling and the advisory check read the version from it.
- **Container images** (`container:`, `services.*.image`, `docker://`) carry a digest: `name:tag@sha256:<digest>`.
- **Find the SHA from the release tag**: `gh api repos/<owner>/<repo>/git/ref/tags/<tag> --jq .object`. When `.type` is `tag`, follow it with `gh api repos/<owner>/<repo>/git/tags/<sha> --jq .object.sha`. Pin a release that has been out for at least 7 days.
- **Reach for `gh` or a few lines of shell before adding a third-party action.** Every action is code that runs with the job's token.
- **Check locally** with `zizmor --pedantic .` (`brew install zizmor`). Set `GH_TOKEN` to include the checks that need the GitHub API.
- **Permissions start empty.** Every workflow sets `permissions: {}`, and each job lists only what it uses. Each write, `id-token` or non-`contents` grant carries a comment saying what needs it: `contents: write # creates the release and its tag`.
- **Expressions never go inside a script.** Pass `${{ … }}` values to `run:` steps through `env:` and quote them (`"$VERSION"`). Default variables like `$GITHUB_EVENT_NAME` and `$GITHUB_SHA` are already in the environment.
- **Checkouts set `persist-credentials: false`** unless a later step runs git against the remote. Prefer `gh api` or `gh release` for tags and releases, which need no saved credential.
- **In-repo actions and workflows use the self-repository form**, `uses: $/.github/workflows/build.yml`, not `./`. An action that runs files from the checkout stays `./`, with an inline ignore saying why.
- **CI workflows set a `concurrency` group** that cancels superseded PR runs. A release or publish workflow uses a group that queues instead of cancelling.
- **Never disable an audit or add an ignore to get a check green.** Each ignore in `.github/zizmor.yml` or inline `# zizmor: ignore[...]` comment says why the finding is safe. A new one needs the same, and a review. Otherwise fix the finding, or ask.

### Dependencies — exact versions

`bun.lock` pins what CI installs. `package.json` pins what we ask for: every version is exact, so a version only changes when a diff says so. A range such as `^1.2.3` lets `bun add <pkg>`, `bun update` or a regenerated lockfile pull a release nobody chose, and a compromised release arrives the same way. `bun run check:dependency-pins` enforces this in the CI lint job.

- **Versions are exact**: `"left-pad": "1.3.0"`, never `^`, `~`, `*`, `latest` or a tag. This covers `dependencies`, `devDependencies`, `optionalDependencies` and `overrides`. `bun add <pkg>` writes an exact version because `bunfig.toml` sets `exact = true`; do not remove that setting.
- **The one exception is a package in this repository's own workspace**, which is referenced with `workspace:*`. The check rejects an exact version there, because `*` and version numbers also match a same-named package on the public registry. There are no workspace packages today.
- **`peerDependencies` stay ranges.** They describe what a consumer may bring, not what we install.
- **This package is published.** Everyone who installs it gets its `dependencies` at exactly these versions, so keep them few, and ship a release when one of them needs a security fix.
- **To change a version**, edit it (or `bun add <pkg>@<version>`), run `bun install`, and read the `bun.lock` diff: it should show that package and what it pulled in, nothing else.
- **Do not work around the release-age gate.** `bunfig.toml` refuses packages published too recently (`minimumReleaseAge`). If an install fails on it, pick an older version; do not lower the setting or add an exclusion without asking.
- **Before adding a dependency**, check that a few lines of our own code would not do, that the package is maintained and widely used, and whether it runs an install script. Bun runs install scripts only for trusted packages. With no `trustedDependencies` in `package.json`, as here today, those are the packages on Bun's built-in default list (`bun pm default-trusted`). Defining `trustedDependencies` replaces that list, so the first time one is added, also list every default-trusted package we still need. A trusted package runs code on every machine that installs, so say why in the PR.
- **Run tools from the lockfile**: after `bun install`, `bunx <tool>` runs the installed, pinned version of a package we depend on. If the package is not installed, `bunx` downloads whatever version is current, so install first or name the version (`bunx <tool>@<version>`). Do not `bunx` or `npx` a package that is not in `bun.lock`.

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

**Scrollbars.** Don't pass `scrollbarOptions={{ visible: true }}` — opentui auto-shows the bar when content overflows the viewport and hides it otherwise. Forcing `visible: true` paints a full-track thumb when content fits, which reads as a stray colored block. Style with `trackOptions: { foregroundColor: colors.textMuted, backgroundColor: colors.backgroundElement }` so the thumb stays subtle and theme-aware (don't use `colors.primary` — too loud). Never explicitly hide scrollbars in scrollable regions.

### Code hygiene

**Clean up dead code.** When removing a feature or command, delete all associated code paths — route entries, component files, registry entries. Don't leave orphaned code "in case we need it later."

**Use typed enumerations.** Finite sets (command categories, provider types, agent phases) must use TypeScript union types or enums, not free-form strings. This catches invalid values at compile time and keeps ordering/grouping explicit.

### Barrel files

**Module barrels, not folder barrels.** A directory has an `index.ts` if and only if it is a _module_ — a cohesive unit with a deliberate public API. Internal files of a module are private; cross-module imports must go through the barrel.

Two-question test before adding (or keeping) an `index.ts`:

1. Does the directory have a public API distinct from its internals?
2. Is there a stable, intentional set of exports the module commits to?

If both answers are "yes", keep the barrel. If either is "no", don't — import individual files directly.

Anti-patterns:

- **Folder barrels** — `index.ts` re-exporting unrelated siblings just because they share a directory. Adds noise, hides nothing.
- **Half-bypassed barrels** — barrel exists; some callers use it, others reach past it. Pick one direction per module.
- **Mixed-direction imports** — same file imports both `from "./mod"` and `from "./mod/internals"`. Never. One direction per dependency edge.

Enforced via the `import-x/no-internal-modules` ESLint rule in `eslint.config.js`. The `forbid` list there is the source of truth for which directories are kept module barriers — adding a new kept barrel means adding a new entry to that list. Test files (`*.test.ts`) are exempt.

`src/cli.ts`'s `await import("./core/api/<feature>")` calls are a documented exception (see header comment in `src/core/api/index.ts`): they stay direct so `bun build --splitting` produces per-feature chunks.

### Skills

Team-shared development-agent skills live at `.agents/skills/<name>/`. Use `/create-skill` to add a new one. Developer-only skills (PR workflow, code comments) intentionally remain there: Apex scans `.claude/skills`, `.skills`, `skills`, `~/.agents/skills`, and `~/.pensar/skills` as runtime skill sources.

Before pull-request or merge-request work, read and follow `.agents/skills/pr/SKILL.md` (`/pr` in coding agents that discover repo `.agents` skills). It covers creating or updating PRs, preserving stack topology and formatting, babysitting CI, handling review or Bugbot findings, resolving conflicts, and performing explicitly authorized merges. The skill is the source of truth for the workflow; verify live GitHub state and operate on the latest head SHA.

When writing or editing comments, JSDoc, or TODOs, read and follow `.agents/skills/code-comments/SKILL.md` (`/code-comments` in coding agents that discover repo `.agents` skills). Comment only what the code cannot say; do not narrate mechanics or add ceremony.

### Gotchas

- **Every acquire needs a release on every path.** Streams, subprocesses, intervals, and listeners should be disposed on the error path too, not just the happy path — `finally` or `AbortSignal` are usually the cleanest way.
