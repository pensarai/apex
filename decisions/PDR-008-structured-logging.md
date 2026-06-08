# PDR-008: Structured logging with configurable levels

Status: In progress
Companion (Console): `docs/design/structured-logging.md` in `pensarai/console`

## Context

Apex has ~642 raw `console.*` calls and no way to set a debug level. The only
existing logger (`src/core/logger/index.ts`) is **session-bound and file-only**:
it writes to `{session}/logs/agent.log` and is unusable before a session exists
(CLI startup, `doctor`, auth). `PENSAR_DEBUG` gates a little provider debug output,
but there is no leveled, structured diagnostic stream.

Apex runs in two contexts:
1. **CLI** on a developer/operator terminal (a TTY).
2. **Sandbox** launched by Console (Daytona), where stderr/stdout is captured by
   the cluster worker and forwarded to CloudWatch (and Sentry warn/error via the
   worker's console bridge).

Two distinct streams must not be conflated:
- **Agent reasoning / tool output** → the **event bus** (`src/core/eventBus.ts`),
  streamed to the Console UI and persisted to `agent_logs`. **Not** this PDR.
- **Operational / diagnostic logging** (the `console.*` debugging stream) → the
  subject of this PDR.

## Decision

Add a process-wide **structured, leveled logger** for operational/diagnostic
output, decoupled from sessions and from the event bus.

### Module: `src/core/logger/structured.ts`

```ts
type LogLevel = 'debug' | 'info' | 'warn' | 'error' | 'silent';
logger.debug(msg, fields?)   // gated by level
logger.info(msg, fields?)
logger.warn(msg, fields?)
logger.error(msg, errOrFields?, fields?)
logger.child(scope: string)  // prefixes/【scope】tags a subsystem
logger.setLevel(level)
```

- **Level resolution** (first match wins):
  1. `--log-level <level>` / `--verbose` (=debug) / `--quiet` (=warn) CLI flags
  2. `PENSAR_LOG_LEVEL` env (injected by Console `dispatchAgent`)
  3. `PENSAR_DEBUG=1|true` ⇒ `debug` (back-compat alias)
  4. default `info`
- **Output:** one-line JSON `{ts, level, scope, msg, ...fields}` to **stderr**
  when `!process.stderr.isTTY` (sandbox); pretty, colorized when a TTY (CLI).
  `PENSAR_LOG_FORMAT=json|pretty` forces it.
- stderr (not stdout) so diagnostic logging never corrupts any machine-readable
  stdout the CLI emits.

### Preserved
- `writeErrorLog()` (→ `~/.pensar/error.log`) and the session `agent.log` stay for
  back-compat; the new logger may additionally call `writeErrorLog` on `error`.
- The event bus is untouched.

### CLI wiring (`src/cli.ts`)
Parse `--log-level/--verbose/--quiet` early, call `logger.setLevel(...)`, and set
`process.env.PENSAR_LOG_LEVEL` so child processes inherit it.

## Rationale
- Mirrors the existing `PENSAR_*` env + CLI-flag conventions, so it is the env var
  Console already plans to inject (`PENSAR_LOG_LEVEL`).
- JSON-to-stderr makes sandbox logs queryable in CloudWatch with zero extra infra,
  and the cluster worker's existing warn/error→Sentry bridge captures real errors.
- Keeping diagnostic logging off the event bus preserves the clean UI stream.

## Alternatives considered
- **Adopt pino/winston:** heavier; the JSON-to-stderr need is small and we want a
  thin, dependency-light core that runs identically in CLI and sandbox.
- **Extend the file-only logger:** it is session-bound and can't serve CLI/init.
- **Only extend `PENSAR_DEBUG`:** no granular levels; the brief asks for them.

## Consequences
- All ~642 `console.*` calls migrate to `logger.*` (a Biome `noConsole` rule
  enforces it; `bin/`, tests, and intentional user-facing CLI prints are exempted).
- Levels: routine milestones → `debug`/`info`; recoverable issues → `warn`;
  failures → `error`. Noise gets demoted or removed during the audit phase.
- A single resolved level flows Console UI → `PENSAR_LOG_LEVEL` → Apex stderr.
