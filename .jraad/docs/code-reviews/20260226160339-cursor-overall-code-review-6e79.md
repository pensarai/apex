# Code Review: branch `cursor/overall-code-review-6e79`

| Field       | Value |
|-------------|-------|
| **Date**    | 2026-02-26 16:03:39 UTC |
| **Target**  | branch `cursor/overall-code-review-6e79` |
| **Base**    | `canary` |
| **Mode**    | default |
| **Commits** | 11 commits |
| **Files**   | 39 files changed |

---

## Summary verdict

This refactor has a solid direction (typed event stream + `AgentRun` + cleaner API surface), but there are two blocking regressions. One breaks error handling in the pentest TUI flow, and the other breaks package imports for Node consumers. I would not merge this as-is.

## Findings

### Critical

1. **Pentest UI marks runs complete even when the underlying run fails**
   - **Location:** `src/tui/components/pentest/pentest.tsx:498-572` (with `AgentRun` behavior in `src/core/api/agentRun.ts:42-53,63-78`)
   - **What:** The code iterates `for await (const event of run)` and then unconditionally calls `setPhase("completed")`, but never awaits `run.result`.
   - **Why it matters:** `AgentRun` ends iteration when the internal promise finishes, including failure paths. If `run.result` rejects, this code won’t observe it and can report a successful completion state while the run actually failed; it also risks unhandled promise rejections.
   - **Suggestion:** After the loop, `await run.result` and only set completed state after that await succeeds. Keep failure handling in `catch` to set `error`/`phase="error"`.

2. **`package.json` export map points Node import paths at raw TypeScript source**
   - **Location:** `package.json:7-17` (and related publish surface in `package.json:27-31`)
   - **What:** `"import"` and `"default"` export conditions now target `./src/core/api/index.ts` (and `./src/core/session/index.ts`), not built JS artifacts.
   - **Why it matters:** Node consumers importing `@pensar/apex` will hit TS source and fail at runtime (e.g. unresolved extensionless ESM imports from TS files). This makes the package API unusable in standard Node ESM usage.
   - **Suggestion:** Export transpiled JS under `build/` for `import`/`default`, keep a Bun-specific condition if needed, and add `types` mappings or declaration entries for TS consumers.

### Recommendations

1. **AgentRun’s iterator silently hides run failures unless callers remember `.result`**
   - **Location:** `src/core/api/agentRun.ts:43-53,77`
   - **What:** The run error is stored (`this.error = err`) but never surfaced through the async iterator; iteration just ends.
   - **Why it matters:** This API design is easy to misuse (already happened in `pentest.tsx`), causing silent failure modes.
   - **Suggestion:** Consider surfacing errors from the iterator when `done` is reached after a rejection, or provide a helper API that couples event consumption and final result in one awaitable.
   - **Timing:** **Be a fast follow-up** — once the immediate call-site bug is fixed, this should be addressed to prevent repeats.

### Suggestions

1. **Add package-import smoke tests in CI**
   - **Location:** package-level test/CI coverage (no current check seen for this)
   - **What:** There is no automated check that `@pensar/apex` can be imported by Node/Bun using published export paths.
   - **Why it matters:** Export-map regressions like this are easy to introduce and hard to notice until publish/consumer runtime.
   - **Suggestion:** Add a small smoke test that imports the package entrypoints under the intended runtimes.

### Nits

- None.

### Praise

- The migration to a typed event bus is conceptually cleaner than callback threading, and `eventBus.test.ts` plus `agentRun.test.ts` are a good start for regression safety on core stream semantics.

## Questions for the author

1. Is the new package API intended to be Node-consumable, Bun-only, or both?  
   (Current `import/default` export conditions imply Node support but point to TS source.)
2. Was the “iterator ends silently on run rejection” behavior intentional, or an accidental side effect of the `AgentRun` abstraction?
