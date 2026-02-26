# Code Review: Replace Callbacks with AgentEventBus/AgentRun

| Field       | Value |
|-------------|-------|
| **Date**    | 2026-02-26 16:00:51 UTC |
| **Target**  | Branch `cursor/overall-code-review-dbe9` |
| **Base**    | `canary` |
| **Mode**    | default |
| **Commits** | 11 commits |
| **Files**   | 39 files changed (+1254 / -709) |

---

## Summary Verdict

This is a well-executed architectural refactor that replaces a scattered callback-based event system with a clean, typed `AgentEventBus` + `AgentRun<T>` pattern. The new API is more ergonomic for consumers (`for await` instead of callbacks), properly encapsulates internal streaming mechanics, and includes solid test coverage. The implementation is correct and the migration is thorough. A few minor suggestions below, but nothing blocking.

---

## Findings

### Critical

None.

### Recommendations

**1. Potential memory growth if consumer never iterates** — Should fix, fast follow-up

`src/core/api/agentRun.ts:83-90`

```typescript
private pushEvent(event: AgentEvent): void {
  if (this.waiting) {
    const resolve = this.waiting;
    this.waiting = null;
    resolve({ value: event, done: false });
  } else {
    this.queue.push(event);
  }
}
```

If a consumer accesses `.result` without iterating events (which is a documented use case per the example "Result-only (ignore streaming)"), events queue indefinitely in memory. For short-lived agents this is fine, but long-running agents with high event volume could accumulate significant memory.

**Why it matters:** An agent that streams thousands of text-deltas while a consumer only awaits `.result` will buffer all events unnecessarily.

**Suggestion:** Consider:
1. A bounded queue with backpressure, or
2. An optional "consume silently" mode that discards events when no iterator is active, or
3. Document the memory tradeoff more explicitly in the JSDoc.

This doesn't block the PR — the existing usage patterns (CLI, TUI) always iterate — but it's worth addressing before wider library adoption.

---

**2. Duplicate subagent-spawn emit in `spawnPentestSwarm`** — Should fix, block this PR

`src/core/agents/offSecAgent/tools/spawnPentestSwarm.ts:182-188`

```typescript
childBus?.emit({
  type: "subagent-spawn",
  subagentId,
  input: { target, objectives },
  status: "pending",
});
```

The `subagent-spawn` event is emitted on `childBus` (the child event bus), but by construction, `childBus = ctx.eventBus?.child(subagentId)`, so this event will have `subagentId` auto-tagged as it bubbles to the parent. Meanwhile, the workflow file `pentest.ts:121-129` emits directly on the parent `eventBus`:

```typescript
eventBus?.emit({
  type: "subagent-spawn",
  subagentId,
  input: { ... },
  status: "pending",
});
```

This is correct. But in `spawnPentestSwarm.ts`, emitting on `childBus` causes the `subagentId` to be applied *twice* conceptually (once in the event payload, once via auto-tagging). The auto-tagging won't overwrite an existing `subagentId` (good), but semantically it's inconsistent with how `pentest.ts` does it.

**Suggestion:** Emit `subagent-spawn`/`subagent-complete` on the *parent* bus (`ctx.eventBus`), not the child bus. This matches the pattern in `pentest.ts` and is cleaner. The child bus should only be passed to the agent for its own stream events.

---

**3. Error event type mismatch in `OffensiveSecurityAgent.consume()`** — Should fix, block this PR

`src/core/agents/offSecAgent/offensiveSecurityAgent.ts:175-180`

```typescript
case "error":
  this.eventBus?.emit({
    type: "error",
    error: (chunk as { type: "error"; error: unknown }).error,
  });
  break;
```

This casts `chunk` to extract `.error`, but the AI SDK's `TextStreamPart` type for `"error"` already has the shape `{ type: "error"; error: unknown }`. The cast is redundant but harmless. However, the real issue is that this is the *only* place errors from the underlying stream are surfaced to the event bus. If `streamResult.fullStream` throws (rather than yielding an error chunk), the error won't be emitted — it'll just propagate up as a rejected promise.

This is actually fine given how `AgentRun` handles it (errors propagate to `.result`), but it means consumers iterating events won't receive an `error` event for thrown exceptions — they'll just see iteration end.

**Suggestion:** Consider emitting an error event in a `catch` block wrapping the `for await` loop in `consume()`, so the event stream is consistent regardless of whether errors are chunked or thrown.

---

### Suggestions

**1. Consider exporting `AgentEventBus` from the public API**

`src/core/api/index.ts`

Currently only `AgentRun` and `AgentEvent` are exported. `AgentEventBus` is not. The JSDoc in `AgentRun` says "The internal AgentEventBus is created and managed automatically — consumers never need to import or configure it."

This is a reasonable design choice for simplicity. However, advanced users building custom agent orchestrations might want direct event bus access for inter-agent communication. Consider whether this should be exposed or kept internal — the current design is defensible either way.

---

**2. `cli.ts` could destructure `run.result` inline**

`src/cli.ts:148-149`

```typescript
const { findings, findingsPath, pocsPath, reportPath } = await run.result;
```

This is already clean, but I note the same destructuring pattern is repeated across all consumer sites. If the result shape ever changes, you'll need to update many places. This is fine for now — just noting the coupling.

---

**3. Test helper functions could be shared**

`src/core/api/agentRun.test.ts:9-20` and `src/core/agents/offSecAgent/eventBus.test.ts:10-30`

Both test files define identical `makeTextDelta`, `makeToolCall`, `makeToolResult` helpers. Consider extracting to a shared test utility file to reduce duplication.

---

### Nits

**1.** `src/core/api/agentRun.ts:32` — The private field `error` is stored but never read. It's set in the catch block but the error is just re-thrown. Either remove it or use it for something (e.g., exposing a `.error` getter).

**2.** `src/core/agents/offSecAgent/eventBus.ts:94` — The `handler!` non-null assertion is safe given the overload structure, but could be made type-safer by restructuring the overloads.

---

### Praise

**1. Clean async-iterable design** — The `AgentRun<T>` wrapper provides an excellent developer experience. The dual consumption modes (iterate for streaming, await `.result` for final output) mirror patterns from the Vercel AI SDK and will feel familiar to users.

**2. Thorough test coverage** — 27 tests for `AgentEventBus` and 8 for `AgentRun` cover the core functionality well, including edge cases (empty runs, errors, nested buses, unsubscribe safety).

**3. Backward-compatible migration** — All consumers have been systematically migrated with consistent patterns. The switch statements in consumer code are uniform and readable.

**4. Package exports** — Adding proper `exports` in `package.json` is essential for library consumers. The conditional exports (bun/import/default) are correctly structured.

---

## Questions for the Author

1. **Bounded queue / backpressure**: Is there an expected upper bound on event volume for a single agent run? If agents can produce thousands of events, the unbounded queue in `AgentRun` could become a concern for memory-constrained environments.

2. **Subagent ID collision**: The `pentest-agent-${index}` naming scheme in both `pentest.ts` and `spawnPentestSwarm.ts` could theoretically collide if both code paths run in the same session. Is this intentional isolation, or should there be a global agent counter?

3. **Why is `TextDeltaData` etc. extracted from `TextStreamPart` rather than defined independently?** This creates a tight coupling to the `ai` package's internal types. If the `ai` package changes its `TextStreamPart` shape, these types will silently change too. Is that coupling intentional?
