# Hosted memory backends

Standalone runs store memories under `~/.pensar/memories/` (or the configured
`PENSAR_DATA_DIR`). Hosts can supply durable storage for the existing
`add_memory`, `list_memories`, and `get_memory` tools by wrapping the entire
agent run with `withMemoryBackend` from `src/core/memory`.

```ts
await withMemoryBackend(backend, () => agent.consume());
```

The backend implements `MemoryBackend.add`, `.list`, and `.get`. It returns the
same `Memory` and `MemorySummary` values as filesystem storage. `add` must resolve
only after the write succeeds; rejected operations become failed tool results.
There is no filesystem fallback inside a hosted scope.

The scope follows asynchronous child work, including in-process child agents.
Concurrent runs and nested scopes remain isolated. A separately dispatched process
must establish its own scope. Hosts own authorization, storage partitioning,
validation, filtering, ordering, and idempotency. Each tool forwards its session ID
and SDK tool-call ID in `MemoryOperationContext`; direct memory API callers can
supply that context explicitly. A backend requiring write identity should reject
missing context.

`addMemoryWithId` and `deleteMemory` are filesystem-only operations and throw inside
a hosted scope. Hosted reads should use the backend directly rather than importing
host records into local files. Keep memory tools enabled when hosting them;
`PENSAR_MEMORY_ENABLED` still controls whether agents register those tools.
