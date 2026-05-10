import { describe, expect, it, vi } from "vitest";
import {
  createSubagentSessionHelpers,
  createSubagentStore,
  SUBAGENT_STATUS_ORDER,
  type SubagentSession,
} from "./subagent-state";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function makeSession(
  overrides: Partial<SubagentSession> & { id: string },
): SubagentSession {
  return {
    name: overrides.id,
    status: "running",
    spawnedAt: new Date("2025-01-01T00:00:00Z"),
    input: null,
    messages: [],
    ...overrides,
  };
}

/**
 * Inline copy of the sort logic from subagent-hub.tsx to avoid importing
 * React/TUI components in a pure Node test.
 */
function sortSessions(sessions: SubagentSession[]): SubagentSession[] {
  return [...sessions].sort((a, b) => {
    const statusDiff =
      SUBAGENT_STATUS_ORDER[a.status] - SUBAGENT_STATUS_ORDER[b.status];
    if (statusDiff !== 0) return statusDiff;
    return a.spawnedAt.getTime() - b.spawnedAt.getTime();
  });
}

// ---------------------------------------------------------------------------
// sortSessions — order stability
// ---------------------------------------------------------------------------

describe("sortSessions", () => {
  it("sorts running before completed", () => {
    const sessions = [
      makeSession({ id: "b", status: "completed" }),
      makeSession({ id: "a", status: "running" }),
    ];
    const sorted = sortSessions(sessions);
    expect(sorted.map((s) => s.id)).toEqual(["a", "b"]);
  });

  it("sorts by spawnedAt within same status", () => {
    const sessions = [
      makeSession({
        id: "b",
        status: "running",
        spawnedAt: new Date("2025-01-02"),
      }),
      makeSession({
        id: "a",
        status: "running",
        spawnedAt: new Date("2025-01-01"),
      }),
    ];
    const sorted = sortSessions(sessions);
    expect(sorted.map((s) => s.id)).toEqual(["a", "b"]);
  });

  it("preserves order for identical sessions", () => {
    const sessions = [
      makeSession({ id: "a", status: "running" }),
      makeSession({ id: "b", status: "running" }),
    ];
    const sorted1 = sortSessions(sessions);
    const sorted2 = sortSessions(sessions);
    expect(sorted1.map((s) => s.id)).toEqual(sorted2.map((s) => s.id));
  });
});

// ---------------------------------------------------------------------------
// Store — snapshot identity changes on every update
//
// This documents the mechanism behind the scroll-to-top bug: every log
// update produces a new Map reference, which causes
// `useMemo(() => sortSessions(…), [sessions])` to recompute `sorted`.
//
// Before the fix, the SubagentHub scroll effect depended on `sorted`,
// meaning every log update re-triggered scrollToIndex. With focusedIndex
// at 0 (the default), scrollToIndex calls scrollBox.scrollTo(0), forcing
// the list to the top.
//
// The fix uses a ref for sorted so the scroll effect only fires when
// focusedIndex changes (user navigation).
// ---------------------------------------------------------------------------

describe("SubagentStore snapshot identity", () => {
  it("produces a new snapshot reference on appendText", () => {
    const store = createSubagentStore();
    const helpers = createSubagentSessionHelpers(store.setState);

    helpers.spawnSession("s1", "Agent 1");
    const snap1 = store.getSnapshot();

    helpers.appendText("s1", "hello");
    const snap2 = store.getSnapshot();

    expect(snap1).not.toBe(snap2);
  });

  it("produces a new snapshot reference on every appendText call", () => {
    const store = createSubagentStore();
    const helpers = createSubagentSessionHelpers(store.setState);

    helpers.spawnSession("s1", "Agent 1");

    const snapshots: Map<string, SubagentSession>[] = [];
    for (let i = 0; i < 5; i++) {
      helpers.appendText("s1", `token-${i}`);
      snapshots.push(store.getSnapshot());
    }

    for (let i = 1; i < snapshots.length; i++) {
      expect(snapshots[i]).not.toBe(snapshots[i - 1]);
    }
  });

  it("notifies subscribers on every update", () => {
    const store = createSubagentStore();
    const helpers = createSubagentSessionHelpers(store.setState);
    const listener = vi.fn();

    store.subscribe(listener);
    helpers.spawnSession("s1", "Agent 1");
    helpers.appendText("s1", "a");
    helpers.appendText("s1", "b");

    expect(listener).toHaveBeenCalledTimes(3);
  });

  it("sorted array reference changes on every log even when order is stable", () => {
    const store = createSubagentStore();
    const helpers = createSubagentSessionHelpers(store.setState);

    helpers.spawnSession("s1", "Agent 1");
    helpers.spawnSession("s2", "Agent 2");

    const snap1 = store.getSnapshot();
    const sorted1 = sortSessions(Array.from(snap1.values()));

    helpers.appendText("s1", "some log output");

    const snap2 = store.getSnapshot();
    const sorted2 = sortSessions(Array.from(snap2.values()));

    // Order is identical — both agents are still "running" with same spawnedAt
    expect(sorted1.map((s) => s.id)).toEqual(sorted2.map((s) => s.id));
    // But the array is a new reference, which would trigger a useEffect
    // that depends on it
    expect(sorted1).not.toBe(sorted2);
  });
});
