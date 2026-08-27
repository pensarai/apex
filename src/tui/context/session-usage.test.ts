import { describe, expect, it, vi } from "vitest";
import { SessionUsageStore } from "./session-usage";

// ---------------------------------------------------------------------------
// SessionUsageStore
// ---------------------------------------------------------------------------

describe("SessionUsageStore", () => {
  it("new session: starts empty, accumulates tokens and context", () => {
    const store = new SessionUsageStore();
    store.enterSession("ses_a");

    expect(store.getSnapshot("ses_a").tokenUsage.inputTokens).toBe(0);
    expect(store.getSnapshot("ses_a").contextUsage).toBeNull();

    store.addSessionTokens("ses_a", {
      inputTokens: 100,
      outputTokens: 20,
      cacheReadTokens: 80,
    });
    store.setRootContext("ses_a", {
      modelId: "claude-sonnet-4-5",
      usedTokens: 10_000,
      contextLimit: 200_000,
    });

    const snap = store.getSnapshot("ses_a");
    expect(snap.tokenUsage.inputTokens).toBe(100);
    expect(snap.contextUsage).toMatchObject({ usedTokens: 10_000 });
  });

  it("switching sessions resets the view, not the other session's totals", () => {
    const store = new SessionUsageStore();
    store.enterSession("ses_a");
    store.addSessionTokens("ses_a", { inputTokens: 100, outputTokens: 10 });

    store.enterSession("ses_b");
    expect(store.activeSessionId).toBe("ses_b");
    expect(store.getSnapshot("ses_b").tokenUsage.inputTokens).toBe(0);

    // Session A keeps its totals — switching did not reset it.
    expect(store.getSnapshot("ses_a").tokenUsage.inputTokens).toBe(100);

    // Late events still account into their originating session.
    store.addSessionTokens("ses_a", { inputTokens: 50 });
    expect(store.getSnapshot("ses_a").tokenUsage.inputTokens).toBe(150);
    expect(store.getSnapshot("ses_b").tokenUsage.inputTokens).toBe(0);
  });

  it("multiple runs in the same session accumulate — never reset", () => {
    const store = new SessionUsageStore();
    store.enterSession("ses_a");

    // Run 1
    store.addSessionTokens("ses_a", { inputTokens: 100, outputTokens: 10 });
    // Run 2 re-enters the same session (remount, new runAgent call)
    store.enterSession("ses_a");
    store.addSessionTokens("ses_a", { inputTokens: 40, outputTokens: 5 });

    const usage = store.getSnapshot("ses_a").tokenUsage;
    expect(usage.inputTokens).toBe(140);
    expect(usage.outputTokens).toBe(15);
  });

  it("resume: enterSession seeds a tracked session exactly once", () => {
    const store = new SessionUsageStore();
    const seed = {
      tokenUsage: {
        inputTokens: 1000,
        outputTokens: 200,
        cacheReadTokens: 900,
        cacheWriteTokens: 50,
      },
      contextUsage: {
        modelId: "claude-sonnet-4-5",
        usedTokens: 42_000,
        contextLimit: 200_000,
      },
    };
    store.enterSession("ses_a", seed);
    expect(store.getSnapshot("ses_a").tokenUsage.inputTokens).toBe(1000);
    expect(store.getSnapshot("ses_a").contextUsage?.usedTokens).toBe(42_000);

    // A later re-entry with a different seed must NOT clobber live totals.
    store.addSessionTokens("ses_a", { inputTokens: 10 });
    store.enterSession("ses_a", {
      tokenUsage: {
        inputTokens: 99_999,
        outputTokens: 0,
        cacheReadTokens: 0,
        cacheWriteTokens: 0,
      },
      contextUsage: null,
    });
    expect(store.getSnapshot("ses_a").tokenUsage.inputTokens).toBe(1010);
  });

  it("untracked session reads are empty and writes are dropped", () => {
    const store = new SessionUsageStore();
    expect(store.getSnapshot("nope").tokenUsage.inputTokens).toBe(0);
    expect(() =>
      store.addSessionTokens("nope", { inputTokens: 5 }),
    ).not.toThrow();
    expect(store.getSnapshot("nope").tokenUsage.inputTokens).toBe(0);
  });

  it("subscribers fire on changes to their session only", () => {
    const store = new SessionUsageStore();
    store.enterSession("ses_a");
    store.enterSession("ses_b");

    const aListener = vi.fn();
    const bListener = vi.fn();
    store.subscribe("ses_a", aListener);
    store.subscribe("ses_b", bListener);

    store.addSessionTokens("ses_a", { inputTokens: 1 });
    expect(aListener).toHaveBeenCalledTimes(1);
    expect(bListener).not.toHaveBeenCalled();

    store.setRootContext("ses_b", {
      modelId: "m",
      usedTokens: 1,
      contextLimit: 10,
    });
    expect(aListener).toHaveBeenCalledTimes(1);
    expect(bListener).toHaveBeenCalledTimes(1);
  });

  it("zero-value steps do not fire subscribers (identical state)", () => {
    const store = new SessionUsageStore();
    store.enterSession("ses_a");
    const listener = vi.fn();
    store.subscribe("ses_a", listener);

    store.addSessionTokens("ses_a", {});
    expect(listener).not.toHaveBeenCalled();
  });

  it("snapshot references are stable across unrelated updates", () => {
    const store = new SessionUsageStore();
    store.enterSession("ses_a");
    store.enterSession("ses_b");

    const before = store.getSnapshot("ses_a");
    store.addSessionTokens("ses_b", { inputTokens: 1 });
    expect(store.getSnapshot("ses_a")).toBe(before);
  });

  it("forgetSession drops state and deactivates it", () => {
    const store = new SessionUsageStore();
    store.enterSession("ses_a");
    store.addSessionTokens("ses_a", { inputTokens: 5 });

    store.forgetSession("ses_a");
    expect(store.activeSessionId).toBeNull();
    expect(store.getSnapshot("ses_a").tokenUsage.inputTokens).toBe(0);

    // Re-entering after forgetting starts fresh.
    store.enterSession("ses_a");
    expect(store.getSnapshot("ses_a").tokenUsage.inputTokens).toBe(0);
  });

  it("entering the already-active session does not re-emit", () => {
    const store = new SessionUsageStore();
    store.enterSession("ses_a");
    const listener = vi.fn();
    store.subscribe("ses_a", listener);

    store.enterSession("ses_a");
    expect(listener).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// Provisional bucket + active view
// ---------------------------------------------------------------------------

describe("SessionUsageStore provisional + active view", () => {
  it("tokens recorded before a session exists seed the first entered session", () => {
    const store = new SessionUsageStore();
    // Brand-new session: first steps fire before onSessionReady mints the id.
    store.addSessionTokens(null, { inputTokens: 100, outputTokens: 10 });
    store.addSessionTokens(null, { cacheReadTokens: 90 });

    store.enterSession("ses_new");
    const usage = store.getSnapshot("ses_new").tokenUsage;
    expect(usage.inputTokens).toBe(100);
    expect(usage.outputTokens).toBe(10);
    expect(usage.cacheReadTokens).toBe(90);

    // Provisional bucket is drained — a second new session starts empty.
    store.enterSession("ses_next");
    expect(store.getSnapshot("ses_next").tokenUsage.inputTokens).toBe(0);
  });

  it("an explicit seed wins over the (empty) provisional bucket on resume", () => {
    const store = new SessionUsageStore();
    store.enterSession("ses_resumed", {
      tokenUsage: {
        inputTokens: 1000,
        outputTokens: 200,
        cacheReadTokens: 900,
        cacheWriteTokens: 50,
      },
    });
    expect(store.getSnapshot("ses_resumed").tokenUsage.inputTokens).toBe(1000);
  });

  it("active snapshot follows session switches", () => {
    const store = new SessionUsageStore();
    store.enterSession("ses_a");
    store.addSessionTokens("ses_a", { inputTokens: 5 });
    expect(store.getActiveSnapshot().tokenUsage.inputTokens).toBe(5);

    store.enterSession("ses_b");
    expect(store.getActiveSnapshot().tokenUsage.inputTokens).toBe(0);

    store.enterSession("ses_a");
    expect(store.getActiveSnapshot().tokenUsage.inputTokens).toBe(5);
  });

  it("active subscribers fire on active-session changes and switches", () => {
    const store = new SessionUsageStore();
    store.enterSession("ses_a");
    const listener = vi.fn();
    store.subscribeActive(listener);

    store.addSessionTokens("ses_a", { inputTokens: 1 });
    expect(listener).toHaveBeenCalledTimes(1);

    // Non-active session changes do not fire the active view.
    store.enterSession("ses_b");
    store.addSessionTokens("ses_a", { inputTokens: 1 });
    expect(listener).toHaveBeenCalledTimes(2); // switch fired once

    // Provisional updates fire the active view (it displays the bucket).
    store.addSessionTokens(null, { inputTokens: 1 });
    expect(listener).toHaveBeenCalledTimes(3);
  });
});
