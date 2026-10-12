import { afterEach, describe, expect, it, vi } from "vitest";
import { runDeadline } from "./runDeadline";

afterEach(() => vi.useRealTimers());

describe("recorded-run deadline", () => {
  it("aborts at the absolute deadline and preserves caller cancellation", () => {
    vi.useFakeTimers();
    const parent = new AbortController();
    const deadline = runDeadline(
      new Date(Date.now() + 2000).toISOString(),
      parent.signal,
    );
    vi.advanceTimersByTime(1999);
    expect(deadline.signal?.aborted).toBe(false);
    vi.advanceTimersByTime(1);
    expect(deadline.signal?.aborted).toBe(true);
    expect(deadline.signal?.reason.name).toBe("AbortError");
    deadline.dispose();
    const other = runDeadline(
      new Date(Date.now() + 2000).toISOString(),
      parent.signal,
    );
    parent.abort("operator cancelled");
    expect(other.signal?.reason).toBe("operator cancelled");
    other.dispose();
    expect(vi.getTimerCount()).toBe(0);
  });

  it("expires immediately, disposes pending timers, and bounds long timer delays", () => {
    vi.useFakeTimers();
    expect(
      runDeadline(new Date(Date.now() - 1).toISOString()).signal?.aborted,
    ).toBe(true);
    const deadline = runDeadline(
      new Date(Date.now() + 3_000_000_000).toISOString(),
    );
    vi.advanceTimersByTime(2_147_483_647);
    expect(deadline.signal?.aborted).toBe(false);
    expect(vi.getTimerCount()).toBe(1);
    deadline.dispose();
    expect(vi.getTimerCount()).toBe(0);
  });
});
