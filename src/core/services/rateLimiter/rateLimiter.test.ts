import { describe, expect, it } from "vitest";
import { RateLimiter } from "./index";

describe("RateLimiter", () => {
  it("returns immediately when no rps limit is set", async () => {
    const limiter = new RateLimiter();
    await limiter.acquireSlot();
    expect(limiter.isEnabled()).toBe(false);
  });

  it("reports enabled when rps is set", () => {
    const limiter = new RateLimiter({ requestsPerSecond: 5 });
    expect(limiter.isEnabled()).toBe(true);
  });

  it("unlimited mode never blocks even with many calls", async () => {
    const limiter = new RateLimiter();
    for (let i = 0; i < 100; i++) {
      await limiter.acquireSlot();
    }
  });

  it("enforces rate: two sequential requests at 10 rps take ~100ms", async () => {
    const limiter = new RateLimiter({ requestsPerSecond: 10 });

    const start = performance.now();
    await limiter.acquireSlot();
    await limiter.acquireSlot();
    const elapsed = performance.now() - start;

    // Second slot should wait ~100ms (1000ms / 10 rps).
    // Allow 50–250ms tolerance for CI jitter.
    expect(elapsed).toBeGreaterThanOrEqual(50);
    expect(elapsed).toBeLessThan(250);
  });

  it("first request completes without measurable delay", async () => {
    const limiter = new RateLimiter({ requestsPerSecond: 2 });
    const start = performance.now();
    await limiter.acquireSlot();
    const elapsed = performance.now() - start;
    expect(elapsed).toBeLessThan(50);
  });
});
