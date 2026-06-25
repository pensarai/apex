import { describe, expect, it } from "vitest";
import { RateLimiter } from "./index";

describe("RateLimiter", () => {
  it("is a no-op in unlimited mode (no requestsPerSecond)", async () => {
    const rl = new RateLimiter();
    const start = performance.now();
    for (let i = 0; i < 5; i++) await rl.acquireSlot();
    expect(performance.now() - start).toBeLessThan(100);
    expect(rl.isEnabled()).toBe(false);
  });

  it("throttles sequential acquisitions to the configured rate", async () => {
    const rl = new RateLimiter({ requestsPerSecond: 50 }); // 20ms / token
    const start = performance.now();
    await rl.acquireSlot();
    await rl.acquireSlot();
    await rl.acquireSlot();
    // first acquire is free; the next two each wait ~20ms
    expect(performance.now() - start).toBeGreaterThanOrEqual(30);
    expect(rl.isEnabled()).toBe(true);
  });

  it("interrupts an in-flight wait when the signal aborts", async () => {
    const rl = new RateLimiter({ requestsPerSecond: 1 }); // 1000ms / token
    await rl.acquireSlot(); // drain the initial token
    const controller = new AbortController();
    const start = performance.now();
    const pending = rl.acquireSlot(controller.signal); // would wait ~1s
    controller.abort();
    await pending;
    expect(performance.now() - start).toBeLessThan(500);
  });

  it("interrupts a queue wait when the signal aborts before the prior request finishes", async () => {
    const rl = new RateLimiter({ requestsPerSecond: 1 }); // 1000ms / token
    await rl.acquireSlot(); // drain the initial token

    // First queued request — will block for ~1s waiting on a token refill.
    const req1 = rl.acquireSlot();

    // Second queued request sits behind req1 in the FIFO queue.
    const controller = new AbortController();
    const start = performance.now();
    const req2 = rl.acquireSlot(controller.signal);

    // Abort req2 while it's still queued behind req1.
    controller.abort();
    await req2;

    // req2 should return almost immediately — not after req1's full 1s delay.
    expect(performance.now() - start).toBeLessThan(500);

    // req1 must still complete so the queue doesn't deadlock.
    await req1;
  });

  it("keeps the queue flowing for the next request after an abort", async () => {
    const rl = new RateLimiter({ requestsPerSecond: 50 });
    await rl.acquireSlot(); // drain the initial token
    const controller = new AbortController();
    const aborted = rl.acquireSlot(controller.signal);
    controller.abort();
    await aborted;
    const start = performance.now();
    await rl.acquireSlot(); // must not deadlock
    expect(performance.now() - start).toBeLessThan(500);
  });
});
