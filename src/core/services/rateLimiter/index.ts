import type { RateLimiterConfig } from "./types";

function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  if (!signal) return new Promise((resolve) => setTimeout(resolve, ms));
  if (signal.aborted) return Promise.resolve();
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      signal.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    function onAbort() {
      clearTimeout(timer);
      resolve();
    }
    signal.addEventListener("abort", onAbort, { once: true });
  });
}

/**
 * Token bucket rate limiter with queue-based concurrency control
 *
 * Uses a promise queue to ensure requests are processed sequentially,
 * preventing race conditions when multiple requests try to acquire tokens simultaneously.
 *
 * Optimizations:
 * - Uses performance.now() for monotonic clock
 * - Precomputes msPerToken in constructor
 * - Caches now value in acquireSlot
 * - Early returns when bucket is full
 * - Skips all logic in unlimited mode
 *
 * Complexity: O(1) time per request, O(n) space for queue (where n = concurrent requests)
 */
export class RateLimiter {
  private tokens: number;
  private lastRefillTime: number;
  private readonly rps: number | undefined;
  private readonly bucketSize: number;
  private readonly msPerToken: number | undefined;
  private queue: Promise<void>;

  constructor(config?: RateLimiterConfig) {
    this.rps = config?.requestsPerSecond;
    // Bucket size = 1 for strict rate limiting (no bursts)
    // Note: Setting bucketSize = this.rps would allow bursts (e.g., 5 immediate requests for RPS=5)
    // which violates rate limiting in security testing contexts
    this.bucketSize = this.rps ? 1 : 0;
    this.tokens = this.bucketSize;
    this.lastRefillTime = performance.now();
    // Precompute msPerToken once in constructor
    this.msPerToken = this.rps ? 1000 / this.rps : undefined;
    // Initialize promise queue for sequential processing
    this.queue = Promise.resolve();
  }

  /**
   * Acquire a slot, blocking until a token is available (concurrent calls are
   * queued FIFO). If `signal` aborts, the wait is interrupted and no token is
   * consumed — callers must still check the signal afterward.
   */
  async acquireSlot(signal?: AbortSignal): Promise<void> {
    // Early exit for unlimited mode - skip all token logic
    if (!this.rps || !this.msPerToken) return;
    if (signal?.aborted) return;

    // Queue this request to ensure sequential processing
    const previousPromise = this.queue;
    let resolveCurrentRequest: () => void;
    this.queue = new Promise<void>((resolve) => {
      resolveCurrentRequest = resolve;
    });

    // Wait for previous request to complete, or abort early.
    // Without the race, a queued caller would block on previousPromise even
    // after its signal fires — the abort check on the next line would only run
    // once the prior acquisition finishes its full throttle delay.
    if (signal) {
      await Promise.race([
        previousPromise,
        new Promise<void>((resolve) => {
          if (signal.aborted) {
            resolve();
            return;
          }
          signal.addEventListener("abort", () => resolve(), { once: true });
        }),
      ]);
    } else {
      await previousPromise;
    }

    try {
      if (signal?.aborted) return;

      // Cache now for this call to avoid multiple time calls
      const now = performance.now();
      this.refill(now);

      if (this.tokens < 1) {
        const waitTime = (1 - this.tokens) * this.msPerToken;
        await sleep(waitTime, signal);
        if (signal?.aborted) return;
        const nowAfterSleep = performance.now();
        this.refill(nowAfterSleep);
      }

      this.tokens -= 1;
    } finally {
      // Chain on previousPromise so that an abort-induced early exit does not
      // unblock the next waiter before the prior acquisition finishes.
      previousPromise.then(() => resolveCurrentRequest!());
    }
  }

  private refill(now: number): void {
    // Early return if bucket already full - just update time and skip math
    if (this.tokens >= this.bucketSize) {
      this.lastRefillTime = now;
      return;
    }

    const elapsed = now - this.lastRefillTime;
    const tokensToAdd = elapsed / this.msPerToken!;
    this.tokens = Math.min(this.bucketSize, this.tokens + tokensToAdd);
    this.lastRefillTime = now;
  }

  isEnabled(): boolean {
    return this.rps !== undefined;
  }
}

export type { RateLimiterConfig };
