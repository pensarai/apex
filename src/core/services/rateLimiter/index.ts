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
  private readonly maxConcurrency: number | undefined;
  private readonly msPerToken: number | undefined;
  private queue: Promise<void>;
  private activeRequests = 0;
  private capacityWaiters: Array<() => void> = [];

  constructor(config?: RateLimiterConfig) {
    this.rps = config?.requestsPerSecond;
    this.bucketSize = this.rps
      ? Math.max(1, Math.floor(config?.burst ?? 1))
      : 0;
    this.maxConcurrency = config?.maxConcurrency
      ? Math.max(1, Math.floor(config.maxConcurrency))
      : undefined;
    this.tokens = this.bucketSize;
    this.lastRefillTime = performance.now();
    // Precompute msPerToken once in constructor
    this.msPerToken = this.rps ? 1000 / this.rps : undefined;
    // Initialize promise queue for sequential processing
    this.queue = Promise.resolve();
  }

  /**
   * Acquire a slot, blocking until a token is available (concurrent calls are
   * queued FIFO). Returns `true` when a token was consumed, `false` when the
   * call exited early (unlimited mode, signal already aborted, or abort during
   * wait). Callers should only {@link releaseSlot} when this returns `true`.
   */
  async acquireSlot(signal?: AbortSignal): Promise<boolean> {
    // Early exit for unlimited mode - skip all token logic
    if (!this.rps || !this.msPerToken) return false;
    if (signal?.aborted) return false;

    // Queue this request to ensure sequential processing
    const previousPromise = this.queue;
    let resolveCurrentRequest: () => void;
    this.queue = new Promise<void>((resolve) => {
      resolveCurrentRequest = resolve;
    });

    // Wait for previous request to complete, or abort early.
    // Without the race, a queued caller would block on previousPromise even
    // after its signal fires — the abort check below would only run once the
    // prior acquisition finishes its full throttle delay.
    let onAbort: (() => void) | undefined;
    if (signal) {
      const abortPromise = new Promise<void>((resolve) => {
        if (signal.aborted) {
          resolve();
          return;
        }
        onAbort = () => resolve();
        signal.addEventListener("abort", onAbort, { once: true });
      });
      await Promise.race([previousPromise, abortPromise]);
      if (onAbort && !signal.aborted) {
        signal.removeEventListener("abort", onAbort);
      }
    } else {
      await previousPromise;
    }

    // When the abort won the race, previousPromise may still be pending.
    // Resolving our queue slot immediately would let the next waiter enter
    // token logic concurrently with the still-running prior request, breaking
    // FIFO serialization.  Chain the resolution to previousPromise instead.
    let chainedResolution = false;

    let acquired = false;

    try {
      if (signal?.aborted) {
        chainedResolution = true;
        return false;
      }

      while (
        this.maxConcurrency !== undefined &&
        this.activeRequests >= this.maxConcurrency
      ) {
        await new Promise<void>((resolve) => {
          const wake = () => {
            signal?.removeEventListener("abort", wake);
            resolve();
          };
          this.capacityWaiters.push(wake);
          signal?.addEventListener("abort", wake, { once: true });
        });
        if (signal?.aborted) return false;
      }

      // Cache now for this call to avoid multiple time calls
      const now = performance.now();
      this.refill(now);

      if (this.tokens < 1) {
        const waitTime = (1 - this.tokens) * this.msPerToken;
        await sleep(waitTime, signal);
        if (signal?.aborted) return false;
        const nowAfterSleep = performance.now();
        this.refill(nowAfterSleep);
      }

      this.tokens -= 1;
      this.activeRequests += 1;
      acquired = true;
      return true;
    } finally {
      if (chainedResolution) {
        previousPromise.then(() => resolveCurrentRequest!());
      } else {
        resolveCurrentRequest!();
      }
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

  releaseSlot(): void {
    if (!this.rps) return;
    this.activeRequests = Math.max(0, this.activeRequests - 1);
    this.capacityWaiters.shift()?.();
  }

  isEnabled(): boolean {
    return this.rps !== undefined;
  }
}

export type { RateLimiterConfig };
