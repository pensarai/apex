import type { RateLimiterConfig } from './types';

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
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
   * Acquire a slot for making a request
   * Blocks until a token is available
   * Uses a queue to prevent race conditions from concurrent calls
   */
  async acquireSlot(): Promise<void> {
    // Early exit for unlimited mode - skip all token logic
    if (!this.rps || !this.msPerToken) return;

    // Queue this request to ensure sequential processing
    const previousPromise = this.queue;
    let resolveCurrentRequest: () => void;
    this.queue = new Promise<void>((resolve) => {
      resolveCurrentRequest = resolve;
    });

    // Wait for previous request to complete
    await previousPromise;

    try {
      // Cache now for this call to avoid multiple time calls
      const now = performance.now();
      this.refill(now);

      if (this.tokens < 1) {
        const waitTime = (1 - this.tokens) * this.msPerToken;
        await sleep(waitTime);
        const nowAfterSleep = performance.now();
        this.refill(nowAfterSleep);
      }

      this.tokens -= 1;
    } finally {
      // Signal next request can proceed
      resolveCurrentRequest!();
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
