import type { RateLimiterConfig } from './types';

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Token bucket rate limiter with optimal time/space efficiency
 *
 * Optimizations:
 * - Uses performance.now() for monotonic clock
 * - Precomputes msPerToken in constructor
 * - Caches now value in acquireSlot
 * - Early returns when bucket is full
 * - Skips all logic in unlimited mode
 *
 * Complexity: O(1) time, O(1) space
 */
export class RateLimiter {
  private tokens: number;
  private lastRefillTime: number;
  private readonly rps: number | undefined;
  private readonly bucketSize: number;
  private readonly msPerToken: number | undefined;

  constructor(config?: RateLimiterConfig) {
    this.rps = config?.requestsPerSecond;
    this.bucketSize = this.rps || 0;
    this.tokens = this.bucketSize;
    this.lastRefillTime = performance.now();
    // Precompute msPerToken once in constructor
    this.msPerToken = this.rps ? 1000 / this.rps : undefined;
  }

  /**
   * Acquire a slot for making a request
   * Blocks until a token is available
   */
  async acquireSlot(): Promise<void> {
    // Early exit for unlimited mode - skip all token logic
    if (!this.rps || !this.msPerToken) return;

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

export { RateLimiterConfig };
