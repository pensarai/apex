/**
 * Configuration for rate limiting offensive requests
 */
export interface RateLimiterConfig {
  /**
   * Maximum requests per second
   * @default undefined (unlimited)
   */
  requestsPerSecond?: number;
  /** Maximum simultaneous in-flight requests. */
  maxConcurrency?: number;
  /** Token-bucket burst capacity. Defaults to one. */
  burst?: number;
}
