/**
 * Configuration for rate limiting offensive requests
 */
export interface RateLimiterConfig {
  /**
   * Maximum requests per second
   * @default undefined (unlimited)
   */
  requestsPerSecond?: number;
}
