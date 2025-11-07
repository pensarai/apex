/**
 * Circuit Breaker Pattern Implementation
 *
 * Prevents cascading failures by stopping requests after repeated failures.
 *
 * States:
 * - CLOSED: Normal operation, requests proceed
 * - OPEN: Too many failures, fail fast without trying
 * - HALF_OPEN: Testing recovery, limited requests allowed
 */
export class CircuitBreaker {
  private failures = 0;
  private successes = 0;
  private lastFailureTime = 0;
  private state: "CLOSED" | "OPEN" | "HALF_OPEN" = "CLOSED";

  constructor(
    private options: {
      failureThreshold: number;  // Number of failures before opening
      resetTimeout: number;      // Time to wait before attempting recovery (ms)
      successThreshold: number;  // Number of successes needed to close
    } = {
      failureThreshold: 5,    // Open after 5 failures
      resetTimeout: 60000,    // Try again after 60s
      successThreshold: 2,    // Close after 2 successes
    }
  ) {}

  async execute<T>(fn: () => Promise<T>): Promise<T> {
    // Check if circuit is OPEN
    if (this.state === "OPEN") {
      const now = Date.now();
      const timeSinceLastFailure = now - this.lastFailureTime;

      if (timeSinceLastFailure >= this.options.resetTimeout) {
        console.log("🟡 Circuit breaker: Entering HALF_OPEN state (attempting recovery)");
        this.state = "HALF_OPEN";
      } else {
        const waitTimeSeconds = Math.ceil((this.options.resetTimeout - timeSinceLastFailure) / 1000);
        throw new Error(
          `Circuit breaker is OPEN. Too many failures (${this.failures}). Will retry in ${waitTimeSeconds}s`
        );
      }
    }

    try {
      const result = await fn();

      // Success
      this.onSuccess();
      return result;
    } catch (error) {
      // Failure
      this.onFailure();
      throw error;
    }
  }

  private onSuccess() {
    this.successes++;
    this.failures = 0;

    if (this.state === "HALF_OPEN") {
      if (this.successes >= this.options.successThreshold) {
        console.log("🟢 Circuit breaker: Entering CLOSED state (recovered)");
        this.state = "CLOSED";
        this.successes = 0;
      }
    }
  }

  private onFailure() {
    this.failures++;
    this.successes = 0;
    this.lastFailureTime = Date.now();

    if (this.failures >= this.options.failureThreshold && this.state !== "OPEN") {
      console.error(
        `🔴 Circuit breaker: OPENING circuit after ${this.failures} consecutive failures`
      );
      this.state = "OPEN";
    }
  }

  getState() {
    return {
      state: this.state,
      failures: this.failures,
      successes: this.successes,
      lastFailureTime: this.lastFailureTime,
    };
  }

  reset() {
    this.state = "CLOSED";
    this.failures = 0;
    this.successes = 0;
    this.lastFailureTime = 0;
  }
}
