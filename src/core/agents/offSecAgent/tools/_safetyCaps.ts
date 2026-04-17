import type { AgentEventBus } from "../../../eventBus";

/**
 * Safety caps for an agent run — shared across every HTTP-emitting tool in
 * the test-case workflow. Cap violations don't crash the run; they return
 * an error to the calling tool (so the agent can adapt) and emit an
 * `alert_raised` detection event with source='rule-engine' so the user sees
 * the enforcement in the run log.
 */
export interface SafetyCapsConfig {
  /** Maximum sustained requests-per-second to a single target host. */
  rpsPerHost: number;
  /** Maximum total HTTP requests across the entire run. */
  totalRequests: number;
  /** Wall-clock deadline in milliseconds. */
  wallClockMs: number;
  /**
   * Optional event bus — when present, cap violations fire an
   * `alert_raised` detection event so the user sees them in the run log.
   */
  eventBus?: AgentEventBus;
}

export interface SafetyCapState {
  readonly config: SafetyCapsConfig;
  readonly startedAt: number;
  /** Total requests counted against the run-wide budget. */
  totalRequests: number;
  /** Per-host token-bucket state: `host → { tokens, lastRefillMs }`. */
  readonly hostBuckets: Map<string, { tokens: number; lastRefillMs: number }>;

  /**
   * Check caps before firing an outbound request. Returns `null` if the
   * request is allowed. Returns a reason string if it must be denied —
   * callers should surface that to the agent and emit an `alert_raised`
   * detection event.
   */
  checkAndConsume(host: string): Promise<null | SafetyCapViolation>;
}

export interface SafetyCapViolation {
  reason: "rate_limit_host" | "total_requests" | "wall_clock";
  host?: string;
  message: string;
  retryAfterMs?: number;
}

/**
 * Build a fresh safety-cap state for a run. Pass the same object to every
 * HTTP-emitting tool via `ToolContext.safetyCaps`.
 */
export function createSafetyCapState(config: SafetyCapsConfig): SafetyCapState {
  const state = {
    config,
    startedAt: Date.now(),
    totalRequests: 0,
    hostBuckets: new Map<string, { tokens: number; lastRefillMs: number }>(),
  };

  const emitViolation = (v: SafetyCapViolation): void => {
    config.eventBus?.emit("detection_event", {
      kind: "alert_raised",
      severity: "low",
      source: "rule-engine",
      summary: `[safety-cap] ${v.message}`,
      data: {
        reason: v.reason,
        host: v.host,
        retryAfterMs: v.retryAfterMs,
        elapsedMs: Date.now() - state.startedAt,
        totalRequests: state.totalRequests,
      },
    });
  };

  const refill = (host: string): { tokens: number; lastRefillMs: number } => {
    const now = Date.now();
    const existing = state.hostBuckets.get(host);
    if (!existing) {
      const fresh = { tokens: config.rpsPerHost, lastRefillMs: now };
      state.hostBuckets.set(host, fresh);
      return fresh;
    }
    const elapsedSec = (now - existing.lastRefillMs) / 1000;
    const refilled = Math.min(
      config.rpsPerHost,
      existing.tokens + elapsedSec * config.rpsPerHost,
    );
    existing.tokens = refilled;
    existing.lastRefillMs = now;
    return existing;
  };

  return {
    ...state,
    checkAndConsume: async (host: string) => {
      // Wall-clock deadline
      const elapsed = Date.now() - state.startedAt;
      if (elapsed >= config.wallClockMs) {
        const v: SafetyCapViolation = {
          reason: "wall_clock",
          message: `Run deadline reached (${(config.wallClockMs / 1000).toFixed(0)}s). No further HTTP requests allowed.`,
        };
        emitViolation(v);
        return v;
      }

      // Run-wide total cap
      if (state.totalRequests >= config.totalRequests) {
        const v: SafetyCapViolation = {
          reason: "total_requests",
          message: `Per-run HTTP request cap reached (${config.totalRequests}). No further outbound requests allowed.`,
        };
        emitViolation(v);
        return v;
      }

      // Per-host token bucket
      const bucket = refill(host);
      if (bucket.tokens < 1) {
        const retryAfterMs = Math.ceil(
          (1 - bucket.tokens) * (1000 / config.rpsPerHost),
        );
        const v: SafetyCapViolation = {
          reason: "rate_limit_host",
          host,
          message: `Per-host rate limit hit for ${host} (max ${config.rpsPerHost} RPS). Back off ~${retryAfterMs}ms.`,
          retryAfterMs,
        };
        emitViolation(v);
        return v;
      }

      // Consume
      bucket.tokens -= 1;
      state.totalRequests += 1;
      return null;
    },
  };
}

/**
 * Extract the bare hostname from a URL for safety-cap bucketing. Falls
 * back to the original string when the URL can't be parsed.
 */
export function hostnameFor(url: string): string {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return url;
  }
}
