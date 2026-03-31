/**
 * W&B Trace Upload — streams agent trace records to Weights & Biases
 * via the Weave TypeScript SDK.
 *
 * Usage:
 * ```ts
 * const cleanup = await attachWandbToEventBus(session, eventBus);
 * // ... run agents ...
 * await cleanup?.();
 * ```
 */

import { resolveConfig, createWeaveTracer, type WandbConfig } from "./client";
import type { TraceRecord } from "../../agents/offSecAgent/trace";
import type { AgentEventBus } from "../../eventBus";
import type { SessionInfo } from "../../session";

// ---------------------------------------------------------------------------
// Uploader handle
// ---------------------------------------------------------------------------

export interface WandbUploaderHandle {
  /** Log a trace record to W&B. Weave queues internally. */
  onRecord: (record: TraceRecord) => void;

  /** Flush Weave's internal queue. Call after the agent run finishes. */
  finalize: () => Promise<void>;
}

/**
 * Create a W&B uploader that streams trace records via Weave.
 *
 * Returns null if W&B credentials are not configured or Weave
 * is not available. Async because Weave init is async.
 */
export async function createWandbUploader(
  session: SessionInfo,
  opts?: Partial<WandbConfig>,
): Promise<WandbUploaderHandle | null> {
  const resolved = resolveConfig(opts);
  if (!resolved.available) return null;

  const tracer = await createWeaveTracer(resolved.config);
  if (!tracer) return null;

  return {
    onRecord: (record: TraceRecord) => tracer.logRecord(record, session.id),
    finalize: () => tracer.finish(),
  };
}

/**
 * Attach a W&B uploader to an EventBus. Returns a cleanup function
 * that unsubscribes and flushes, or null if W&B is not configured.
 *
 * Call this BEFORE the agent starts streaming so all trace records
 * (including the orchestrator's init and early steps) are captured.
 */
export async function attachWandbToEventBus(
  session: SessionInfo,
  eventBus: AgentEventBus,
  opts?: Partial<WandbConfig>,
): Promise<(() => Promise<void>) | null> {
  const uploader = await createWandbUploader(session, opts);
  if (!uploader) return null;

  const handler = (e: { record: TraceRecord }) => {
    uploader.onRecord(e.record);
  };
  eventBus.on("trace-record", handler);

  return async () => {
    eventBus.off("trace-record", handler);
    await uploader.finalize();
  };
}
