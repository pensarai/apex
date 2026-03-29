/**
 * W&B Trace Upload — streams agent trace records to Weights & Biases
 * via the Weave TypeScript SDK.
 *
 * Usage:
 * ```ts
 * const uploader = await createWandbUploader(session);
 * if (uploader && eventBus) {
 *   eventBus.on("trace-record", (e) => uploader.onRecord(e.record));
 *   // Call uploader.finalize() after run completes
 * }
 * ```
 */

import { resolveConfig, createWeaveTracer } from "./client";
import type { TraceRecord } from "../../agents/offSecAgent/trace";
import type { SessionInfo } from "../../session";

// ---------------------------------------------------------------------------
// Uploader handle
// ---------------------------------------------------------------------------

export interface WandbUploaderHandle {
  /** Log a trace record to W&B. Called from EventBus subscription. */
  onRecord: (record: TraceRecord) => void;

  /**
   * Finalize: flush all pending records to W&B.
   * Call after the agent run finishes.
   */
  finalize: () => Promise<void>;
}

export interface WandbUploaderOpts {
  apiKey?: string;
  entity?: string;
  project?: string;
}

/**
 * Create a W&B uploader that streams trace records via Weave.
 *
 * Returns null if W&B credentials are not configured or Weave
 * is not available. Async because Weave init is async.
 */
export async function createWandbUploader(
  session: SessionInfo,
  opts?: WandbUploaderOpts,
): Promise<WandbUploaderHandle | null> {
  const resolved = resolveConfig(opts);
  if (!resolved.available) return null;

  const t = await createWeaveTracer(resolved.config);
  if (!t) return null;
  const logRecord = t.logRecord;
  const finish = t.finish;

  // Chain promises so finalize() can await all in-flight records
  let pending = Promise.resolve();

  function onRecord(record: TraceRecord): void {
    pending = pending.then(() => logRecord(record, session.id));
  }

  async function finalize(): Promise<void> {
    await pending;
    await finish();
  }

  return { onRecord, finalize };
}
