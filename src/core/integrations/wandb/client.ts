/**
 * W&B Weave client wrapper.
 *
 * Thin layer over the `weave` npm package. Handles initialization,
 * authentication, and provides traced operations for recording
 * agent step and checkpoint data.
 */

import type { TraceRecord } from "../../agents/offSecAgent/trace";

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

export interface WandbConfig {
  apiKey: string;
  entity: string;
  project: string;
}

export type ResolvedConfig =
  | { available: false }
  | { available: true; config: WandbConfig };

export function resolveConfig(
  overrides?: Partial<WandbConfig>,
): ResolvedConfig {
  const apiKey = overrides?.apiKey ?? process.env.WANDB_API_KEY;
  const entity = overrides?.entity ?? process.env.WANDB_ENTITY;
  const project =
    overrides?.project ?? process.env.WANDB_PROJECT ?? "apex-traces";

  if (!apiKey || !entity) return { available: false };
  return { available: true, config: { apiKey, entity, project } };
}

// ---------------------------------------------------------------------------
// Weave client initialization
// ---------------------------------------------------------------------------

let weaveModule: typeof import("weave") | null = null;
let weaveInitialized = false;

/**
 * Lazily import and initialize the weave SDK.
 * Returns null if weave is not installed or init fails.
 */
async function initWeave(
  config: WandbConfig,
): Promise<typeof import("weave") | null> {
  if (weaveInitialized && weaveModule) return weaveModule;

  try {
    weaveModule = await import("weave");
  } catch {
    // weave not installed — expected in non-W&B environments
    return null;
  }

  try {
    await weaveModule.login(config.apiKey);
    await weaveModule.init(`${config.entity}/${config.project}`);
    weaveInitialized = true;
    return weaveModule;
  } catch (e) {
    console.error("[wandb] Weave init failed:", e);
    weaveModule = null;
    return null;
  }
}

// ---------------------------------------------------------------------------
// Traced operations
// ---------------------------------------------------------------------------

/**
 * Create a traced function that logs a trace record to W&B Weave.
 * Returns null if Weave is not available.
 */
export async function createWeaveTracer(config: WandbConfig): Promise<{
  logRecord: (record: TraceRecord, sessionId: string) => Promise<void>;
  finish: () => Promise<void>;
} | null> {
  const weave = await initWeave(config);
  if (!weave) return null;

  const logTraceRecord = weave.op(
    async (record: TraceRecord, sessionId: string) => {
      return { record, sessionId };
    },
    { name: "apex_trace_record" },
  );

  let logErrorLogged = false;

  return {
    logRecord: async (record: TraceRecord, sessionId: string) => {
      try {
        await logTraceRecord(record, sessionId);
      } catch (e) {
        if (!logErrorLogged) {
          console.error(
            "[wandb] Record upload failed (suppressing future warnings):",
            e,
          );
          logErrorLogged = true;
        }
      }
    },
    finish: async () => {
      try {
        // getGlobalClient is exported by weave but not in the public .d.ts (weave@0.x).
        // Safe to call — returns null if no client is initialized.
        const client = (
          weave as {
            getGlobalClient?: () => {
              waitForBatchProcessing(): Promise<void>;
            } | null;
          }
        ).getGlobalClient?.();
        if (client) {
          await client.waitForBatchProcessing();
        }
      } catch (e) {
        console.error("[wandb] Flush failed:", e);
      }
    },
  };
}
