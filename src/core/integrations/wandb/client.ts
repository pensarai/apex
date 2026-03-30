/**
 * W&B Weave client wrapper.
 *
 * Uses weave.op() to trace records — the stable, documented API.
 * Records appear in Weave with trace data in the inputs field.
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

let weaveReady: Promise<typeof import("weave") | null> | null = null;

async function initWeave(
  config: WandbConfig,
): Promise<typeof import("weave") | null> {
  if (weaveReady) return weaveReady;

  weaveReady = (async () => {
    let weave: typeof import("weave");
    try {
      weave = await import("weave");
    } catch {
      return null;
    }

    try {
      await weave.login(config.apiKey);
      await weave.init(`${config.entity}/${config.project}`);
      return weave;
    } catch (e) {
      console.error("[wandb] Weave init failed:", e);
      return null;
    }
  })();

  return weaveReady;
}

// ---------------------------------------------------------------------------
// Tracer
// ---------------------------------------------------------------------------

export async function createWeaveTracer(config: WandbConfig): Promise<{
  logRecord: (record: TraceRecord, sessionId: string) => void;
  finish: () => Promise<void>;
} | null> {
  const weave = await initWeave(config);
  if (!weave) return null;

  // weave.op() is the stable API — wraps an async function and logs
  // its inputs/output as a traced call in the Weave dashboard.
  const logTraceRecord = weave.op(
    async (record: TraceRecord, sessionId: string) => {
      const base = {
        recorded: true,
        type: record.type,
        agentId: record.agentId,
        sessionId,
      };

      if (record.type === "step") {
        return {
          ...base,
          stepIndex: record.stepIndex,
          usage: record.usage,
          cumulativeUsage: record.cumulativeUsage,
          inputTokens: record.usage.inputTokens,
          outputTokens: record.usage.outputTokens,
          cumulativeInputTokens: record.cumulativeUsage.inputTokens,
          cumulativeOutputTokens: record.cumulativeUsage.outputTokens,
          stepDurationMs: record.stepDurationMs,
          elapsedMs: record.elapsedMs,
          toolsCalled: record.actions.map((a) => a.toolName),
          summarized: record.summarized,
        };
      }

      return base;
    },
    { name: "apex_trace_record" },
  );

  let logErrorLogged = false;

  return {
    logRecord: (record: TraceRecord, sessionId: string) => {
      try {
        // Fire-and-forget — weave.op returns a promise but queues internally.
        // We don't await to avoid blocking the trace writer.
        void logTraceRecord(record, sessionId);
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
        const getClient = (
          weave as unknown as {
            getGlobalClient?: () => {
              waitForBatchProcessing(): Promise<void>;
            } | null;
          }
        ).getGlobalClient;
        const client = getClient?.();
        if (client) {
          await client.waitForBatchProcessing();
        }
      } catch (e) {
        console.error("[wandb] Flush failed:", e);
      }
    },
  };
}
