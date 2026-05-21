/**
 * W&B Weave client wrapper.
 *
 * Uses weave.op() to trace records — the stable, documented API.
 * Records appear in Weave with trace data in the inputs field.
 */

import type { TraceRecord } from "../../agents/offSecAgent";
import { writeErrorLog } from "../../logger";

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
// Weave client initialization (single project per process)
// ---------------------------------------------------------------------------

let weaveReady: Promise<typeof import("weave") | null> | null = null;
let cachedConfigKey: string | null = null;

async function initWeave(
  config: WandbConfig,
): Promise<typeof import("weave") | null> {
  const configKey = `${config.entity}/${config.project}`;

  if (weaveReady) {
    if (cachedConfigKey && cachedConfigKey !== configKey) {
      writeErrorLog(
        `initWeave called with ${configKey} but already initialized with ${cachedConfigKey}. Weave supports one project per process.`,
        "WANDB",
      );
    }
    return weaveReady;
  }

  cachedConfigKey = configKey;

  weaveReady = (async () => {
    // Dynamic import hidden from bundler — weave is an optional runtime dependency.
    // The variable prevents bun build --compile from statically resolving it.
    const moduleName = "weave";
    let weave: typeof import("weave");
    try {
      weave = await import(/* @vite-ignore */ moduleName);
    } catch {
      weaveReady = null;
      cachedConfigKey = null;
      return null;
    }

    try {
      await weave.login(config.apiKey);
      await weave.init(configKey);
      return weave;
    } catch (e) {
      writeErrorLog(e, "WANDB");
      weaveReady = null;
      cachedConfigKey = null;
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

  const logTraceRecord = weave.op(
    async (input: { record: TraceRecord; sessionId: string }) => {
      const { record } = input;
      if (record.type === "step") {
        return {
          inputTokens: record.usage.inputTokens,
          outputTokens: record.usage.outputTokens,
          cacheReadTokens: record.usage.cacheReadTokens ?? 0,
          cacheWriteTokens: record.usage.cacheWriteTokens ?? 0,
        };
      }
      if (record.type === "init") {
        return {
          model: record.model,
          toolCount: record.activeTools.length,
        };
      }
      if (record.type === "checkpoint") {
        return {
          confirmedVulns: record.targetState.confirmedVulnerabilities.length,
          blockers: record.blockers.length,
        };
      }
      return null;
    },
    { name: "apex_trace_record" },
  );

  let logErrorLogged = false;

  return {
    logRecord: (record: TraceRecord, sessionId: string) => {
      logTraceRecord({ record, sessionId }).catch((e) => {
        if (!logErrorLogged) {
          writeErrorLog(e, "WANDB_UPLOAD");
          logErrorLogged = true;
        }
      });
    },
    finish: async () => {
      try {
        const getClient = (
          weave as unknown as {
            getGlobalClient?: () => Record<string, unknown> | null;
          }
        ).getGlobalClient;
        if (!getClient) {
          writeErrorLog(
            "getGlobalClient not found — flush skipped. Check weave SDK version.",
            "WANDB",
          );
          return;
        }
        const client = getClient();
        if (client && typeof client.waitForBatchProcessing === "function") {
          await (client.waitForBatchProcessing as () => Promise<void>)();
        }
      } catch (e) {
        writeErrorLog(e, "WANDB_FLUSH");
      }
    },
  };
}
