/**
 * W&B Weave client wrapper.
 *
 * Uses Weave's saveCallStart/saveCallEnd to log trace records
 * as structured calls with top-level fields — not wrapped in
 * a function's inputs.arg0.
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

interface WeaveClient {
  projectId: string;
  saveCallStart(call: {
    project_id: string;
    id?: string | null;
    op_name: string;
    display_name?: string | null;
    trace_id?: string | null;
    parent_id?: string | null;
    started_at: string;
    attributes: object;
    inputs: object;
  }): void;
  saveCallEnd(call: {
    project_id: string;
    id: string;
    ended_at: string;
    output?: unknown;
    summary: Record<string, unknown>;
  }): void;
  waitForBatchProcessing(): Promise<void>;
}

let weaveClient: WeaveClient | null = null;

async function initWeave(config: WandbConfig): Promise<WeaveClient | null> {
  if (weaveClient) return weaveClient;

  let weave: typeof import("weave");
  try {
    weave = await import("weave");
  } catch {
    return null;
  }

  try {
    await weave.login(config.apiKey);
    const client = await weave.init(`${config.entity}/${config.project}`);
    weaveClient = client as unknown as WeaveClient;
    return weaveClient;
  } catch (e) {
    console.error("[wandb] Weave init failed:", e);
    return null;
  }
}

// ---------------------------------------------------------------------------
// Tracer
// ---------------------------------------------------------------------------

export async function createWeaveTracer(config: WandbConfig): Promise<{
  logRecord: (record: TraceRecord, sessionId: string) => void;
  finish: () => Promise<void>;
} | null> {
  const client = await initWeave(config);
  if (!client) return null;

  let logErrorLogged = false;
  let callCounter = 0;

  return {
    logRecord: (record: TraceRecord, sessionId: string) => {
      try {
        const callId = `trace-${sessionId}-${callCounter++}`;
        const now = new Date().toISOString();
        const opName = `weave:///apex/trace/${record.type}`;
        const displayName =
          record.type === "init"
            ? `init:${record.agentId ?? "orchestrator"}`
            : record.type === "checkpoint"
              ? `checkpoint:${record.agentId ?? "orchestrator"}:${record.stepIndex}`
              : `step:${record.agentId ?? "orchestrator"}:${record.stepIndex}`;

        client.saveCallStart({
          project_id: client.projectId,
          id: callId,
          op_name: opName,
          display_name: displayName,
          trace_id: sessionId,
          started_at: now,
          attributes: {
            sessionId,
            agentId: record.agentId,
            recordType: record.type,
          },
          inputs: record as unknown as object,
        });

        client.saveCallEnd({
          project_id: client.projectId,
          id: callId,
          ended_at: now,
          output: null,
          summary: {},
        });
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
        if (weaveClient) {
          await weaveClient.waitForBatchProcessing();
        }
      } catch (e) {
        console.error("[wandb] Flush failed:", e);
      }
    },
  };
}
