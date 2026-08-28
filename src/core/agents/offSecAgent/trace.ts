/**
 * Structured Step Trace — append-only per-step JSONL log.
 *
 * Each line in trace.jsonl is either a {@link StepRecord} (type: "step")
 * or a {@link StateCheckpoint} (type: "checkpoint"). Together they form
 * a {@link TraceRecord} discriminated union.
 *
 * Consumers: evalgate (failure classification), debugging (cat | jq),
 * metrics pipeline (step-level cost analysis), post-training data curation.
 */

import { createHash } from "node:crypto";
import { appendFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import type { ModelMessage } from "ai";
import type { AgentEventBus } from "../../eventBus";
import { getActiveTraceCorrelation } from "../../observability";

// ---------------------------------------------------------------------------
// Shared type aliases
// ---------------------------------------------------------------------------

/** Known output types from the AI SDK's ToolResultOutput variants. */
export type ToolOutputType =
  | "text"
  | "json"
  | "error-text"
  | "error-json"
  | "content"
  | "execution-denied";

// ---------------------------------------------------------------------------
// StepRecord — one line in trace.jsonl
// ---------------------------------------------------------------------------

export interface StepRecord {
  /** Discriminator — distinguishes from StateCheckpoint in trace.jsonl */
  type: "step";

  /** OTel correlation (active span at write time). */
  correlation?: TraceCorrelation;

  /** Monotonically increasing within this agent, starting at 0 */
  stepIndex: number;

  /** ISO 8601 timestamp when onStepFinish fired */
  timestamp: string;

  /** Agent identifier — null for orchestrator, "pentest-agent-1" etc. for subagents */
  agentId: string | null;

  // -- Observation (what the agent received from prior step's tool execution) --

  /**
   * Tool results that were injected before this step's model call.
   * Extracted from tool-result parts in the messages added since last step.
   * null on step 0 (no prior tool execution).
   */
  observations: Array<{
    toolCallId: string;
    toolName: string;
    outputType: ToolOutputType;
    /** First 2000 chars of stringified output — enough for analysis, bounded for size */
    outputPreview: string;
    /** True byte length of full output */
    outputLength: number;
  }> | null;

  // -- Reasoning (what the model emitted before acting) --

  /**
   * Extended thinking content, if the model produced reasoning parts.
   * null if no reasoning parts were emitted this step.
   */
  reasoning: string | null;

  /**
   * Free-form text the model emitted before tool calls (the "inner monologue").
   * null if the model went straight to a tool call.
   */
  text: string | null;

  // -- Action (what the agent decided to do) --

  /**
   * Tool calls made in this step. Empty array if the model produced only text
   * (e.g., final response).
   */
  actions: Array<{
    toolCallId: string;
    toolName: string;
    /** First 1000 chars of JSON.stringify(input) */
    inputPreview: string;
    /** True byte length of full serialized input */
    inputLength: number;
  }>;

  // -- Metrics --

  /** Tokens consumed in this step */
  usage: {
    inputTokens: number;
    outputTokens: number;
    /** Anthropic cache read tokens (prompt caching). Absent for non-Anthropic models. */
    cacheReadTokens?: number;
    /** Anthropic cache write tokens (prompt caching). Absent for non-Anthropic models. */
    cacheWriteTokens?: number;
  };

  /** Cumulative tokens across all steps so far (including this one) */
  cumulativeUsage: {
    inputTokens: number;
    outputTokens: number;
    cacheReadTokens?: number;
    cacheWriteTokens?: number;
  };

  /** Wall-clock ms from previous step's completion (or agent start) to this step's completion */
  stepDurationMs: number;

  /** Wall-clock ms from agent creation to this step's completion */
  elapsedMs: number;

  /** True if this step triggered context summarization */
  summarized: boolean;
}

// ---------------------------------------------------------------------------
// StateCheckpoint — agent state snapshot in trace.jsonl
// ---------------------------------------------------------------------------

export interface StateCheckpoint {
  /** Discriminator — distinguishes from StepRecord in trace.jsonl */
  type: "checkpoint";

  /** OTel correlation (active span at write time). */
  correlation?: TraceCorrelation;

  /** Step index at which the checkpoint was emitted */
  stepIndex: number;

  /** ISO 8601 */
  timestamp: string;

  agentId: string | null;

  /** What the agent knows about the target */
  targetState: {
    /** Discovered endpoints, services, technologies */
    discoveredSurface: string[];
    /** Credentials or auth tokens obtained */
    credentialsObtained: string[];
    /** Vulnerabilities confirmed so far */
    confirmedVulnerabilities: string[];
  };

  /** What the agent has attempted */
  actionsAttempted: Array<{
    description: string;
    outcome: "success" | "failure" | "partial" | "in-progress";
  }>;

  /** What the agent plans to do next and why */
  nextSteps: Array<{
    action: string;
    rationale: string;
    priority: "high" | "medium" | "low";
  }>;

  /** Explicit assessment of what's not working or blocked */
  blockers: string[];

  /** Free-form assessment — captures anything not covered above */
  assessment: string;
}

// ---------------------------------------------------------------------------
// InitRecord — first line in trace.jsonl, captures agent setup context
// ---------------------------------------------------------------------------

export interface InitRecord {
  /** Discriminator */
  type: "init";

  timestamp: string;

  /** OTel correlation (active span at write time). */
  correlation?: TraceCorrelation;

  agentId: string | null;

  /** AI model identifier used for this agent */
  model: string;

  /** SHA-256 prefix (12 chars) of the system prompt — detects prompt version drift */
  systemPromptHash: string;

  /** Full system prompt text (for training data export) */
  systemPrompt?: string;

  /** Tool names available to this agent */
  activeTools: string[];

  sessionId: string;

  target?: string;

  /** For pentest agents — the testing objectives */
  objectives?: string[];
}

/** Data fields provided by the checkpoint_state tool (metadata is filled by the writer). */
export type CheckpointInput = Omit<
  StateCheckpoint,
  "type" | "stepIndex" | "timestamp" | "agentId"
>;

// ---------------------------------------------------------------------------
// TaskRecord — task lifecycle events in trace.jsonl
// ---------------------------------------------------------------------------

export interface TaskRecord {
  /** Discriminator — distinguishes from other record types in trace.jsonl */
  type: "task";

  /** OTel correlation (active span at write time). */
  correlation?: TraceCorrelation;

  /** ISO 8601 timestamp when the task event occurred */
  timestamp: string;

  /** Agent identifier — null for orchestrator */
  agentId: string | null;

  /** Step index at the time of the task event */
  stepIndex: number;

  /** Whether the task was created or updated */
  action: "created" | "updated";

  /** Task ID from the task system */
  taskId: number;

  /** Task data snapshot at the time of the event */
  data: {
    subject: string;
    status: "pending" | "in_progress" | "completed" | "failed";
    objective: string;
    technique: string;
    result?: string;
    observation?: string;
  };
}

/** Data fields provided by task tools (metadata is filled by the writer). */
export type TaskRecordInput = Omit<
  TaskRecord,
  "type" | "timestamp" | "agentId" | "stepIndex"
>;

/**
 * OTel correlation for a trace record, populated when the writer runs
 * inside an active span. Absent on legacy records.
 */
export interface TraceCorrelation {
  traceId?: string;
  spanId?: string;
}

/** Discriminated union of all trace record types. */
export type TraceRecord =
  | InitRecord
  | StepRecord
  | StateCheckpoint
  | TaskRecord;

/** Every record may carry OTel correlation (absent on legacy records). */
export type CorrelatedRecord = TraceRecord & { correlation?: TraceCorrelation };

// ---------------------------------------------------------------------------
// Extraction helpers
// ---------------------------------------------------------------------------

const OUTPUT_PREVIEW_LIMIT = 2000;
const INPUT_PREVIEW_LIMIT = 1000;
const SYSTEM_PROMPT_HASH_PREFIX_LENGTH = 12;

/**
 * Resolve ToolResultOutput to a string representation and its type tag.
 * Handles all ToolResultOutput variants from the AI SDK.
 */
function stringifyOutput(output: unknown): {
  text: string;
  type: ToolOutputType;
} {
  if (output == null) return { text: "", type: "text" };

  if (
    typeof output === "object" &&
    "type" in (output as Record<string, unknown>)
  ) {
    const typed = output as {
      type: string;
      value?: unknown;
      reason?: string;
    };

    switch (typed.type) {
      case "text":
      case "error-text":
        return {
          text: String(typed.value ?? ""),
          type: typed.type as ToolOutputType,
        };
      case "json":
      case "error-json":
        return {
          text: JSON.stringify(typed.value ?? null),
          type: typed.type as ToolOutputType,
        };
      case "execution-denied":
        return {
          text: typed.reason ?? "execution denied",
          type: typed.type,
        };
      case "content":
        return { text: JSON.stringify(typed.value ?? []), type: typed.type };
      default:
        // Unknown SDK output type — fall back to "text" rather than lose type safety
        return { text: JSON.stringify(output), type: "text" };
    }
  }

  if (typeof output === "string") return { text: output, type: "text" };
  return { text: JSON.stringify(output), type: "json" };
}

function preview(str: string, maxLen: number): string {
  return str.length <= maxLen ? str : str.slice(0, maxLen);
}

// ---------------------------------------------------------------------------
// StepTraceWriter
// ---------------------------------------------------------------------------

export interface StepTraceWriterOpts {
  /** Absolute path to the trace.jsonl file */
  tracePath: string;

  /** Agent identifier — null for orchestrator */
  agentId: string | null;

  /**
   * When provided, every trace record is emitted as a "trace-record"
   * event on the bus. Enables streaming integrations (e.g., W&B) to
   * subscribe once at the workflow level and receive records from all
   * agents automatically.
   */
  eventBus?: AgentEventBus;
}

/**
 * Append-only writer for per-step trace records.
 *
 * Create one instance per agent at construction time. Call
 * {@link recordStep} from every `onStepFinish` invocation and
 * {@link markSummarized} from `onSummarized`.
 */
export class StepTraceWriter {
  private readonly tracePath: string;
  private readonly agentId: string | null;
  private readonly eventBus?: AgentEventBus;

  private stepIndex = 0;
  private cumulativeUsage: StepRecord["cumulativeUsage"] = {
    inputTokens: 0,
    outputTokens: 0,
  };
  private lastStepTime: number;
  private readonly agentStartTime: number;
  private summarized = false;
  private previousMessageCount = 0;

  constructor(opts: StepTraceWriterOpts) {
    this.tracePath = opts.tracePath;
    this.agentId = opts.agentId;
    this.eventBus = opts.eventBus;

    const now = Date.now();
    this.agentStartTime = now;
    this.lastStepTime = now;

    mkdirSync(dirname(this.tracePath), { recursive: true });
  }

  /**
   * Write the init record as the first line of trace.jsonl.
   * Call once before the stream starts.
   */
  writeInit(
    data: Omit<
      InitRecord,
      "type" | "timestamp" | "agentId" | "systemPromptHash"
    > & { systemPrompt: string },
  ): void {
    const { systemPrompt, ...rest } = data;
    const record: InitRecord = {
      type: "init",
      timestamp: new Date().toISOString(),
      agentId: this.agentId,
      systemPromptHash: createHash("sha256")
        .update(systemPrompt)
        .digest("hex")
        .slice(0, SYSTEM_PROMPT_HASH_PREFIX_LENGTH),
      systemPrompt,
      ...rest,
    };
    this.appendRecord(record);
  }

  /**
   * Mark that context summarization occurred.
   * The next step record will have `summarized: true` and
   * previousMessageCount resets to 0 (messages are rebuilt post-summary).
   */
  markSummarized(): void {
    this.summarized = true;
    this.previousMessageCount = 0;
  }

  /**
   * Record a single step. Called from onStepFinish.
   *
   * @param responseMessages - `event.response.messages` from the AI SDK
   *   (cumulative response messages, NOT including initial prompt messages)
   * @param usage - `event.usage` from the AI SDK (this step's token counts)
   */
  recordStep(
    responseMessages: ModelMessage[],
    usage: {
      inputTokens: number;
      outputTokens: number;
      cacheReadTokens?: number;
      cacheWriteTokens?: number;
    },
  ): void {
    const now = Date.now();
    const newMessages = responseMessages.slice(this.previousMessageCount);
    this.previousMessageCount = responseMessages.length;

    const observations: NonNullable<StepRecord["observations"]> = [];
    const reasoningParts: string[] = [];
    const textParts: string[] = [];
    const actions: StepRecord["actions"] = [];

    for (const msg of newMessages) {
      if (!Array.isArray(msg.content)) {
        if (typeof msg.content === "string" && msg.role === "assistant") {
          textParts.push(msg.content);
        }
        continue;
      }

      for (const part of msg.content) {
        switch (part.type) {
          case "tool-result": {
            const { text, type } = stringifyOutput(
              (part as { output?: unknown }).output,
            );
            observations.push({
              toolCallId: part.toolCallId,
              toolName: part.toolName,
              outputType: type,
              outputPreview: preview(text, OUTPUT_PREVIEW_LIMIT),
              outputLength: Buffer.byteLength(text, "utf-8"),
            });
            break;
          }
          case "reasoning": {
            reasoningParts.push((part as { text: string }).text);
            break;
          }
          case "text": {
            textParts.push((part as { text: string }).text);
            break;
          }
          case "tool-call": {
            const serialized = JSON.stringify(
              (part as { input: unknown }).input,
            );
            actions.push({
              toolCallId: part.toolCallId,
              toolName: part.toolName,
              inputPreview: preview(serialized, INPUT_PREVIEW_LIMIT),
              inputLength: Buffer.byteLength(serialized, "utf-8"),
            });
            break;
          }
          // Silently skip other part types (file, tool-approval-request, etc.)
        }
      }
    }

    const inputTokens = usage.inputTokens ?? 0;
    const outputTokens = usage.outputTokens ?? 0;
    const cacheReadTokens = usage.cacheReadTokens;
    const cacheWriteTokens = usage.cacheWriteTokens;
    this.cumulativeUsage.inputTokens += inputTokens;
    this.cumulativeUsage.outputTokens += outputTokens;
    if (cacheReadTokens != null) {
      this.cumulativeUsage.cacheReadTokens =
        (this.cumulativeUsage.cacheReadTokens ?? 0) + cacheReadTokens;
    }
    if (cacheWriteTokens != null) {
      this.cumulativeUsage.cacheWriteTokens =
        (this.cumulativeUsage.cacheWriteTokens ?? 0) + cacheWriteTokens;
    }

    const record: StepRecord = {
      type: "step",
      stepIndex: this.stepIndex,
      timestamp: new Date(now).toISOString(),
      agentId: this.agentId,

      observations:
        this.stepIndex === 0
          ? null
          : observations.length > 0
            ? observations
            : null,

      reasoning: reasoningParts.length > 0 ? reasoningParts.join("") : null,
      text: textParts.length > 0 ? textParts.join("") : null,
      actions,

      usage: { inputTokens, outputTokens, cacheReadTokens, cacheWriteTokens },
      cumulativeUsage: { ...this.cumulativeUsage },

      stepDurationMs: now - this.lastStepTime,
      elapsedMs: now - this.agentStartTime,
      summarized: this.summarized,
    };

    this.appendRecord(record);
    this.stepIndex++;
    this.lastStepTime = now;
    this.summarized = false;
  }

  // ---------------------------------------------------------------------------
  // Checkpoint support (PRD 2)
  // ---------------------------------------------------------------------------

  /**
   * The step index that will be assigned to the next record.
   * During tool execution (between steps), this is the index of the
   * current in-flight step — use it for checkpoint records.
   */
  get currentStepIndex(): number {
    return this.stepIndex;
  }

  /**
   * Append a {@link StateCheckpoint} record to trace.jsonl.
   *
   * Called by the `checkpoint_state` tool during tool execution.
   * The writer fills in metadata (type, stepIndex, timestamp, agentId);
   * the caller provides the data fields.
   */
  appendCheckpoint(data: CheckpointInput): void {
    const record: StateCheckpoint = {
      type: "checkpoint",
      stepIndex: this.stepIndex,
      timestamp: new Date().toISOString(),
      agentId: this.agentId,
      ...data,
    };
    this.appendRecord(record);
  }

  // ---------------------------------------------------------------------------
  // Task record support
  // ---------------------------------------------------------------------------

  /**
   * Append a {@link TaskRecord} to trace.jsonl.
   *
   * Called by task tools (create_task, update_task) during tool execution.
   * The writer fills in metadata (type, timestamp, agentId, stepIndex);
   * the caller provides the action and data fields.
   */
  appendTaskRecord(data: TaskRecordInput): void {
    const record: TaskRecord = {
      type: "task",
      timestamp: new Date().toISOString(),
      agentId: this.agentId,
      stepIndex: this.stepIndex,
      ...data,
    };
    this.appendRecord(record);
  }

  /** Sync append — ~1-3KB per line, sub-ms. Sync ensures crash safety. */
  private appendRecord(record: TraceRecord): void {
    // Correlate with the active OTel span when valid — W&B and JSONL
    // consumers receive it through this same record, no extra wiring.
    const correlation = getActiveTraceCorrelation();
    const enriched: CorrelatedRecord = correlation
      ? { ...record, correlation }
      : record;
    try {
      appendFileSync(this.tracePath, `${JSON.stringify(enriched)}\n`);
    } catch {
      // Trace is non-critical observability — never crash the agent for it.
    }
    try {
      this.eventBus?.emit("trace-record", {
        record: enriched,
        subagentId: this.agentId ?? undefined,
      });
    } catch {
      // Event emission failures are non-critical — never crash the agent.
    }
  }
}
