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

import type { ModelMessage } from "ai";
import { createHash } from "crypto";
import { appendFileSync, mkdirSync } from "fs";
import { dirname } from "path";
import type { AgentEventBus } from "../../eventBus";

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
// Hash chain fields (APTS-AR-012)
// ---------------------------------------------------------------------------

/**
 * Fields present on every trace record to form a tamper-evident hash chain.
 *
 * `seq` is a monotonically increasing sequence number (0-based, no gaps).
 * `previousHash` is the SHA-256 hex digest of the previous record's JSON
 * line (empty string for the first record).
 * `hash` is the SHA-256 hex digest of the current record's JSON line
 * *after* all other fields (including `previousHash`) are set but
 * *before* `hash` itself is written — i.e. the hash covers everything
 * except the `hash` field.
 *
 * Verification: for each record, strip the `hash` field, re-serialize to
 * JSON, SHA-256 the result, and compare to the stored `hash`. Then check
 * that `previousHash` equals the preceding record's `hash`. Gaps in `seq`
 * indicate deletion.
 */
export interface HashChainFields {
  /** Monotonically increasing sequence number (0-based, no gaps). */
  seq: number;
  /** SHA-256 hex digest of the previous record's JSON line (empty string for first record). */
  previousHash: string;
  /** SHA-256 hex digest of this record's content (excluding the `hash` field itself). */
  hash: string;
}

// ---------------------------------------------------------------------------
// StepRecord — one line in trace.jsonl
// ---------------------------------------------------------------------------

export interface StepRecord extends HashChainFields {
  /** Discriminator — distinguishes from StateCheckpoint in trace.jsonl */
  type: "step";

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

export interface StateCheckpoint extends HashChainFields {
  /** Discriminator — distinguishes from StepRecord in trace.jsonl */
  type: "checkpoint";

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

export interface InitRecord extends HashChainFields {
  /** Discriminator */
  type: "init";

  timestamp: string;

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

/** Data fields provided by the checkpoint_state tool (metadata + hash chain filled by the writer). */
export type CheckpointInput = Omit<
  StateCheckpoint,
  "type" | "stepIndex" | "timestamp" | "agentId" | keyof HashChainFields
>;

// ---------------------------------------------------------------------------
// TaskRecord — task lifecycle events in trace.jsonl
// ---------------------------------------------------------------------------

export interface TaskRecord extends HashChainFields {
  /** Discriminator — distinguishes from other record types in trace.jsonl */
  type: "task";

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

/** Data fields provided by task tools (metadata + hash chain filled by the writer). */
export type TaskRecordInput = Omit<
  TaskRecord,
  "type" | "timestamp" | "agentId" | "stepIndex" | keyof HashChainFields
>;

/** Discriminated union of all trace record types. */
export type TraceRecord =
  | InitRecord
  | StepRecord
  | StateCheckpoint
  | TaskRecord;

// ---------------------------------------------------------------------------
// Hash chain verification (APTS-AR-012)
// ---------------------------------------------------------------------------

export interface ChainVerificationResult {
  valid: boolean;
  entriesChecked: number;
  /** If invalid, the 0-based index of the first record that failed verification. */
  breakIndex?: number;
  /** Human-readable reason for the break. */
  breakReason?: string;
}

/**
 * Verify the integrity of a trace hash chain per APTS-AR-012.
 *
 * Algorithm:
 * 1. Read all entries in sequence order.
 * 2. For each entry, strip the `hash` field, recompute SHA-256, compare.
 * 3. Verify `previousHash` matches prior entry's `hash`.
 * 4. Verify `seq` values are continuous (no gaps).
 * 5. Any mismatch → chain is broken; return the break point.
 */
export function verifyTraceChain(
  records: TraceRecord[],
): ChainVerificationResult {
  if (records.length === 0) {
    return { valid: true, entriesChecked: 0 };
  }

  let expectedPreviousHash = "";

  for (let i = 0; i < records.length; i++) {
    const record = records[i];

    if (record.seq !== i) {
      return {
        valid: false,
        entriesChecked: i,
        breakIndex: i,
        breakReason: `Sequence gap: expected seq=${i}, got seq=${record.seq}`,
      };
    }

    if (record.previousHash !== expectedPreviousHash) {
      return {
        valid: false,
        entriesChecked: i,
        breakIndex: i,
        breakReason: `Previous hash mismatch at seq=${i}: expected "${expectedPreviousHash}", got "${record.previousHash}"`,
      };
    }

    const storedHash = record.hash;
    const recordCopy = { ...record, hash: "" };
    const recomputed = createHash("sha256")
      .update(JSON.stringify(recordCopy))
      .digest("hex");

    if (recomputed !== storedHash) {
      return {
        valid: false,
        entriesChecked: i,
        breakIndex: i,
        breakReason: `Hash mismatch at seq=${i}: recomputed "${recomputed}", stored "${storedHash}"`,
      };
    }

    expectedPreviousHash = storedHash;
  }

  return { valid: true, entriesChecked: records.length };
}

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

  /** Hash chain state (APTS-AR-012) */
  private seq = 0;
  private previousHash = "";

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
      | "type"
      | "timestamp"
      | "agentId"
      | "systemPromptHash"
      | keyof HashChainFields
    > & { systemPrompt: string },
  ): void {
    const { systemPrompt, ...rest } = data;
    const record: InitRecord = {
      seq: 0,
      previousHash: "",
      hash: "",
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
      seq: 0,
      previousHash: "",
      hash: "",
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
      seq: 0,
      previousHash: "",
      hash: "",
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
      seq: 0,
      previousHash: "",
      hash: "",
      type: "task",
      timestamp: new Date().toISOString(),
      agentId: this.agentId,
      stepIndex: this.stepIndex,
      ...data,
    };
    this.appendRecord(record);
  }

  /**
   * Sync append with hash chain (APTS-AR-012).
   *
   * Each record gets a monotonic `seq`, `previousHash` (the hash of the
   * prior record), and `hash` (SHA-256 of the record with all fields set
   * except `hash` itself). This makes the log tamper-evident: modifying
   * or deleting any entry breaks the chain.
   */
  private appendRecord(record: TraceRecord): void {
    try {
      record.seq = this.seq;
      record.previousHash = this.previousHash;
      record.hash = "";

      const contentToHash = JSON.stringify(record);
      const hash = createHash("sha256").update(contentToHash).digest("hex");
      record.hash = hash;

      appendFileSync(this.tracePath, JSON.stringify(record) + "\n");

      this.previousHash = hash;
      this.seq++;
    } catch {
      // Trace is non-critical observability — never crash the agent for it.
    }
    try {
      this.eventBus?.emit("trace-record", {
        record,
        subagentId: this.agentId ?? undefined,
      });
    } catch {
      // Event emission failures are non-critical — never crash the agent.
    }
  }
}
