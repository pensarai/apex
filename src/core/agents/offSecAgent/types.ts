import type {
  ModelMessage,
  StopCondition,
  StreamTextOnFinishCallback,
  StreamTextOnStepFinishCallback,
  StreamTextResult,
  TextStreamPart,
  ToolChoice,
  ToolSet,
} from "ai";
import type { AIModel, AIAuthConfig } from "../../ai";
import type { CredentialManager } from "../../credentials";
import type { FindingsRegistry } from "../../findings/registry";
import type { SessionInfo } from "../../session";
import type { ToolName } from "./tools";
import type { UnifiedSandbox } from "./tools/sandbox";
import { z } from "zod";

// Backward-compatible Finding schema (toolCallDescription is optional for parsing old findings)
export const ApexFindingObject = z.object({
  title: z.string(),
  severity: z.preprocess(
    (val) => {
      if (typeof val === "string") {
        const upper = val.toUpperCase();
        if (upper.includes("CRITICAL")) return "CRITICAL";
        if (upper.includes("HIGH")) return "HIGH";
        if (upper.includes("MEDIUM")) return "MEDIUM";
        if (upper.includes("LOW")) return "LOW";
      }
      return val;
    },
    z.enum(["CRITICAL", "HIGH", "MEDIUM", "LOW"]),
  ),
  description: z.string(),
  impact: z.string(),
  evidence: z.string(),
  endpoint: z.string(),
  pocPath: z.string(),
  remediation: z.string(),
  references: z.string().optional(),
  toolCallDescription: z.string().optional(), // Optional for backward compatibility
});

export type Finding = z.infer<typeof ApexFindingObject>;

/**
 * Input for the general-purpose OffensiveSecurityAgent harness.
 *
 * The base agent owns tool creation — specific agents just declare
 * which tools they need via `activeTools`.
 *
 * @typeParam TResult - The type returned by `consume()`. Defaults to `void`.
 */
export type OffensiveSecurityAgentInput<TResult = void> = {
  /** System prompt defining agent persona and behavior */
  system: string;

  /** Initial user prompt that kicks off the agent */
  prompt: string;

  /** AI model identifier */
  model: AIModel;

  /** Session providing paths for findings, POCs, logs, etc. */
  session: SessionInfo;

  /** The target URL / host — passed to browser tools for context */
  target?: string;

  /**
   * Which tools the agent is allowed to use.
   *
   * Accepts both built-in tool names and custom tool names (from `extraTools`).
   * This array controls which tools the model can see and invoke
   * (maps to the AI SDK `activeTools`).
   */
  activeTools: (ToolName | (string & {}))[];

  /**
   * Additional tools to merge into the toolset.
   *
   * Use this to inject agent-specific tools (e.g. a structured response
   * tool) without modifying the shared tool registry. These are merged
   * on top of the built-in tools created by `createAllTools`.
   */
  extraTools?: ToolSet;

  /** Existing conversation history (for resumption / multi-turn) */
  messages?: Array<ModelMessage>;

  /** Condition(s) under which the agent should stop */
  stopWhen?:
    | StopCondition<NoInfer<ToolSet>>
    | StopCondition<NoInfer<ToolSet>>[];

  /** Strategy for selecting which tool to call */
  toolChoice?: ToolChoice<ToolSet>;

  /** Callback fired after each agent step completes */
  onStepFinish?: StreamTextOnStepFinishCallback<ToolSet>;

  /** Callback fired when the entire stream finishes */
  onFinish?: StreamTextOnFinishCallback<ToolSet>;

  /** AbortSignal to cancel the agent mid-run */
  abortSignal?: AbortSignal;

  /** Per-provider API key overrides */
  authConfig?: AIAuthConfig;

  /**
   * When set, tools like execute_command / http_request / create_poc
   * route execution through this sandbox instead of running locally.
   */
  sandbox?: UnifiedSandbox;

  /**
   * Shared findings registry for cross-agent dedup.
   * When present, `document_vulnerability` checks for duplicates before writing.
   */
  findingsRegistry?: FindingsRegistry;

  /**
   * In-memory credential store. When present, tools resolve credential
   * IDs to secrets at execution time and prompt builders emit only
   * safe {@link CredentialReference} metadata — the agent never sees
   * raw passwords, tokens, or API keys.
   */
  credentialManager?: CredentialManager;

  /**
   * Called after the stream is fully consumed to produce a typed result.
   *
   * Receives the completed `StreamTextResult` — at this point all lazy
   * properties (`.steps`, `.text`, `.response`, etc.) are resolved.
   *
   * If omitted, `consume()` returns `void`.
   */
  resolveResult?: (
    streamResult: StreamTextResult<ToolSet, never>,
  ) => TResult | Promise<TResult>;

  /** The subagent ID if this agent is a subagent */
  subagentId?: string;

  /**
   * Callbacks for forwarding subagent stream events to the parent consumer.
   *
   * Passed through to the tool context so orchestration tools
   * (run_attack_surface, spawn_pentest_swarm) can forward their
   * sub-agent events back to the top-level consumer.
   */
  subagentCallbacks?: SubagentConsumeCallbacks;

  /** Callbacks for persisting agent discoveries to external storage (e.g., database). */
  callbacks?: ConsumeCallbacks;

  /**
   * Zod schema for structured output via the `response` tool.
   *
   * When provided, the base class automatically:
   * 1. Creates and injects a `response` tool with this schema
   * 2. Merges `hasToolCall("response")` into the stop conditions
   * 3. Defaults `resolveResult` to return the captured structured data
   *
   * Specialized agents just set this and include `"response"` in
   * `activeTools` to get typed structured output from `consume()`.
   */
  responseSchema?: z.ZodSchema;
};

/**
 * Shared input fields for all specialized agents.
 *
 * Specialized agent input interfaces should extend this to inherit
 * the common harness fields, then add only their agent-specific ones.
 */
export interface SpecializedAgentInput {
  /** AI model to drive the agent */
  model: AIModel;

  /** Session providing paths for findings, POCs, logs, etc. */
  session: SessionInfo;

  /** Optional per-provider API key overrides */
  authConfig?: AIAuthConfig;

  /** Callback fired after each agent step */
  onStepFinish?: StreamTextOnStepFinishCallback<ToolSet>;

  /** AbortSignal to cancel the agent mid-run */
  abortSignal?: AbortSignal;

  /** Callbacks for stream events and subagent forwarding */
  callbacks?: ConsumeCallbacks;

  /** Shared findings registry for cross-agent dedup */
  findingsRegistry?: FindingsRegistry;

  /** In-memory credential store for secret-free agent prompts */
  credentialManager?: CredentialManager;

  /** Override the default stop condition */
  stopWhen?: StopCondition<ToolSet>;
}

/**
 * Typed callbacks for consuming the agent's output stream.
 * Pass to `agent.consume()` for ergonomic stream processing.
 */
export type ConsumeCallbacks = {
  onTextDelta?: (
    delta: Extract<TextStreamPart<ToolSet>, { type: "text-delta" }>,
  ) => void;
  onToolCall?: (
    delta: Extract<TextStreamPart<ToolSet>, { type: "tool-call" }>,
  ) => void;
  onToolResult?: (
    delta: Extract<TextStreamPart<ToolSet>, { type: "tool-result" }>,
  ) => void;
  onError?: (error: unknown) => void;
  subagentCallbacks?: SubagentConsumeCallbacks;
};

/**
 * Typed callbacks for consuming the subagent's output stream.
 * Pass to `subagent.consume()` for ergonomic stream processing.
 */
export type SubagentConsumeCallbacks = {
  onSubagentSpawn?: ({
    subagentId,
    input,
    status,
  }: {
    subagentId: string;
    input: unknown;
    status: "pending" | "completed" | "failed";
  }) => void;
  onSubagentComplete?: ({
    subagentId,
    input,
    status,
  }: {
    subagentId: string;
    input: unknown;
    status: "completed" | "failed";
  }) => void;
  onTextDelta?: (
    delta: Extract<TextStreamPart<ToolSet>, { type: "text-delta" }> & {
      subagentId?: string;
    },
  ) => void;
  onToolCall?: (
    delta: Extract<TextStreamPart<ToolSet>, { type: "tool-call" }> & {
      subagentId?: string;
    },
  ) => void;
  onToolResult?: (
    delta: Extract<TextStreamPart<ToolSet>, { type: "tool-result" }> & {
      subagentId?: string;
    },
  ) => void;
  onError?: (error: unknown) => void;
};
