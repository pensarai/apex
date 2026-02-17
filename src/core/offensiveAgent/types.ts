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
import type { AIModel } from "../ai";
import type { AIAuthConfig } from "../ai/utils";
import type { SessionInfo } from "../session";
import type { ToolName } from "./tools";

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
   * All tools are created by the harness; this array controls which
   * ones the model can see and invoke (maps to the AI SDK `activeTools`).
   */
  activeTools: ToolName[];

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
};

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
