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
import type { Session } from "../session";
import type { ToolName, PersistenceCallbacks } from "./tools";

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
  session: Session.SessionInfo;

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

  /** Optional persistence callbacks for external storage integration */
  persistence?: PersistenceCallbacks;

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
};
