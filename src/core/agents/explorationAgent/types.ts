import type {
  ModelMessage,
  StreamTextOnStepFinishCallback,
  ToolSet,
} from "ai";
import type { AIModel } from "../../ai";
import type { AIAuthConfig } from "../../ai/utils";
import type { SessionInfo } from "../../session";

/**
 * Input for {@link ExplorationAgent}.
 *
 * The exploration agent is a light, single-turn specialization of
 * {@link OffensiveSecurityAgent} whose only job is to browse a cloned
 * repository, issue one batched `ask_user_questions` tool call, and stop.
 *
 * This input type intentionally omits most of the harness-level knobs
 * (findings registry, sandbox, skills, approval gate, etc.) because V1
 * never exercises them. Add fields here as real exploration consumers
 * need them.
 */
export interface ExplorationAgentInput {
  /** Initial user prompt — typically a short directive describing the repo to explore. */
  prompt: string;

  /** AI model identifier (defaults selected by the consumer; Opus 4.6 is the reference default). */
  model: AIModel;

  /** Session providing paths for trace/message persistence and the agent's working directory. */
  session: SessionInfo;

  /** Per-provider API key overrides. */
  authConfig?: AIAuthConfig;

  /** AbortSignal to cancel the agent mid-run. */
  abortSignal?: AbortSignal;

  /** Callback fired after each agent step completes. */
  onStepFinish?: StreamTextOnStepFinishCallback<ToolSet>;

  /**
   * Existing conversation history to seed the agent with.
   *
   * When present, these messages replace the synthetic user-prompt message
   * the base class would otherwise construct from `prompt`. Used by the
   * Console consumer to resume an `agent_chat_sessions` thread on each turn.
   */
  priorMessages?: ModelMessage[];
}
