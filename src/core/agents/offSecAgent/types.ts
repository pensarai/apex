import type {
  ModelMessage,
  StopCondition,
  StreamTextOnFinishCallback,
  StreamTextOnStepFinishCallback,
  StreamTextResult,
  ToolChoice,
  ToolSet,
} from "ai";
import type { AIModel, CacheMetrics } from "../../ai";
import type { AIAuthConfig } from "../../ai/utils";
import type { CredentialManager } from "../../credentials";
import type { AttackSurfaceRegistry } from "../../findings/attackSurfaceRegistry";
import type { FindingsRegistry } from "../../findings/registry";
import type { SessionInfo, SessionConfig } from "../../session";
import type { ApprovalGate } from "../../operator";
import type { SkillsRegistry } from "../../skills/registry";
import type { ToolName } from "./tools";
import type { UnifiedSandbox } from "./tools/sandbox";
import type { AgentEventBus } from "../../eventBus";
import { z } from "zod";
import {
  CweEntrySchema,
  ValidatedCweEntrySchema,
} from "../../../lib/cwe/types";
import { EvidenceFileEntrySchema } from "../../../lib/evidence/types";

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
  cwes: z.array(ValidatedCweEntrySchema.or(CweEntrySchema)).optional(),
  rootCauseGroup: z.string().optional(),
  relatedFindings: z.array(z.string()).optional(),
  evidenceFiles: z.array(EvidenceFileEntrySchema).optional(),
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
/** Agent operating mode that controls which tools are available. */
export type AgentMode = "default" | "plan";

export type OffensiveSecurityAgentInput<TResult = void> = {
  /** System prompt defining agent persona and behavior. Defaults to BASE_SYSTEM_PROMPT when omitted. */
  system?: string;

  /** Initial user prompt that kicks off the agent */
  prompt: string;

  /** AI model identifier */
  model: AIModel;

  /**
   * Operating mode that controls which tools are available.
   *
   * - `"default"` — all tools in `activeTools` are available (default)
   * - `"plan"` — only read-only / non-mutating tools are available
   *
   * When set to `"plan"`, the agent's `activeTools` are intersected with
   * {@link PLAN_MODE_TOOL_NAMES} so that mutation tools (create_file,
   * update_file, document_vulnerability, document_app,
   * document_endpoint) are excluded.
   *
   * @default "default"
   */
  mode?: AgentMode;

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

  /** Called when Anthropic cache metrics are present in a step's providerMetadata */
  onCacheMetrics?: (metrics: CacheMetrics) => void;

  /** AbortSignal to cancel the agent mid-run */
  abortSignal?: AbortSignal;

  /** Per-provider API key overrides */
  authConfig?: AIAuthConfig;

  /**
   * When set, tools like execute_command / http_request / document_vulnerability
   * route execution through this sandbox instead of running locally.
   */
  sandbox?: UnifiedSandbox;

  /**
   * Shared findings registry for cross-agent dedup.
   * When present, `document_vulnerability` checks for duplicates before writing.
   */
  findingsRegistry?: FindingsRegistry;

  /**
   * Shared attack surface registry for cross-agent asset dedup.
   * When present, `document_endpoint` checks for duplicates before writing.
   */
  attackSurfaceRegistry?: AttackSurfaceRegistry;

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
   * Override the auto-computed task directory. When set, takes precedence
   * over the directory derived from `subagentId`. Use this when a plan
   * agent needs to write tasks to the execution agent's task directory.
   */
  tasksDir?: string;

  /**
   * Override for plan file scoping. When set, write_plan uses this ID
   * instead of `subagentId` to derive the plan file path, allowing
   * plan agents to write plans scoped to their corresponding execution agent.
   */
  planSubagentId?: string;

  /**
   * Event bus for streaming agent output.
   *
   * When provided, the agent emits all streaming events (text deltas,
   * tool calls, tool results, errors) on this bus. Multiple consumers
   * can subscribe independently — TUI, DB persistence, metrics, etc.
   *
   * The bus is also passed through to tools so orchestration tools
   * (run_attack_surface, spawn_pentest_swarm) can emit subagent events
   * on the same bus.
   *
   * When omitted, a fresh bus is created internally — callers can access
   * it via `agent.eventBus` after construction.
   */
  eventBus?: AgentEventBus;

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

  /**
   * Skills registry for on-demand skill loading.
   * When provided, read_skill is available.
   */
  skillsRegistry?: SkillsRegistry;

  /**
   * Gates availability of the `ask_user_questions` tool. When `true`, the
   * base class forwards the flag via {@link ToolContext} so specialized
   * agents (e.g. the exploration agent) can opt into interactive clarification.
   */
  askUserQuestionsEnabled?: boolean;

  /**
   * When provided, each tool call is gated through the approval gate.
   * The gate will pause execution until the operator approves or denies
   * the call (when `requireApproval` is enabled on the gate).
   */
  approvalGate?: ApprovalGate;

  /**
   * Directory where `messages.json` is persisted after each step.
   * Defaults to `session.rootPath`.
   */
  messagesDir?: string;

  /**
   * Mutable handle the agent populates so the caller can cancel the
   * currently running shell command without killing the agent.
   */
  commandCancelHandle?: CommandCancelHandle;

  /**
   * Environment variables to inject into the agent's persistent shell.
   * Each key-value pair is set in the shell's process environment at
   * spawn time, so they're available to every `execute_command` call.
   * Scoped to this agent instance — other agents on the same machine
   * never see them.
   */
  environmentVariables?: Record<string, string>;

  /** Enable extended thinking (reasoning) for supported models. */
  enableThinking?: boolean;

  /**
   * Project-level threat model content (e.g. from `.pensar/threat_model.md`).
   * Forwarded into the {@link ToolContext} so tools that spawn dedicated
   * per-endpoint threat-model sub-agents can include this as additional
   * grounding context.
   */
  projectThreatModel?: string;
};

/**
 * Mutable handle for cancelling the running shell command.
 * The agent populates `cancel` at construction time; the caller invokes it.
 */
export type CommandCancelHandle = {
  cancel: () => boolean;
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

  /** Existing conversation history for resumption */
  messages?: Array<ModelMessage>;

  /** Callback fired after each agent step */
  onStepFinish?: StreamTextOnStepFinishCallback<ToolSet>;

  /** Called when Anthropic cache metrics are present in a step's providerMetadata */
  onCacheMetrics?: (metrics: CacheMetrics) => void;

  /** AbortSignal to cancel the agent mid-run */
  abortSignal?: AbortSignal;

  /** Event bus for streaming agent output */
  eventBus?: AgentEventBus;

  /**
   * When set, stream chunks emitted during {@link OffensiveSecurityAgent.consume}
   * are tagged with this id on the event bus (for multi-agent UIs).
   */
  subagentId?: string;

  /** Shared findings registry for cross-agent dedup */
  findingsRegistry?: FindingsRegistry;

  /** Shared attack surface registry for cross-agent asset dedup */
  attackSurfaceRegistry?: AttackSurfaceRegistry;

  /** In-memory credential store for secret-free agent prompts */
  credentialManager?: CredentialManager;

  /** Override the default stop condition */
  stopWhen?: StopCondition<ToolSet>;

  /**
   * Environment variables to inject into the agent's persistent shell.
   * Forwarded to the underlying {@link OffensiveSecurityAgentInput}.
   */
  environmentVariables?: Record<string, string>;

  /** Enable extended thinking (reasoning) for supported models. */
  enableThinking?: boolean;

  /**
   * Project-level threat model content. Forwarded into {@link ToolContext}
   * so per-endpoint threat-model sub-agents can incorporate it as grounding.
   */
  projectThreatModel?: string;
}

/**
 * Input for the `OffensiveSecurityAgent.create()` async factory.
 *
 * Identical to {@link OffensiveSecurityAgentInput} except `session` is
 * optional. When omitted, the factory creates a new session automatically
 * using the remaining fields.
 *
 * Pass an existing `session` to reuse one (e.g. from the console API or
 * when spawning subagents).
 */
export type CreateAgentInput<TResult = void> = Omit<
  OffensiveSecurityAgentInput<TResult>,
  "session" | "system"
> & {
  /** Existing session to reuse. When omitted a new one is created. */
  session?: SessionInfo;
  /** Session config used when auto-creating a session (ignored when `session` is provided). */
  sessionConfig?: SessionConfig;
  /** System prompt override. When omitted, BASE_SYSTEM_PROMPT is used. The session workspace section is always appended. */
  system?: string;
  /** Called when the async AI name generation resolves with a name. */
  onNameGenerated?: (name: string) => void;
};
