import type {
  LanguageModelMiddleware,
  ModelMessage,
  StopCondition,
  StreamTextOnFinishCallback,
  StreamTextOnStepFinishCallback,
  StreamTextResult,
  ToolChoice,
  ToolSet,
} from "ai";
import { z } from "zod";
import { AttackPathSchema } from "../../../lib/attack-path/types";
import {
  CweEntrySchema,
  ValidatedCweEntrySchema,
} from "../../../lib/cwe/types";
import { EvidenceFileEntrySchema } from "../../../lib/evidence/types";
import type {
  AIAuthConfig,
  AIModel,
  CacheMetrics,
  OpenAIReasoningEffort,
  ThinkingEffort,
  UsageRecorder,
} from "../../ai";
import type { CredentialManager } from "../../credentials";
import type { AgentEventBus } from "../../eventBus";
import type { AttackSurfaceRegistry } from "../../findings/attackSurfaceRegistry";
import type { FindingsRegistry } from "../../findings/registry";
import type { ApprovalGate } from "../../operator";
import type { PromptInjectionLibrary } from "../../prompt-injections";
import type { SessionConfig, SessionInfo } from "../../session";
import type { SkillsRegistry } from "../../skills/registry";
import type { GrpcPentestContext } from "../specialized/attackSurface/grpcSchema";
import type { SubagentSpawner } from "./subagentSpawner";
import type { PlaywrightMcpSession, ToolName, UnifiedSandbox } from "./tools";

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
  /** True for the single lead finding of a root-cause group (the one that should anchor the consolidated write-up). */
  rootCauseLead: z.boolean().optional(),
  evidenceFiles: z.array(EvidenceFileEntrySchema).optional(),
  attackPath: AttackPathSchema.optional(),
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
export type AgentMode = "default" | "plan" | "fast-strike";

/** Structured authorization envelope for a multi-application System pentest. */
export type SystemPentestScope = {
  systemId: string;
  memberHosts: string[];
};

/** Identifies which streamed event a {@link StreamIdFactory} is minting an id for. */
export type StreamIdFactoryContext =
  | { kind: "message"; stepIndex: number }
  | { kind: "text-part"; stepIndex: number; textPartIndex: number }
  | { kind: "tool-part"; toolCallId: string };

/**
 * Mints message/part ids for streamed events. Defaults to random ULIDs
 * ({@link newMessageId}/{@link newPartId}) when unset; a durable runtime injects
 * a factory that derives deterministic, replay-stable ids from the context.
 */
export type StreamIdFactory = (context: StreamIdFactoryContext) => string;

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
   * - `"fast-strike"` — live registry minus {@link FAST_STRIKE_EXCLUDED_TOOL_NAMES}; ignores `activeTools`
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
   * gRPC context when the target is a gRPC method rather than an HTTP
   * endpoint. Forwarded into the {@link ToolContext} so `spawn_pentest_agent`
   * can hand it down to spawned workers.
   */
  grpc?: GrpcPentestContext;

  /** Structured multi-application scope forwarded to pentest workers. */
  systemScope?: SystemPentestScope;

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

  /** Provider middleware applied only to this agent's model calls. Unset → raw model. */
  languageModelMiddleware?: LanguageModelMiddleware | LanguageModelMiddleware[];

  /** Per-run usage recorder. Unset → the process-global usage callback fires as today. */
  usageRecorder?: UsageRecorder;

  /** Factory for streamed message/part ids. Unset → random ULIDs, unchanged. */
  streamIdFactory?: StreamIdFactory;

  /** Callback fired when the entire stream finishes */
  onFinish?: StreamTextOnFinishCallback<ToolSet>;

  /** Called when Anthropic cache metrics are present in a step's providerMetadata */
  onCacheMetrics?: (metrics: CacheMetrics) => void;

  /**
   * Forward usage callbacks through tools that spawn agents. Enable only when
   * the caller does not already account for subagents from trace events.
   */
  forwardUsageCallbacksToSpawnedAgents?: boolean;

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
   * Seam through which orchestration tools spawn sub-agents. Forwarded into the
   * {@link ToolContext}; unset → tools use the in-process spawner.
   */
  subagentSpawner?: SubagentSpawner;

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

  /** Display label for the OTel span name / `gen_ai.agent.name`. */
  subagentName?: string;

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
   * Runtime-only prompt-injection library. Raw payloads are resolved inside
   * trusted tool execution paths, not in prompts or model-visible messages.
   */
  promptInjectionLibrary?: PromptInjectionLibrary;

  /**
   * Local filesystem path for a prompt-injection payload library. Falls back
   * to PENSAR_PROMPT_INJECTION_LIBRARY / APEX_PROMPT_INJECTION_LIBRARY.
   */
  promptInjectionLibrarySource?: string;

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

  /** Secret values to scrub from execute_command output. Forwarded into the {@link ToolContext}. */
  secretValues?: string[];

  /** Enable extended thinking (reasoning) for supported models. */
  enableThinking?: boolean;

  /** Adaptive-thinking effort hint (Anthropic Opus/Sonnet 4.6+); ignored elsewhere. */
  thinkingEffort?: ThinkingEffort | null;

  /** OpenAI reasoning effort for GPT/o-series reasoning models. */
  openAIReasoningEffort?: OpenAIReasoningEffort | null;

  /**
   * Whitebox attack surface flag forwarded into the {@link ToolContext} for
   * orchestrator-driven pentests. Defaults to `true` when undefined.
   */
  surfaceIntegrationEnabled?: boolean;

  /**
   * Project-level threat model content (e.g. from `.pensar/threat_model.md`).
   * Forwarded into the {@link ToolContext} so tools that spawn dedicated
   * per-endpoint threat-model sub-agents can include this as additional
   * grounding context.
   */
  projectThreatModel?: string;

  /**
   * Pre-constructed Playwright MCP browser session to use for this agent
   * instead of constructing a fresh one. Used by `spawn_pentest_agent` to
   * hand a worker a freshly-cloned-and-seeded session — fresh Chromium,
   * own MCP child-process, but pre-loaded with a snapshot of the
   * orchestrator's cookies + per-origin localStorage so the worker is
   * already authenticated for the same origins the orchestrator was.
   *
   * The agent does NOT share this session with any other agent at runtime
   * — each agent owns its own isolated Chromium and a sub-agent's
   * browser-side mutations (navigations, `localStorage.setItem`,
   * `browser_evaluate` calls, alerts, etc.) never leak back into the
   * caller's browser. Lifecycle of an externally-supplied session belongs
   * to whoever supplied it (e.g. `spawn_pentest_agent` disconnects the
   * worker session on completion).
   */
  browserSession?: PlaywrightMcpSession;

  /**
   * X display (e.g. `":11"`) for this agent's browser. Overrides
   * `process.env.DISPLAY` for the session this agent constructs, so several
   * headed agents in one process (concurrent per-endpoint pentests) each run
   * on their own virtual desktop. Ignored when `browserSession` is supplied
   * (that session already owns its display). Omit to fall back to the
   * process-wide `DISPLAY`.
   */
  display?: string;
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

  /** Display label forwarded to {@link OffensiveSecurityAgentInput} for span names. */
  subagentName?: string;

  /** Shared findings registry for cross-agent dedup */
  findingsRegistry?: FindingsRegistry;

  /** Shared attack surface registry for cross-agent asset dedup */
  attackSurfaceRegistry?: AttackSurfaceRegistry;

  /** In-memory credential store for secret-free agent prompts */
  credentialManager?: CredentialManager;

  /**
   * When set, tools route execution through this sandbox instead of running
   * locally. Shared by every specialized agent so the runtime can forward it
   * uniformly — individual agents no longer re-declare it.
   */
  sandbox?: UnifiedSandbox;

  /** Provider middleware applied only to this agent's model calls. Forwarded to the runtime. */
  languageModelMiddleware?: LanguageModelMiddleware | LanguageModelMiddleware[];

  /** Per-run usage recorder. Forwarded to the runtime. */
  usageRecorder?: UsageRecorder;

  /** Factory for streamed message/part ids. Forwarded to the runtime. */
  streamIdFactory?: StreamIdFactory;

  /**
   * Seam through which this agent's orchestration tools spawn sub-agents.
   * Forwarded (into the OffensiveSecurityAgent constructor) into the ToolContext;
   * unset → the in-process spawner, so behavior is unchanged. A durable runtime
   * injects a child-workflow spawner here so a specialized agent's fan-out (e.g.
   * spawn_coding_agent) becomes durable child workflows.
   */
  subagentSpawner?: SubagentSpawner;

  /**
   * Additional tools merged on top of the built-in toolset (same-named tools
   * override the built-ins). Forwarded (into the OffensiveSecurityAgent constructor)
   * so a durable runtime can swap `read_file`/`list_files`/`grep` for
   * sandbox-backed versions without touching the shared tool registry.
   */
  extraTools?: ToolSet;

  /** Override the default stop condition */
  stopWhen?: StopCondition<ToolSet>;

  /**
   * Environment variables to inject into the agent's persistent shell.
   * Forwarded to the underlying {@link OffensiveSecurityAgentInput}.
   */
  environmentVariables?: Record<string, string>;

  /** Secret values to scrub from execute_command output. Forwarded into the {@link ToolContext}. */
  secretValues?: string[];

  /** Enable extended thinking (reasoning) for supported models. */
  enableThinking?: boolean;

  /** Adaptive-thinking effort hint (Anthropic Opus/Sonnet 4.6+); ignored elsewhere. */
  thinkingEffort?: ThinkingEffort | null;

  /** OpenAI reasoning effort for GPT/o-series reasoning models. */
  openAIReasoningEffort?: OpenAIReasoningEffort | null;

  /**
   * Whitebox attack surface flag forwarded into the {@link ToolContext} for
   * orchestrator-driven pentests. Defaults to `true` when undefined.
   */
  surfaceIntegrationEnabled?: boolean;

  /**
   * Project-level threat model content. Forwarded into {@link ToolContext}
   * so per-endpoint threat-model sub-agents can incorporate it as grounding.
   */
  projectThreatModel?: string;

  /**
   * Pre-constructed Playwright MCP browser session for this sub-agent —
   * typically a freshly-cloned-and-seeded session built by
   * `spawn_pentest_agent` so the worker inherits the orchestrator's
   * cookies + localStorage but operates against its OWN isolated Chromium
   * (so its browser mutations don't leak back to the orchestrator or to
   * sibling workers). Forwarded to the underlying
   * {@link OffensiveSecurityAgentInput}.
   */
  browserSession?: PlaywrightMcpSession;

  /**
   * X display (e.g. `":11"`) for this agent's browser, forwarded to the
   * underlying {@link OffensiveSecurityAgentInput} so concurrent per-endpoint
   * pentests can each run headed on their own virtual desktop.
   */
  display?: string;
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
