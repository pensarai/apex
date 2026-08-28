import type { StreamTextOnStepFinishCallback, ToolSet } from "ai";
import type {
  AIAuthConfig,
  AIModel,
  CacheMetrics,
  OpenAIReasoningEffort,
  ThinkingEffort,
} from "../../../ai";
import type { CredentialManager } from "../../../credentials";
import type { AgentEventBus } from "../../../eventBus";
import type { AttackSurfaceRegistry } from "../../../findings/attackSurfaceRegistry";
import type { FindingsRegistry } from "../../../findings/registry";
import type { PromptInjectionLibrary } from "../../../prompt-injections";
import type { SessionInfo } from "../../../session";
import type { SkillsRegistry } from "../../../skills/registry";
import type { GrpcPentestContext } from "../../specialized/attackSurface/grpcSchema";
import type { StepTraceWriter } from "../trace";
import type { PersistentShell } from "./persistentShell";
import type { PlaywrightMcpSession } from "./playwrightMcp";
import type { UnifiedSandbox } from "./sandbox";

/**
 * Shared context passed to every tool factory.
 *
 * Each tool receives what it needs from here — session paths,
 * abort signal, etc. — so individual tool files never import
 * session or agent internals directly.
 */
export type ToolContext = {
  /** Session providing paths for findings, POCs, logs, scratchpad, etc. */
  session: SessionInfo;

  /** The agent's operational working directory. Defaults to session.rootPath. */
  agentCwd: string;

  /** The target URL / host — needed by browser tools for context */
  target?: string;

  /**
   * gRPC context when the owning agent's target is a gRPC method. Set on a
   * pentest orchestrator so `spawn_pentest_agent` forwards it to workers,
   * which then run the gRPC test battery instead of HTTP-style tests.
   */
  grpc?: GrpcPentestContext;

  /** Signal to cancel in-flight operations */
  abortSignal?: AbortSignal;

  /** AI model — needed by tools that delegate to sub-agents */
  model?: AIModel;

  /** Per-provider API key overrides — needed by tools that spawn sub-agents */
  authConfig?: AIAuthConfig;

  /** Event bus for streaming agent output and subagent lifecycle events */
  eventBus?: AgentEventBus;

  /** Usage callbacks forwarded to sub-agents spawned by tools. */
  onStepFinish?: StreamTextOnStepFinishCallback<ToolSet>;
  onCacheMetrics?: (metrics: CacheMetrics) => void;

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
   * In-memory credential store. When present, tools can resolve
   * credential IDs to full secrets without the agent ever seeing them.
   */
  credentialManager?: CredentialManager;

  /** Secret values injected into the shell env; scrubbed from execute_command output. */
  secretValues?: string[];

  /**
   * Shell env this agent runs with. Tools that spawn a sub-agent forward it so
   * the child's shell resolves the same variables (credential secrets among
   * them) as the parent's.
   */
  environmentVariables?: Record<string, string>;

  /**
   * Long-lived bash process shared across execute_command calls.
   * Environment variables, working directory, and background processes
   * persist between invocations. Only used in local (non-sandbox) mode.
   */
  persistentShell?: PersistentShell;

  /**
   * Skills registry for on-demand skill loading.
   * When present, read_skill is available.
   */
  skillsRegistry?: SkillsRegistry;

  /**
   * Runtime-only prompt-injection payload resolver. Agents receive safe
   * metadata and IDs; tools resolve raw payloads only during execution.
   */
  promptInjectionLibrary?: PromptInjectionLibrary;

  /**
   * Local filesystem path for a prompt-injection payload library. When set,
   * tools load safe metadata and runtime payloads from this source instead of
   * shipping payloads inside Apex.
   */
  promptInjectionLibrarySource?: string;

  /**
   * Step trace writer for appending records to trace.jsonl.
   * When present, checkpoint_state tool is available.
   */
  traceWriter?: StepTraceWriter;

  /**
   * Per-agent task directory for structured task decomposition.
   * When present, task tools (create_task, update_task, list_tasks) are available.
   * Set to `{session.rootPath}/subagents/{subagentId}-tasks/` for subagents.
   * Only populated when `SessionConfig.taskDriven` is enabled.
   */
  tasksDir?: string;

  /** Enable extended thinking for sub-agents spawned by orchestration tools. */
  enableThinking?: boolean;

  /** Adaptive-thinking effort hint for spawned sub-agents (Anthropic 4.6+). */
  thinkingEffort?: ThinkingEffort | null;

  /** OpenAI reasoning effort for GPT/o-series sub-agents. */
  openAIReasoningEffort?: OpenAIReasoningEffort | null;

  /**
   * Whitebox attack surface flag. Forwarded into `runPentestWorkflow` so the
   * orchestrator-driven pentest path honors the user's config / env override.
   * Defaults to `true` when undefined.
   */
  surfaceIntegrationEnabled?: boolean;

  /**
   * Project-level threat model content (e.g. from `.pensar/threat_model.md`).
   * Passed to spawned per-endpoint threat-model sub-agents as additional
   * context so they can incorporate deployment details, compliance
   * requirements, or known concerns when analyzing each endpoint.
   */
  projectThreatModel?: string;

  /**
   * Override for plan file scoping. When set, write_plan uses this ID
   * instead of `subagentId` to derive the plan file path, allowing
   * plan agents to write plans scoped to their corresponding execution agent.
   */
  planSubagentId?: string;

  /** Owner subagent id — emitted as `parentSubagentId` on lifecycle events. */
  subagentId?: string;

  /**
   * Playwright MCP browser session for this agent's browser tools.
   *
   * When set, `createBrowserToolset` wires its browser tools through this
   * pre-constructed session instead of spinning up its own MCP
   * child-process / Chromium. This is how `spawn_pentest_agent` hands a
   * worker a session that was cloned from the orchestrator's session and
   * pre-seeded with the orchestrator's cookies + localStorage — the
   * worker is authenticated for the same origins as the orchestrator but
   * operates against an isolated Chromium so its actions do not leak back
   * to the orchestrator or to sibling workers.
   *
   * Lifecycle: when this field is set externally, the supplier owns
   * disconnect (e.g. `spawn_pentest_agent` tears down the worker's
   * session on completion). When unset, `createBrowserToolset` constructs
   * its own session and wires `abortSignal` to disconnect.
   */
  browserSession?: PlaywrightMcpSession;

  /**
   * X display (e.g. `":11"`) the owning agent's browser runs on. Spawn tools
   * pass it to worker sessions so a spawned worker's browser shares the same
   * virtual desktop instead of falling back to the process-wide `DISPLAY`.
   */
  display?: string;
};
