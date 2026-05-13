import type { AIAuthConfig, AIModel } from "../../../ai";
import type { CredentialManager } from "../../../credentials";
import type { AgentEventBus } from "../../../eventBus";
import type { AttackSurfaceRegistry } from "../../../findings/attackSurfaceRegistry";
import type { FindingsRegistry } from "../../../findings/registry";
import type { SessionInfo } from "../../../session";
import type { SkillsRegistry } from "../../../skills/registry";
import type { StepTraceWriter } from "../trace";
import type { PersistentShell } from "./persistentShell";
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

  /** Signal to cancel in-flight operations */
  abortSignal?: AbortSignal;

  /** AI model — needed by tools that delegate to sub-agents */
  model?: AIModel;

  /** Per-provider API key overrides — needed by tools that spawn sub-agents */
  authConfig?: AIAuthConfig;

  /** Event bus for streaming agent output and subagent lifecycle events */
  eventBus?: AgentEventBus;

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
};
