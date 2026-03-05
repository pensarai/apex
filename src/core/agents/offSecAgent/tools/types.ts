import type { AIModel } from "../../../ai";
import type { AIAuthConfig } from "../../../ai/utils";
import type { CredentialManager } from "../../../credentials";
import type { FindingsRegistry } from "../../../findings/registry";
import type { SessionInfo } from "../../../session";

import type { ConsumeCallbacks, SubagentConsumeCallbacks } from "../types";
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

  /** The target URL / host — needed by browser tools for context */
  target?: string;

  /** Signal to cancel in-flight operations */
  abortSignal?: AbortSignal;

  /** AI model — needed by tools that delegate to sub-agents */
  model?: AIModel;

  /** Per-provider API key overrides — needed by tools that spawn sub-agents */
  authConfig?: AIAuthConfig;

  /** Callbacks for forwarding subagent stream events to the parent consumer */
  subagentCallbacks?: SubagentConsumeCallbacks;
  callbacks?: ConsumeCallbacks;

  /**
   * When set, tools like execute_command / create_poc
   * route execution through this sandbox instead of running locally.
   */
  sandbox?: UnifiedSandbox;

  /**
   * Shared findings registry for cross-agent dedup.
   * When present, `document_vulnerability` checks for duplicates before writing.
   */
  findingsRegistry?: FindingsRegistry;

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
   * Side-channel callback for streaming raw stdout chunks from
   * execute_command back to the TUI while the command is still running.
   */
  onCommandOutput?: (data: string) => void;
};
