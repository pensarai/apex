import type { AIModel } from "../../../ai";
import type { AIAuthConfig } from "../../../ai/utils";
import type { FindingsRegistry } from "../../../findings/registry";
import type { SessionInfo } from "../../../session";

import type { ConsumeCallbacks, SubagentConsumeCallbacks } from "../types";
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
   * When set, tools like execute_command / http_request / create_poc
   * route execution through this sandbox instead of running locally.
   */
  sandbox?: UnifiedSandbox;

  /**
   * Shared findings registry for cross-agent dedup.
   * When present, `document_finding` checks for duplicates before writing.
   */
  findingsRegistry?: FindingsRegistry;
};
