import type { AIModel } from "../../ai";
import type { AIAuthConfig } from "../../ai/utils";
import type { SessionInfo } from "../../session";

import type { ConsumeCallbacks, SubagentConsumeCallbacks } from "../types";

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
};
