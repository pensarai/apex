/**
 * Pentest Workflow API Types
 *
 * Type definitions for the console-facing pentest API.
 */

import type { AIModel } from "../core/ai";
import type { Session } from "../core/session";
import type {
  Finding,
  VulnerabilityClass,
  SubAgentManifest,
  FileAccessConfig,
} from "../core/agent/subagent/types";
import type { RunSubAgentResult } from "../core/agent/subagent";

// Re-export core types for consumers
export type {
  AIModel,
  Finding,
  VulnerabilityClass,
  SubAgentManifest,
  FileAccessConfig,
  RunSubAgentResult,
};

// Re-export Session namespace types
export type AuthCredentials = Session.AuthCredentials;
export type ScopeConstraints = Session.ScopeConstraints;
export type SessionConfig = Session.SessionConfig;

/**
 * Progress callbacks that fire during pentest execution
 */
export interface PentestCallbacks {
  /** Called when execution enters a new phase */
  onPhaseChange?: (
    phase: "enumeration" | "attack-surface" | "orchestrator" | "testing"
  ) => void;
  /** Called when a subagent starts testing */
  onSubagentStart?: (id: string, endpoint: string, vulnClass: string) => void;
  /** Called when a subagent completes */
  onSubagentComplete?: (result: RunSubAgentResult) => void;
  /** Called when a finding is discovered */
  onFindingDiscovered?: (finding: Finding) => void;
}

/**
 * Tool override functions for sandboxed execution
 */
export interface ToolOverride {
  execute_command?: (opts: {
    command: string;
    timeout?: number;
    background?: boolean;
    toolCallDescription?: string;
  }) => Promise<{
    success: boolean;
    stdout: string;
    stderr: string;
    error?: string;
    command?: string;
  }>;
  http_request?: (opts: {
    url: string;
    method?: string;
    headers?: Record<string, string>;
    body?: string;
    timeout?: number;
  }) => Promise<{
    success: boolean;
    status: number;
    statusText: string;
    headers: Record<string, string>;
    body: string;
    error?: string;
  }>;
}

/**
 * Input for whitebox pentest (single endpoint with source code access)
 */
export interface WhiteboxPentestInput {
  /** Target endpoint URL to test */
  endpoint: string;
  /** Absolute path to source code directory */
  sourceCodePath: string;
  /** AI model to use (default: claude-sonnet-4-5) */
  model?: AIModel;
  /** Optional authentication credentials */
  authCredentials?: Session.AuthCredentials;
  /** Per-subagent timeout in milliseconds */
  timeout?: number;
  /** Resume an existing session by ID */
  sessionId?: string;
  /** Progress callbacks */
  callbacks?: PentestCallbacks;
  /** Maximum parallel subagents (default: 10) */
  concurrency?: number;
  /** Custom session name */
  sessionName?: string;
  /** Optional tool override for sandboxed execution */
  toolOverride?: ToolOverride;
}

/**
 * Input for blackbox pentest (full domain scan)
 */
export interface BlackboxPentestInput {
  /** Target domain or base URL */
  target: string;
  /** AI model to use (default: claude-sonnet-4-5) */
  model?: AIModel;
  /** Maximum parallel subagents (default: 10) */
  concurrency?: number;
  /** Skip katana+feroxagent enumeration step */
  skipEnumeration?: boolean;
  /** Optional authentication credentials */
  authCredentials?: Session.AuthCredentials;
  /** Scope constraints for testing */
  scopeConstraints?: Session.ScopeConstraints;
  /** Resume an existing session by ID */
  sessionId?: string;
  /** Progress callbacks */
  callbacks?: PentestCallbacks;
  /** Per-subagent timeout in milliseconds */
  timeout?: number;
  /** Paths to block from file access (sandbox) */
  blockedPaths?: string[];
  /** Block Docker container access */
  blockDocker?: boolean;
  /** Custom session name */
  sessionName?: string;
}

/**
 * Input for resuming an existing pentest session
 */
export interface ResumePentestInput {
  /** Session ID to resume */
  sessionId: string;
  /** AI model to use (overrides session's original model) */
  model?: AIModel;
  /** Progress callbacks */
  callbacks?: PentestCallbacks;
  /** Maximum parallel subagents (default: 10) */
  concurrency?: number;
}

/**
 * Statistics about the pentest execution
 */
export interface PentestStats {
  /** Total number of subagents that were run */
  subagentsRun: number;
  /** Number of subagents that completed successfully */
  subagentsSucceeded: number;
  /** Total number of findings discovered */
  totalFindings: number;
  /** Number of critical severity findings */
  criticalFindings: number;
  /** Number of high severity findings */
  highFindings: number;
  /** Number of medium severity findings */
  mediumFindings: number;
  /** Number of low severity findings */
  lowFindings: number;
}

/**
 * Result of a pentest execution
 */
export interface PentestResult {
  /** Whether the pentest completed successfully */
  success: boolean;
  /** Session ID (for resumption) */
  sessionId: string;
  /** Full path to the session directory */
  sessionPath: string;
  /** All discovered vulnerabilities */
  findings: Finding[];
  /** Human-readable summary of results */
  summary: string;
  /** Execution statistics */
  stats: PentestStats;
  /** Error message if the pentest failed */
  error?: string;
  /** The subagent manifest that was used */
  manifest?: SubAgentManifest;
}

/**
 * Session state for determining resume point
 */
export type SessionPhase =
  | "not-started"
  | "enumeration"
  | "attack-surface"
  | "orchestrator"
  | "testing"
  | "completed";

/**
 * Internal session state info
 */
export interface SessionState {
  phase: SessionPhase;
  hasEnumerationResults: boolean;
  hasAttackSurfaceResults: boolean;
  hasManifest: boolean;
  completedSubagents: string[];
  totalSubagents: number;
}
