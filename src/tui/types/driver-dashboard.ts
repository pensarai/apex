/**
 * Type definitions for the Driver Dashboard
 * Used in driver mode for manual agent orchestration
 */

import type { PentestTarget } from "../../core/agent/attackSurfaceAgent/types";
import type { DisplayMessage } from "../components/agent-display";
import type { Session } from "../../core/session";

/**
 * Endpoint discovered during recon
 */
export interface DiscoveredEndpoint {
  id: string;
  url: string;
  method: string;
  suggestedObjective: string;
  source: 'recon' | 'manual';
}

/**
 * Status of a driver mode agent
 */
export type DriverAgentStatus = 'idle' | 'running' | 'paused' | 'completed' | 'failed';

/**
 * Interface for the DriverModeAgent wrapper
 */
export interface IDriverModeAgent {
  /** Start agent with extracted target/objective */
  start(target: PentestTarget): Promise<void>;

  /** Inject user instruction to pivot/redirect agent */
  injectUserMessage(message: string): Promise<void>;

  /** Pause execution (can be resumed) */
  pause(): void;

  /** Resume after pause */
  resume(): void;

  /** Stop completely */
  stop(): void;

  /** Current status */
  readonly status: DriverAgentStatus;
}

/**
 * Agent instance in the driver dashboard
 */
export interface DriverAgent {
  id: string;
  name: string;
  target: PentestTarget;
  status: DriverAgentStatus;
  messages: DisplayMessage[];
  createdAt: Date;
  /** Reference to the running agent instance */
  agentRef?: IDriverModeAgent;
}

/**
 * State for the driver dashboard
 */
export interface DriverDashboardState {
  session: Session.SessionInfo;
  endpoints: DiscoveredEndpoint[];
  agents: DriverAgent[];
  reconStatus: 'idle' | 'running' | 'completed';
  activeAgentId: string | null;
  focusedView: 'overview' | 'agent-chat';
}

/**
 * Events streamed from driver mode agent
 */
export interface DriverAgentStreamEvent {
  agentId: string;
  type: 'message' | 'tool-call' | 'tool-result' | 'status-change';
  data: DisplayMessage | { status: DriverAgentStatus };
}

/**
 * Result from driver mode agent completion
 */
export interface DriverAgentResult {
  agentId: string;
  vulnerabilitiesFound: boolean;
  findingsCount: number;
  pocPaths: string[];
  findingPaths: string[];
  summary: string;
  error?: string;
}
