/**
 * Operator Dashboard
 *
 * Thin wrapper around the unified Session component for operator mode.
 * Provides operator-specific configuration and routing.
 */

import type { SessionInfo } from "../../../core/session";

interface OperatorDashboardProps {
  session: SessionInfo;
  /** If true, restore saved state from disk instead of starting fresh */
  isResume?: boolean;
  /** If true, synthesize operator context from swarm session data */
  openAsOperator?: boolean;
}

/**
 * Operator Dashboard - uses unified Session component in operator mode
 */
export default function OperatorDashboard({
  session,
  isResume = false,
  openAsOperator,
}: OperatorDashboardProps) {
  return null;
}

// Re-export types for backward compatibility
export type {
  Endpoint,
  VerifiedVuln,
  Credential,
  Hypothesis,
  Evidence,
} from "./types";
