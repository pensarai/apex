/**
 * Operator Dashboard
 *
 * Thin wrapper around the unified Session component for operator mode.
 * Provides operator-specific configuration and routing.
 */

import { sessions } from "../../../core/session";

interface OperatorDashboardProps {
  sessionId: string;
  /** If true, restore saved state from disk instead of starting fresh */
  isResume?: boolean;
  /** If true, synthesize operator context from swarm session data */
  openAsOperator?: boolean;
}

/**
 * Operator Dashboard - uses unified Session component in operator mode
 */
export default function OperatorDashboard({
  sessionId,
  isResume = false,
  openAsOperator,
}: OperatorDashboardProps) {
  const session = sessions.get(sessionId);
  return <text>Operator Dashboard</text>;
}

// Re-export types for backward compatibility
export type {
  Endpoint,
  VerifiedVuln,
  Credential,
  Hypothesis,
  Evidence,
} from "./types";
