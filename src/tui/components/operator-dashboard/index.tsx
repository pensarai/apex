/**
 * Operator Dashboard
 *
 * Thin wrapper around the unified Session component for operator mode.
 * Provides operator-specific configuration and routing.
 */

import { Session as SessionComponent } from "../../session";
import type { Session } from "../../../core/session";

interface OperatorDashboardProps {
  session: Session.SessionInfo;
  /** If true, restore saved state from disk instead of starting fresh */
  isResume?: boolean;
}

/**
 * Operator Dashboard - uses unified Session component in operator mode
 */
export default function OperatorDashboard({ session, isResume = false }: OperatorDashboardProps) {
  return (
    <SessionComponent
      session={session}
      mode="operator"
      isResume={isResume}
    />
  );
}

// Re-export types for backward compatibility
export type { Endpoint, VerifiedVuln, Credential, Hypothesis, Evidence } from "./types";
