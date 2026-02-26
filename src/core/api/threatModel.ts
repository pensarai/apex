import {
  runThreatModelWorkflow,
  type ThreatModelWorkflowInput,
} from "../workflows/threatModel";
import type { ThreatModelResult } from "../agents/specialized/threatModel/types";
import { AgentRun } from "./agentRun";

// ---------------------------------------------------------------------------
// Input type
// ---------------------------------------------------------------------------

export type ThreatModelInput = Omit<ThreatModelWorkflowInput, "eventBus">;

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

/**
 * Run the application-centric threat model workflow.
 *
 * Phase 0: Application Context Discovery
 * Phase 1a: Attack Surface Reconnaissance
 * Phase 1b: Deployment Context
 * Phase 1c: Security Controls
 * Phase 2: Architecture Synthesis
 * Phase 3: Attack Path Synthesis
 * Phase 4: Assembly + Serialization
 */
export function runThreatModelAgent(
  input: ThreatModelInput,
): AgentRun<ThreatModelResult> {
  return new AgentRun(async (eventBus) => {
    return runThreatModelWorkflow({ ...input, eventBus });
  });
}
