import {
  runThreatModelWorkflow as _runThreatModelWorkflow,
  type ThreatModelWorkflowInput,
  type ThreatModelWorkflowResult,
} from "../workflows/threatModel";
import { AgentRun } from "./agentRun";

export type { ThreatModelWorkflowInput, ThreatModelWorkflowResult };

export function runThreatModelWorkflow(
  input: Omit<ThreatModelWorkflowInput, "eventBus">,
): AgentRun<ThreatModelWorkflowResult> {
  return new AgentRun(async (eventBus) => {
    return _runThreatModelWorkflow({ ...input, eventBus });
  });
}
