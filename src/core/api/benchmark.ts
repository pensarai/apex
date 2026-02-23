import {
  BenchmarkComparisonAgent,
  type BenchmarkComparisonAgentInput,
  type BenchmarkComparisonResult,
} from "../agents/specialized/benchmarkComparisonAgent";
import { AgentRun } from "./agentRun";

// ---------------------------------------------------------------------------
// Convenience runner
// ---------------------------------------------------------------------------

export function runBenchmarkComparisonAgent(
  input: Omit<BenchmarkComparisonAgentInput, "eventBus">,
): AgentRun<BenchmarkComparisonResult> {
  return new AgentRun(async (eventBus) => {
    const agent = new BenchmarkComparisonAgent({ ...input, eventBus });
    return agent.consume();
  });
}
