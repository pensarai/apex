import {
  BenchmarkComparisonAgent,
  type BenchmarkComparisonAgentInput,
} from "../agents/specialized/benchmarkComparisonAgent";
import { AgentRun } from "./agentRun";

export function runBenchmarkComparisonAgent(
  input: BenchmarkComparisonAgentInput,
) {
  return new AgentRun(async (_eventBus) => {
    const agent = new BenchmarkComparisonAgent(input);
    const { comparison, resultsPath } = await agent.consume();
    return { comparison, resultsPath };
  });
}
