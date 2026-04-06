import {
  BenchmarkComparisonAgent,
  type BenchmarkComparisonAgentInput,
} from "../agents/specialized/benchmarkComparisonAgent";
// ---------------------------------------------------------------------------
// Convenience runner
// ---------------------------------------------------------------------------

export async function runBenchmarkComparisonAgent(
  input: BenchmarkComparisonAgentInput,
) {
  const agent = new BenchmarkComparisonAgent(input);

  const { comparison, resultsPath } = await agent.consume();

  return { comparison, resultsPath };
}
