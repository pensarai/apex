import {
  BenchmarkComparisonAgent,
  type BenchmarkComparisonAgentInput,
} from "../agents/specialized/benchmarkComparisonAgent";
import { AgentEventBus } from "../agents/offSecAgent/eventBus";
// ---------------------------------------------------------------------------
// Convenience runner
// ---------------------------------------------------------------------------

export async function runBenchmarkComparisonAgent(
  input: BenchmarkComparisonAgentInput,
) {
  const eventBus = input.eventBus ?? new AgentEventBus();
  const agent = new BenchmarkComparisonAgent({ ...input, eventBus });

  const { comparison, resultsPath } = await agent.consume();

  if (comparison) {
    console.log(
      `\nComparison: ${comparison.matched.length}/${comparison.totalExpected} matched, ` +
        `Precision: ${Math.round(comparison.precision * 100)}%, ` +
        `Recall: ${Math.round(comparison.recall * 100)}%`,
    );
  }
  console.log(`Results: ${resultsPath}`);

  return { comparison, resultsPath };
}
