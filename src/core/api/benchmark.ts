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
  const eventBus = input.eventBus ?? (() => {
    const bus = new AgentEventBus();
    bus.on("text-delta", (e) => process.stdout.write(e.data.text));
    bus.on("tool-call", (e) => console.log(`→ calling ${e.data.toolName}`));
    bus.on("tool-result", (e) =>
      console.log(`✓ ${e.data.toolName} completed`),
    );
    bus.on("error", (e) => console.error("Agent error:", e.error));
    return bus;
  })();
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
