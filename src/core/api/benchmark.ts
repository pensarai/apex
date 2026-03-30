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

  agent.eventBus.on("text-delta", (d) => process.stdout.write(d.text));
  agent.eventBus.on("tool-call-complete", (d) =>
    console.log(`→ calling ${d.toolName}`),
  );
  agent.eventBus.on("tool-result", (d) =>
    console.log(`✓ ${d.toolName} completed`),
  );
  agent.eventBus.on("error", (d) => console.error("Agent error:", d.error));

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
