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
    process.stdout.write(`→ calling ${d.toolName}\n`),
  );
  agent.eventBus.on("tool-result", (d) =>
    process.stdout.write(`✓ ${d.toolName} completed\n`),
  );
  agent.eventBus.on("error", (d) =>
    process.stderr.write(`Agent error: ${d.error}\n`),
  );

  const { comparison, resultsPath } = await agent.consume();

  if (comparison) {
    process.stdout.write(
      `\nComparison: ${comparison.matched.length}/${comparison.totalExpected} matched, ` +
        `Precision: ${Math.round(comparison.precision * 100)}%, ` +
        `Recall: ${Math.round(comparison.recall * 100)}%\n`,
    );
  }
  process.stdout.write(`Results: ${resultsPath}\n`);

  return { comparison, resultsPath };
}
