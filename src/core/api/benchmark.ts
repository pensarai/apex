import {
  BenchmarkComparisonAgent,
  type BenchmarkComparisonAgentInput,
} from "../agents/benchmarkComparisonAgent";
// ---------------------------------------------------------------------------
// Convenience runner
// ---------------------------------------------------------------------------

export async function runBenchmarkComparisonAgent(
  input: BenchmarkComparisonAgentInput
) {
  const agent = new BenchmarkComparisonAgent(input);

  const { comparison, resultsPath } = await agent.consume({
    onTextDelta: (d) => process.stdout.write(d.text),
    onToolCall: (d) => console.log(`→ calling ${d.toolName}`),
    onToolResult: (d) => console.log(`✓ ${d.toolName} completed`),
    onError: (e) => console.error("Agent error:", e),
  });

  if (comparison) {
    console.log(
      `\nComparison: ${comparison.matched.length}/${comparison.totalExpected} matched, ` +
        `Precision: ${Math.round(comparison.precision * 100)}%, ` +
        `Recall: ${Math.round(comparison.recall * 100)}%`
    );
  }
  console.log(`Results: ${resultsPath}`);

  return { comparison, resultsPath };
}
