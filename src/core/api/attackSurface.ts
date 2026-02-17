import {
  AttackSurfaceAgent,
  type AttackSurfaceAgentInput,
} from "../agents/attackSurfaceAgent/agent";
// ---------------------------------------------------------------------------
// Convenience runner
// ---------------------------------------------------------------------------

export async function runAttackSurfaceAgent(input: AttackSurfaceAgentInput) {
  const agent = new AttackSurfaceAgent(input);

  const { results, targets, resultsPath, assetsPath } = await agent.consume({
    onTextDelta: (d) => process.stdout.write(d.text),
    onToolCall: (d) => console.log(`→ calling ${d.toolName}`),
    onToolResult: (d) => console.log(`✓ ${d.toolName} completed`),
    onError: (e) => console.error("Agent error:", e),
  });

  console.log(`\nIdentified ${targets.length} targets for deep testing`);
  console.log(`Results: ${resultsPath}`);
  console.log(`Assets: ${assetsPath}`);

  return { results, targets, resultsPath, assetsPath };
}
