import {
  BlackboxAttackSurfaceAgent,
  type AttackSurfaceAgentInput,
} from "../agents/specialized/attackSurface/blackboxAgent";
// ---------------------------------------------------------------------------
// Convenience runner
// ---------------------------------------------------------------------------

export async function runAttackSurfaceAgent(input: AttackSurfaceAgentInput) {
  const agent = new BlackboxAttackSurfaceAgent(input);

  const { results, targets, resultsPath, assetsPath } = await agent.consume({
    onTextDelta: (d) => input.callbacks?.onTextDelta?.(d),
    onToolCall: (d) => input.callbacks?.onToolCall?.(d),
    onToolResult: (d) => input.callbacks?.onToolResult?.(d),
    onError: (e) => input.callbacks?.onError?.(e),
  });

  console.log(`\nIdentified ${targets.length} targets for deep testing`);
  console.log(`Results: ${resultsPath}`);
  console.log(`Assets: ${assetsPath}`);

  return { results, targets, resultsPath, assetsPath };
}
