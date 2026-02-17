import {
  BlackboxAttackSurfaceAgent,
  type AttackSurfaceAgentInput,
  type AttackSurfaceResult,
} from "../agents/specialized/attackSurface/blackboxAgent";
import {
  WhiteboxAttackSurfaceAgent,
  type WhiteboxAttackSurfaceAgentInput,
  type WhiteboxAttackSurfaceResult,
} from "../agents/specialized/whiteboxAttackSurface";

// ---------------------------------------------------------------------------
// Unified input — accepts both blackbox and whitebox configurations
// ---------------------------------------------------------------------------

export type AttackSurfaceInput = AttackSurfaceAgentInput;

// ---------------------------------------------------------------------------
// Convenience runners
// ---------------------------------------------------------------------------

/**
 * Run the appropriate attack surface agent based on the input.
 *
 * - If `cwd` is provided (and no `target`), runs the **whitebox** agent
 *   which analyzes source code directly to map endpoints and pages.
 * - Otherwise, runs the **blackbox** agent which probes a live target
 *   from the outside.
 */
export async function runAttackSurfaceAgent(
  input: AttackSurfaceAgentInput,
): Promise<AttackSurfaceResult | WhiteboxAttackSurfaceResult> {
  const isWhitebox = "cwd" in input && input.cwd && !input.target;

  if (isWhitebox) {
    return runWhiteboxAttackSurface(
      input as AttackSurfaceAgentInput & { cwd: string },
    );
  }

  return runBlackboxAttackSurface(input);
}

// ---------------------------------------------------------------------------
// Blackbox (live target probing)
// ---------------------------------------------------------------------------

async function runBlackboxAttackSurface(
  input: AttackSurfaceAgentInput,
): Promise<AttackSurfaceResult> {
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

// ---------------------------------------------------------------------------
// Whitebox (source code analysis)
// ---------------------------------------------------------------------------

async function runWhiteboxAttackSurface(
  input: AttackSurfaceAgentInput & { cwd: string },
): Promise<WhiteboxAttackSurfaceResult> {
  const whiteboxInput: WhiteboxAttackSurfaceAgentInput = {
    codebasePath: input.cwd,
    model: input.model,
    session: input.session,
    authConfig: input.authConfig,
    onStepFinish: input.onStepFinish,
    abortSignal: input.abortSignal,
    callbacks: input.callbacks,
  };

  const agent = new WhiteboxAttackSurfaceAgent(whiteboxInput);

  const result = await agent.consume({
    onTextDelta: (d) => input.callbacks?.onTextDelta?.(d),
    onToolCall: (d) => input.callbacks?.onToolCall?.(d),
    onToolResult: (d) => input.callbacks?.onToolResult?.(d),
    onError: (e) => input.callbacks?.onError?.(e),
  });

  console.log(
    `\nWhitebox analysis complete: ${result.summary.totalApps} apps, ` +
      `${result.summary.totalApiEndpoints} API endpoints, ` +
      `${result.summary.totalPages} pages`,
  );

  return result;
}
