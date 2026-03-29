import {
  BlackboxAttackSurfaceAgent,
  type AttackSurfaceAgentInput,
  type AttackSurfaceResult,
} from "../agents/specialized/attackSurface/blackboxAgent";
import type { WhiteboxAttackSurfaceResult } from "../agents/specialized/whiteboxAttackSurface";
import { runWhiteboxAttackSurfaceWorkflow } from "../workflows/whiteboxAttackSurface";

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
 * - If `cwd` is provided, runs the **whitebox** agent which analyzes
 *   source code directly to map endpoints and pages.
 * - Otherwise, runs the **blackbox** agent which probes a live target
 *   from the outside.
 *
 * `target` is always required (the live URL to test against).
 */
export async function runAttackSurfaceAgent(
  input: AttackSurfaceAgentInput,
): Promise<AttackSurfaceResult | WhiteboxAttackSurfaceResult> {
  const isWhitebox = "cwd" in input && !!input.cwd;

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

  const { results, targets, resultsPath, assetsPath } = await agent.consume();

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
  const result = await runWhiteboxAttackSurfaceWorkflow({
    codebasePath: input.cwd,
    model: input.model,
    session: input.session,
    authConfig: input.authConfig,
    abortSignal: input.abortSignal,
    attackSurfaceRegistry: input.attackSurfaceRegistry,
    eventBus: input.eventBus,
  });

  console.log(
    `\nWhitebox analysis complete: ${result.summary.totalApps} apps, ` +
      `${result.summary.totalApiEndpoints} API endpoints, ` +
      `${result.summary.totalPages} pages`,
  );

  return result;
}
