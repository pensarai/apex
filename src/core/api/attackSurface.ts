import {
  type AttackSurfaceAgentInput,
  type AttackSurfaceResult,
  BlackboxAttackSurfaceAgent,
} from "../agents/specialized/attackSurface/blackboxAgent";
import {
  GeneralizedAttackSurfaceAgent,
  type GeneralizedAttackSurfaceAgentInput,
  type GeneralizedAttackSurfaceResult,
} from "../agents/specialized/attackSurface/generalizedAgent";
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
// Generalized (origin-driven, app-level threat models)
// ---------------------------------------------------------------------------

export type {
  GeneralizedAttackSurfaceAgentInput,
  GeneralizedAttackSurfaceResult,
} from "../agents/specialized/attackSurface/generalizedAgent";

/**
 * Run the generalized, origin-driven attack-surface agent. Given only an
 * origin, it discovers the services hosted there, maps them to connected
 * repositories where applicable, and produces application-level threat models
 * and pentest objectives.
 */
export async function runGeneralizedAttackSurface(
  input: GeneralizedAttackSurfaceAgentInput,
): Promise<GeneralizedAttackSurfaceResult> {
  const agent = new GeneralizedAttackSurfaceAgent(input);
  return agent.consume();
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
    surfaceIntegrationEnabled: input.surfaceIntegrationEnabled,
    enableThinking: input.enableThinking,
    thinkingEffort: input.thinkingEffort,
    openAIReasoningEffort: input.openAIReasoningEffort,
    reasoning: input.reasoning,
  });

  console.log(
    `\nWhitebox analysis complete: ${result.summary.totalApps} apps, ` +
      `${result.summary.totalApiEndpoints} API endpoints, ` +
      `${result.summary.totalPages} pages`,
  );

  return result;
}
