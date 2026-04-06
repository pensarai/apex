import {
  BlackboxAttackSurfaceAgent,
  type AttackSurfaceAgentInput,
  type AttackSurfaceResult,
} from "../agents/specialized/attackSurface/blackboxAgent";
import type { WhiteboxAttackSurfaceResult } from "../agents/specialized/whiteboxAttackSurface";
import { runWhiteboxAttackSurfaceWorkflow } from "../workflows/whiteboxAttackSurface";
import { AgentRun } from "./agentRun";

export type AttackSurfaceInput = AttackSurfaceAgentInput;

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
export function runAttackSurfaceAgent(
  input: Omit<AttackSurfaceAgentInput, "eventBus">,
): AgentRun<AttackSurfaceResult | WhiteboxAttackSurfaceResult> {
  return new AgentRun(async (eventBus) => {
    const isWhitebox = "cwd" in input && !!input.cwd;

    if (isWhitebox) {
      return runWhiteboxAttackSurfaceWorkflow({
        codebasePath: (input as AttackSurfaceAgentInput & { cwd: string }).cwd,
        model: input.model,
        session: input.session,
        authConfig: input.authConfig,
        abortSignal: input.abortSignal,
        attackSurfaceRegistry: input.attackSurfaceRegistry,
        eventBus,
      });
    }

    const agent = new BlackboxAttackSurfaceAgent({
      ...input,
      eventBus,
    } as AttackSurfaceAgentInput);
    const { results, targets, resultsPath, assetsPath } =
      await agent.consume();
    return { results, targets, resultsPath, assetsPath };
  });
}
