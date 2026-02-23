import {
  BlackboxAttackSurfaceAgent,
  type AttackSurfaceAgentInput,
  type AttackSurfaceResult,
} from "../agents/specialized/attackSurface/blackboxAgent";
import type { WhiteboxAttackSurfaceResult } from "../agents/specialized/whiteboxAttackSurface";
import { runWhiteboxAttackSurfaceWorkflow } from "../workflows/whiteboxAttackSurface";
import { AgentRun } from "./agentRun";

// ---------------------------------------------------------------------------
// Unified input — accepts both blackbox and whitebox configurations
// ---------------------------------------------------------------------------

export type AttackSurfaceInput = Omit<AttackSurfaceAgentInput, "eventBus">;

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
export function runAttackSurfaceAgent(
  input: Omit<AttackSurfaceAgentInput, "eventBus">,
): AgentRun<AttackSurfaceResult | WhiteboxAttackSurfaceResult> {
  const isWhitebox = "cwd" in input && !!input.cwd;

  if (isWhitebox) {
    const whiteboxInput = input as Omit<AttackSurfaceAgentInput, "eventBus"> & { cwd: string };
    return new AgentRun(async (eventBus) => {
      return runWhiteboxAttackSurface(whiteboxInput, eventBus);
    });
  }

  return new AgentRun(async (eventBus) => {
    return runBlackboxAttackSurface(input, eventBus);
  });
}

// ---------------------------------------------------------------------------
// Blackbox (live target probing)
// ---------------------------------------------------------------------------

async function runBlackboxAttackSurface(
  input: Omit<AttackSurfaceAgentInput, "eventBus">,
  eventBus: import("../agents/offSecAgent/eventBus").AgentEventBus,
): Promise<AttackSurfaceResult> {
  const agent = new BlackboxAttackSurfaceAgent({
    ...input,
    eventBus,
  } as AttackSurfaceAgentInput);
  return agent.consume();
}

// ---------------------------------------------------------------------------
// Whitebox (source code analysis)
// ---------------------------------------------------------------------------

async function runWhiteboxAttackSurface(
  input: Omit<AttackSurfaceAgentInput, "eventBus"> & { cwd: string },
  eventBus: import("../agents/offSecAgent/eventBus").AgentEventBus,
): Promise<WhiteboxAttackSurfaceResult> {
  return runWhiteboxAttackSurfaceWorkflow({
    codebasePath: input.cwd,
    model: input.model,
    session: input.session,
    authConfig: input.authConfig,
    abortSignal: input.abortSignal,
    eventBus,
  });
}
