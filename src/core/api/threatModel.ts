import {
  runWhiteboxAttackSurfaceWorkflow,
  type WhiteboxAttackSurfaceWorkflowInput,
} from "../workflows/whiteboxAttackSurface";
import {
  runThreatModelWorkflow,
  type ThreatModelWorkflowResult,
} from "../workflows/threatModel";
import type { AIModel } from "../ai";
import type { AIAuthConfig } from "../ai/utils";
import type { SessionInfo } from "../session";
import type { ConsumeCallbacks } from "../agents/offSecAgent/types";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ThreatModelInput {
  /** Local codebase path (required — threat model is whitebox-only) */
  cwd: string;

  model: AIModel;
  session: SessionInfo;
  authConfig?: AIAuthConfig;
  abortSignal?: AbortSignal;
  callbacks?: ConsumeCallbacks;
}

// ---------------------------------------------------------------------------
// Convenience runner
// ---------------------------------------------------------------------------

/**
 * Run standalone STRIDE threat model generation.
 *
 * Phase 1: Run whitebox attack surface discovery to map endpoints.
 * Phase 2: Run STRIDE threat model workflow (deployment context, security
 *           controls, synthesis).
 *
 * Outputs: stride-threat-model.md and stride-threat-model.json in the
 * session root directory.
 */
export async function runStrideThreatModel(
  input: ThreatModelInput,
): Promise<ThreatModelWorkflowResult> {
  const { cwd, model, session, authConfig, abortSignal, callbacks } = input;

  // Phase 1: Attack surface discovery
  const attackSurfaceInput: WhiteboxAttackSurfaceWorkflowInput = {
    codebasePath: cwd,
    model,
    session,
    authConfig,
    abortSignal,
    callbacks,
  };

  const attackSurface =
    await runWhiteboxAttackSurfaceWorkflow(attackSurfaceInput);

  // Phase 2: STRIDE threat model generation
  const result = await runThreatModelWorkflow({
    codebasePath: cwd,
    attackSurface,
    model,
    session,
    authConfig,
    abortSignal,
    callbacks,
  });

  return result;
}
