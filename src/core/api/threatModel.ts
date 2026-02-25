import {
  runWhiteboxAttackSurfaceWorkflow,
  type WhiteboxAttackSurfaceWorkflowInput,
} from "../workflows/whiteboxAttackSurface";
import { Storage } from "../storage";
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

  /** Optional user-provided hint about what the application is (e.g. "AI browser automation framework") */
  applicationIdentity?: string;

  authConfig?: AIAuthConfig;
  abortSignal?: AbortSignal;
  callbacks?: ConsumeCallbacks;
}

// ---------------------------------------------------------------------------
// Convenience runner
// ---------------------------------------------------------------------------

/**
 * Run application-centric threat model generation.
 *
 * Phase 1: Run whitebox attack surface discovery to map endpoints.
 * Phase 2: Run threat model workflow (application context, deployment context,
 *           security controls, attack path synthesis).
 *
 * Outputs: threat-model.md and threat-model.json in the session root directory.
 */
export async function runStrideThreatModel(
  input: ThreatModelInput,
): Promise<ThreatModelWorkflowResult> {
  const { cwd, model, session, applicationIdentity, authConfig, abortSignal, callbacks } = input;

  // The whitebox attack surface workflow has two phases:
  //   Phase 1 (app discovery): passes direct callbacks to consume()
  //   Phase 2 (endpoint discovery): passes only subagentCallbacks to consume()
  //
  // consume() fires BOTH direct and subagentCallbacks for each event, so we
  // must not provide both pointing at the same handler or output is duplicated.
  //
  // Strategy: route all event handlers through subagentCallbacks only. The
  // workflow's Phase 1 consume() calls both pathways — but since we leave
  // the direct callbacks (onTextDelta etc.) undefined, only subagentCallbacks
  // fires. Phase 2 also uses subagentCallbacks, so both phases produce output.
  const attackSurfaceCallbacks: ConsumeCallbacks | undefined = callbacks
    ? {
        onError: callbacks.onError,
        subagentCallbacks: callbacks.subagentCallbacks ?? {
          onTextDelta: callbacks.onTextDelta
            ? (d) => callbacks.onTextDelta!(d)
            : undefined,
          onToolCall: callbacks.onToolCall
            ? (d) => callbacks.onToolCall!(d)
            : undefined,
          onToolResult: callbacks.onToolResult
            ? (d) => callbacks.onToolResult!(d)
            : undefined,
          onError: callbacks.onError,
        },
      }
    : undefined;

  // Phase 1: Attack surface discovery
  const attackSurfaceInput: WhiteboxAttackSurfaceWorkflowInput = {
    codebasePath: cwd,
    model,
    session,
    authConfig,
    abortSignal,
    callbacks: attackSurfaceCallbacks,
  };

  const attackSurface =
    await runWhiteboxAttackSurfaceWorkflow(attackSurfaceInput);

  // Write attack surface to disk for the threat model workflow to read
  await Storage.write(
    ["executions", session.id, "attack-surface-results"],
    attackSurface,
  );

  // Phase 2: STRIDE threat model generation
  // The threat model workflow passes direct callbacks to consume(), so we
  // pass the original callbacks as-is (no subagentCallbacks duplication risk
  // since the threat model workflow's CodeAgents don't spawn subagents).
  const result = await runThreatModelWorkflow({
    codebasePath: cwd,
    model,
    session,
    applicationIdentity,
    authConfig,
    abortSignal,
    callbacks,
  });

  return result;
}
