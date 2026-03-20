import type { ConsumeCallbacks } from "../agents/offSecAgent/types";
import type { AIModel } from "../ai/ai";
import type { AIAuthConfig } from "../ai/utils";
import type { SessionInfo } from "../session";
import type {
  ThreatModelAgentResult,
  ThreatModelResult,
} from "../agents/specialized/threatModel/types";
import { CodeAgent } from "../agents/specialized/codeAgent/agent";
import { threatModelCommand, assembleResult } from "../commands/threatModel";

// ---------------------------------------------------------------------------
// Input
// ---------------------------------------------------------------------------

export interface ThreatModelInput {
  cwd: string;
  model: AIModel;
  session: SessionInfo;
  applicationIdentity?: string;
  authConfig?: AIAuthConfig;
  abortSignal?: AbortSignal;
  callbacks?: ConsumeCallbacks;
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

/**
 * Run the threat model agent and return the assembled result.
 *
 * Creates a {@link CodeAgent} configured with the threat model prompts and
 * response schema, consumes the agent stream, then assembles the final
 * {@link ThreatModelResult} with computed metadata and summary.
 */
export async function runThreatModelAgent(
  input: ThreatModelInput,
): Promise<ThreatModelResult> {
  const {
    cwd,
    model,
    session,
    applicationIdentity,
    authConfig,
    abortSignal,
    callbacks,
  } = input;

  const agent = new CodeAgent<ThreatModelAgentResult>({
    codebasePath: cwd,
    objective: threatModelCommand.buildPrompt({
      cwd,
      session,
      applicationIdentity,
    }),
    system: threatModelCommand.system,
    responseSchema: threatModelCommand.responseSchema,
    model,
    session,
    authConfig,
    abortSignal,
    callbacks,
  });

  const agentResult = await agent.consume(callbacks);

  const modelStr = typeof model === "string" ? model : String(model);
  const ctx = { session, cwd, model: modelStr };

  await threatModelCommand.onResult(agentResult, ctx);

  return assembleResult(agentResult, ctx);
}
