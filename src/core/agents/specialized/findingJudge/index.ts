/**
 * Finding Judge
 *
 * Agentic validation for submitted findings. The judge runs after the POC
 * exits successfully and before persistence to catch hallucinated findings,
 * hardcoded evidence, and mismatched claims.
 */

import type { AIModel } from "../../../ai";
import type { ToolContext } from "../../offSecAgent/tools";
import type {
  FindingJudgeAgentOutput,
  FindingJudgeInput,
  FindingJudgeResult,
} from "./types";

export {
  buildFindingJudgePrompt,
  FINDING_JUDGE_SYSTEM_PROMPT,
} from "./prompts";
export {
  FINDING_TYPES,
  type FindingJudgeAgentOutput,
  type FindingJudgeInput,
  FindingJudgeOutputSchema,
  type FindingJudgeResult,
  type FindingJudgeVerificationDetails,
  type FindingType,
} from "./types";

export type FindingJudgeRuntimeContext = Pick<
  ToolContext,
  | "session"
  | "authConfig"
  | "abortSignal"
  | "eventBus"
  | "sandbox"
  | "target"
  | "enableThinking"
> & {
  model: AIModel;
};

/**
 * Validate a vulnerability finding by running a bounded verifier agent.
 *
 * Infrastructure failures intentionally preserve the already-successful
 * POC-backed finding with low confidence and explicit unverified metadata.
 */
export async function judgeFinding(
  input: FindingJudgeInput,
  ctx: FindingJudgeRuntimeContext,
): Promise<FindingJudgeResult> {
  try {
    // Lazy import avoids the tool-registry cycle:
    // offSec tools -> documentFinding -> findingJudge -> OffensiveSecurityAgent.
    const { FindingJudgeAgent } = await import("./agent");
    const agent = new FindingJudgeAgent({
      finding: input,
      model: ctx.model,
      session: ctx.session,
      authConfig: ctx.authConfig,
      abortSignal: ctx.abortSignal,
      eventBus: ctx.eventBus,
      sandbox: ctx.sandbox,
      target: input.target ?? ctx.target ?? ctx.session.targets[0],
      enableThinking: ctx.enableThinking,
    });

    const result = await agent.consume();
    if (!result) {
      throw new Error("Finding judge agent finished without a response.");
    }

    return normalizeJudgeResult(result);
  } catch (err: unknown) {
    const fallback = createJudgeFailureResult(err, ctx.model);
    console.error(
      `[FindingJudge] Agentic validation failed: model=${fallback.error?.model} type=${fallback.error?.type} message=${fallback.error?.message}`,
    );
    return fallback;
  }
}

function normalizeJudgeResult(
  result: FindingJudgeAgentOutput,
): FindingJudgeResult {
  return {
    valid: result.valid,
    findingType: result.findingType,
    confidence: result.confidence,
    reasoning: result.reasoning,
    concerns: result.concerns,
    verificationSteps: result.verificationSteps,
    toolEvidence: result.toolEvidence,
    reproducedPoc: result.reproducedPoc,
    webResearchUsed: result.webResearchUsed,
    limitations: result.limitations,
  };
}

export function createJudgeFailureResult(
  err: unknown,
  model: AIModel,
): FindingJudgeResult {
  const errObj =
    typeof err === "object" && err !== null
      ? (err as Record<string, unknown>)
      : {};
  const message = err instanceof Error ? err.message : String(err);
  const type = err instanceof Error ? err.constructor.name : typeof err;
  const stack = err instanceof Error ? err.stack : undefined;
  const statusCode = errObj.status ?? errObj.statusCode ?? errObj.code;
  const statusStr = statusCode != null ? ` [status=${statusCode}]` : "";
  const isAbort =
    err instanceof Error &&
    (err.name === "AbortError" || err.constructor.name === "DOMException");
  const confidence = isAbort ? 0.3 : 0.4;
  const diagnostic = `${type}${statusStr}: ${message.substring(0, 200)}`;

  return {
    valid: true,
    findingType: "vulnerability",
    confidence,
    reasoning: `Agentic finding judge could not complete (${diagnostic}). Preserving the successfully executed PoC-backed finding as unverified with low confidence so it is not lost.`,
    concerns: [
      "Agentic judge infrastructure failed before producing a completed verification judgment.",
      "Finding is preserved because the submitted PoC already executed successfully, but the judge did not independently verify the claim.",
    ],
    verificationSteps: [],
    toolEvidence: [],
    reproducedPoc: false,
    webResearchUsed: false,
    limitations: [
      "No independent judge verification was completed due to infrastructure failure.",
    ],
    error: {
      message: `${message}${statusStr}`,
      type,
      model: String(model ?? "undefined"),
      stack: stack?.substring(0, 500),
    },
  };
}
