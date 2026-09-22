/**
 * Finding Judge
 *
 * Agentic validation for submitted findings. The judge runs after the POC
 * exits successfully and before persistence to catch hallucinated findings,
 * hardcoded evidence, and mismatched claims.
 */

import type { AIModel } from "../../../ai";
import { createLogger } from "../../../logger/structured";
import { scopedLogger } from "../../../util/lazyLogger";
import type { CodeCellResult } from "../../offSecAgent/codeMode/runtime";
import type { ToolContext } from "../../offSecAgent/tools";
import type {
  FindingJudgeAgentOutput,
  FindingJudgeInput,
  FindingJudgeResult,
} from "./types";

const log = scopedLogger(() => createLogger("FindingJudge"));

export type {
  FindingJudgeAgentOutput,
  FindingJudgeInput,
  FindingJudgeResult,
  FindingType,
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
  | "thinkingEffort"
  | "openAIReasoningEffort"
  | "toolProtocol"
  | "engagementContext"
  | "onStepFinish"
> & {
  model: AIModel;
  onCodeCellComplete?: (result: CodeCellResult) => void;
  /**
   * Subagent id used to tag the judge's own stream events. Callers that
   * spawn the judge as a nested subagent must pass the same id they
   * emitted in the `subagent-spawn` lifecycle event so the live UI and
   * persisted logs line up. Defaults to `"finding-judge"`.
   */
  subagentId?: string;
  /** Human-readable label for readable OTel span names. Defaults to "Finding Judge". */
  subagentName?: string;
};

/**
 * Validate a vulnerability finding by running a bounded verifier agent.
 *
 * Infrastructure failures reject the finding as unverified rather than
 * preserving it as a vulnerability.
 */
export async function judgeFinding(
  input: FindingJudgeInput,
  ctx: FindingJudgeRuntimeContext,
): Promise<FindingJudgeResult> {
  let failure: unknown;
  for (let attempt = 1; attempt <= 2; attempt += 1) {
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
        subagentId: ctx.subagentId,
        subagentName: ctx.subagentName,
        sandbox: ctx.sandbox,
        target: input.target ?? ctx.target ?? ctx.session.targets[0],
        enableThinking: ctx.enableThinking,
        thinkingEffort: ctx.thinkingEffort,
        openAIReasoningEffort: ctx.openAIReasoningEffort,
        toolProtocol: ctx.toolProtocol,
        engagementContext: ctx.engagementContext,
        onStepFinish: ctx.onStepFinish,
        onCodeCellComplete: ctx.onCodeCellComplete,
      });

      const result = await agent.consume();
      if (!result) {
        throw new Error("Finding judge agent finished without a response.");
      }

      const contextReceipt = input.sourceTargetId
        ? ctx.engagementContext
            ?.receipts()
            .find((receipt) => receipt.targetId === input.sourceTargetId)
        : undefined;
      return normalizeJudgeResult(result, contextReceipt);
    } catch (error: unknown) {
      failure = error;
      if (ctx.abortSignal?.aborted) break;
      if (attempt === 1) {
        log.warn("Finding validation failed; retrying once", {
          model: ctx.model,
          message: error instanceof Error ? error.message : String(error),
        });
      }
    }
  }
  const fallback = createJudgeFailureResult(failure, ctx.model);
  log.warn("Agentic validation failed", {
    model: fallback.error?.model,
    type: fallback.error?.type,
    message: fallback.error?.message,
  });
  return fallback;
}

function normalizeJudgeResult(
  result: FindingJudgeAgentOutput,
  contextReceipt?: FindingJudgeResult["contextReceipt"],
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
    ...(contextReceipt && { contextReceipt }),
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
    valid: false,
    findingType: "informational",
    confidence,
    reasoning: `Agentic finding judge could not complete (${diagnostic}). Rejecting the finding as unverified so unavailable judge infrastructure does not preserve false positives as vulnerabilities.`,
    concerns: [
      "Agentic judge infrastructure failed before producing a completed verification judgment.",
      "The submitted PoC may have executed successfully, but the judge did not independently verify that it proves a material vulnerability.",
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
