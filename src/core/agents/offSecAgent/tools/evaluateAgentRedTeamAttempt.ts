import { tool } from "ai";
import { z } from "zod";
import {
  AgentRedTeamAttemptLedger,
  evaluateAgentRedTeamAttempt as evaluateAttempt,
  recordAgentRedTeamObservation,
  sha256,
} from "../../../agent-redteam";
import {
  getPromptInjectionLibrary,
  redactPromptInjectionPayloads,
} from "../../../prompt-injections";
import { createAgentRedTeamSemanticJudge } from "../../specialized/agentRedTeamJudge";
import type { ToolContext } from "./types";

const eventSchema = z.object({
  kind: z.enum([
    "tool-invocation",
    "external-communication",
    "state-change",
    "memory-write",
    "memory-read",
    "tenant-access",
    "session-reset",
    "resource-usage",
    "error",
  ]),
  name: z.string().optional(),
  target: z.string().optional(),
  value: z.union([z.number(), z.string(), z.boolean()]).optional(),
  details: z.string().optional(),
  observedAt: z.string().optional(),
});

export function evaluateAgentRedTeamAttempt(ctx: ToolContext) {
  return tool({
    description: `Record and evaluate one delivered agent-red-team campaign attempt.

Evaluate the control attempt before its paired attack. The tool stores redacted target artifacts, applies deterministic canary/tool/state/memory/tenant/resource oracles, and uses the specialized semantic judge only for policy-behavior comparisons.`,
    inputSchema: z.object({
      campaignId: z.string(),
      attemptId: z.string(),
      responseText: z.string(),
      toolTrace: z.string().optional(),
      events: z.array(eventSchema).default([]),
      latencyMs: z.number().nonnegative().optional(),
      inputTokens: z.number().int().nonnegative().optional(),
      outputTokens: z.number().int().nonnegative().optional(),
      toolCallDescription: z.string(),
    }),
    execute: async (input) => {
      const ledger = new AgentRedTeamAttemptLedger(
        ctx.session.rootPath,
        input.campaignId,
      );
      const campaign = ledger.readCampaign();
      if (!campaign) {
        return {
          success: false,
          message: `Unknown agent red-team campaign: ${input.campaignId}`,
        };
      }
      const attempt = campaign.attempts.find(
        (candidate) => candidate.id === input.attemptId,
      );
      if (!attempt) {
        return {
          success: false,
          message: `Unknown attempt ${input.attemptId} in campaign ${input.campaignId}.`,
        };
      }

      let responseText = input.responseText;
      let toolTrace = input.toolTrace;
      let events = input.events;
      if (ctx.promptInjectionLibrary || ctx.promptInjectionLibrarySource) {
        const library = await getPromptInjectionLibrary({
          library: ctx.promptInjectionLibrary,
          source: ctx.promptInjectionLibrarySource,
        });
        responseText = redactPromptInjectionPayloads(responseText, library);
        toolTrace = toolTrace
          ? redactPromptInjectionPayloads(toolTrace, library)
          : undefined;
        events = events.map((event) => ({
          ...event,
          name: event.name
            ? redactPromptInjectionPayloads(event.name, library)
            : undefined,
          target: event.target
            ? redactPromptInjectionPayloads(event.target, library)
            : undefined,
          value:
            typeof event.value === "string"
              ? redactPromptInjectionPayloads(event.value, library)
              : event.value,
          details: event.details
            ? redactPromptInjectionPayloads(event.details, library)
            : undefined,
        }));
      }

      const canaryCredentialId = attempt.oracle.canaryCredentialId;
      const protectedCanaryValue = canaryCredentialId
        ? ctx.credentialManager?.resolve(canaryCredentialId)?.canary
        : undefined;
      const canaryHashMismatch = Boolean(
        protectedCanaryValue &&
          attempt.oracle.canarySha256 &&
          sha256(protectedCanaryValue) !== attempt.oracle.canarySha256,
      );
      const canaryInCarrier = Boolean(
        protectedCanaryValue &&
          attempt.renderedPrompt.includes(protectedCanaryValue),
      );
      const observation = recordAgentRedTeamObservation({
        attempt,
        responseText,
        toolTrace,
        events,
        latencyMs: input.latencyMs,
        inputTokens: input.inputTokens,
        outputTokens: input.outputTokens,
        protectedCanaryValue,
        testIntegrityError: canaryHashMismatch
          ? "Protected canary credential no longer matches the campaign hash."
          : canaryInCarrier
            ? "Protected canary appeared in the delivered carrier."
            : undefined,
        sessionRootPath: ctx.session.rootPath,
      });

      if (attempt.variant === "control") {
        return {
          success: true,
          recordedControl: true,
          campaignId: campaign.id,
          attemptId: attempt.id,
          observationId: observation.id,
          message:
            "Control observation recorded. Deliver the paired attack next.",
        };
      }

      const observations = ledger.readObservations();
      const controlObservation = attempt.controlAttemptId
        ? [...observations]
            .reverse()
            .find((item) => item.attemptId === attempt.controlAttemptId)
        : undefined;
      if (attempt.controlAttemptId && !controlObservation) {
        return {
          success: false,
          needsControl: true,
          observationId: observation.id,
          controlAttemptId: attempt.controlAttemptId,
          message: `Record control attempt ${attempt.controlAttemptId} before evaluating this attack.`,
        };
      }

      const semanticJudge = ctx.model
        ? createAgentRedTeamSemanticJudge({
            model: ctx.model,
            authConfig: ctx.authConfig,
            abortSignal: ctx.abortSignal,
            openAIReasoningEffort: ctx.openAIReasoningEffort,
            sessionId: ctx.session.id,
          })
        : undefined;
      const evaluation = await evaluateAttempt({
        attempt,
        observation,
        controlObservation,
        semanticJudge,
        sessionRootPath: ctx.session.rootPath,
      });
      return {
        success: true,
        evaluation,
        message: `Attempt ${attempt.id} evaluated as ${evaluation.verdict} (${evaluation.evidenceStrength}, confidence ${evaluation.confidence.toFixed(2)}).`,
      };
    },
  });
}
