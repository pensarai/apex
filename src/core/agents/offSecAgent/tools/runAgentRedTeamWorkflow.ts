import { tool } from "ai";
import { z } from "zod";
import type {
  AgentRedTeamImpact,
  AgentRedTeamMutationId,
  AgentRedTeamSurface,
  AgentRedTeamTechniqueId,
  AgentRedTeamVector,
} from "../../../agent-redteam";
import {
  AGENT_RED_TEAM_IMPACTS,
  AGENT_RED_TEAM_MUTATIONS,
  AGENT_RED_TEAM_SURFACES,
  AGENT_RED_TEAM_TECHNIQUES,
  AGENT_RED_TEAM_VECTORS,
  runAgentRedTeamWorkflow as runWorkflow,
  sha256,
} from "../../../agent-redteam";
import type { ToolContext } from "./types";

const vectorSchema = z.enum(
  AGENT_RED_TEAM_VECTORS as [AgentRedTeamVector, ...AgentRedTeamVector[]],
);
const surfaceSchema = z.enum(
  AGENT_RED_TEAM_SURFACES as [AgentRedTeamSurface, ...AgentRedTeamSurface[]],
);
const impactSchema = z.enum(
  AGENT_RED_TEAM_IMPACTS as [AgentRedTeamImpact, ...AgentRedTeamImpact[]],
);
const techniqueSchema = z.enum(
  AGENT_RED_TEAM_TECHNIQUES as [
    AgentRedTeamTechniqueId,
    ...AgentRedTeamTechniqueId[],
  ],
);
const mutationSchema = z.enum(
  AGENT_RED_TEAM_MUTATIONS.map((mutation) => mutation.id) as [
    AgentRedTeamMutationId,
    ...AgentRedTeamMutationId[],
  ],
);

const goalSchema = z.object({
  id: z.string().describe("Stable operator-facing goal id"),
  description: z
    .string()
    .describe("Authorized behavior or boundary being tested"),
  impact: impactSchema,
  canaryCredentialId: z
    .string()
    .optional()
    .describe("Credential ID containing a protected red-team canary"),
});

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

const observationSchema = z.object({
  attemptId: z.string().optional(),
  promptText: z.string().optional(),
  responseText: z.string().describe("Observed target response text"),
  toolTrace: z.string().optional(),
  events: z.array(eventSchema).optional(),
  latencyMs: z.number().nonnegative().optional(),
  inputTokens: z.number().int().nonnegative().optional(),
  outputTokens: z.number().int().nonnegative().optional(),
  goal: goalSchema.optional(),
});

export function runAgentRedTeamWorkflow(ctx: ToolContext) {
  return tool({
    description: `Create an Apex agent red-team campaign for an LLM-backed application or agentic system.

The campaign contains versioned attack/control pairs across direct and indirect prompt injection, tool and MCP poisoning, memory and delegation boundaries, prompt leakage, encoding/stego bypasses, multi-turn attacks, and bounded resource tests. Coverage is planned only; it becomes observed or vulnerable after attempts are delivered and evaluated.

This tool never resolves raw external-library payloads. Library attempts contain PromptInjectionRef ids and hashes only.`,
    inputSchema: z.object({
      target: z.string().optional(),
      goals: z.array(goalSchema).optional(),
      protectedCanaryCredentialId: z.string().optional(),
      vectors: z.array(vectorSchema).optional(),
      surfaces: z.array(surfaceSchema).optional(),
      impacts: z.array(impactSchema).optional(),
      techniques: z.array(techniqueSchema).optional(),
      mutationChains: z.array(z.array(mutationSchema)).optional(),
      maxAttempts: z.number().int().min(1).max(200).default(64),
      usePromptInjectionLibrarySeeds: z.boolean().default(true),
      promptInjectionSeedCategories: z.array(z.string()).optional(),
      promptInjectionSeedTags: z.array(z.string()).optional(),
      maxPromptInjectionSeeds: z.number().int().min(0).max(100).default(8),
      observations: z.array(observationSchema).optional(),
      toolCallDescription: z.string(),
    }),
    execute: async (input) => {
      const target = input.target ?? ctx.target ?? ctx.session.targets[0];
      if (!target) {
        return {
          success: false,
          message:
            "run_agent_redteam_workflow requires a target or a session target.",
        };
      }

      try {
        const canaryCredential = input.protectedCanaryCredentialId
          ? ctx.credentialManager?.resolve(input.protectedCanaryCredentialId)
          : undefined;
        if (
          input.protectedCanaryCredentialId &&
          (!canaryCredential || !canaryCredential.canary)
        ) {
          return {
            success: false,
            message: `Protected canary credential ${input.protectedCanaryCredentialId} is unavailable or has no canary value.`,
          };
        }
        const result = await runWorkflow({
          target,
          sessionRootPath: ctx.session.rootPath,
          protectedCanaryCredentialId: input.protectedCanaryCredentialId,
          protectedCanarySha256: canaryCredential?.canary
            ? sha256(canaryCredential.canary)
            : undefined,
          credentialManager: ctx.credentialManager,
          goals: input.goals,
          vectors: input.vectors,
          surfaces: input.surfaces,
          impacts: input.impacts,
          techniques: input.techniques,
          mutationChains: input.mutationChains,
          maxAttempts: input.maxAttempts,
          usePromptInjectionLibrarySeeds: input.usePromptInjectionLibrarySeeds,
          promptInjectionLibrary: ctx.promptInjectionLibrary,
          promptInjectionLibrarySource: ctx.promptInjectionLibrarySource,
          promptInjectionSeedCategories: input.promptInjectionSeedCategories,
          promptInjectionSeedTags: input.promptInjectionSeedTags,
          maxPromptInjectionSeeds: input.maxPromptInjectionSeeds,
          observations: input.observations,
        });

        return {
          success: true,
          target,
          campaignId: result.campaignId,
          totalAttempts: result.attempts.length,
          ledgerPath: result.ledgerPath,
          seedProviders: result.seedProviders,
          coverage: summarizeCoverage(result.coverage),
          attempts: result.attempts.map((attempt) => ({
            id: attempt.id,
            campaignId: attempt.campaignId,
            vector: attempt.vector,
            surface: attempt.surface,
            impact: attempt.impact,
            techniqueId: attempt.techniqueId,
            mutationChain: attempt.mutationChain,
            carrierId: attempt.carrierId,
            carrierVersion: attempt.carrierVersion,
            carrierLabel: attempt.carrierLabel,
            variant: attempt.variant,
            status: attempt.status,
            comparisonGroupId: attempt.comparisonGroupId,
            controlAttemptId: attempt.controlAttemptId,
            turns: attempt.turns,
            oracle: attempt.oracle,
            primitiveStack: attempt.primitiveStack,
            ablationGroupId: attempt.ablationGroupId,
            ablatedPrimitiveId: attempt.ablatedPrimitiveId,
            expectedDetectorBlindSpot: attempt.expectedDetectorBlindSpot,
            renderedPrompt: attempt.renderedPrompt,
            seed: attempt.seed,
            carrierFeatures: attempt.carrierFeatures,
          })),
          evaluations: result.evaluations,
          abuseChains: result.abuseChains,
          message: `Generated ${result.attempts.length} planned attempts in campaign ${result.campaignId}.`,
        };
      } catch (error) {
        return {
          success: false,
          message: error instanceof Error ? error.message : String(error),
        };
      }
    },
  });
}

function summarizeCoverage(
  coverage: Awaited<ReturnType<typeof runWorkflow>>["coverage"],
) {
  return {
    vectors: coverage.vectors,
    surfaces: coverage.surfaces,
    impacts: coverage.impacts,
    techniques: coverage.techniques,
    planned: {
      vectors: coverage.vectors.filter((item) => item.status === "planned")
        .length,
      surfaces: coverage.surfaces.filter((item) => item.status === "planned")
        .length,
      impacts: coverage.impacts.filter((item) => item.status === "planned")
        .length,
      techniques: coverage.techniques.filter(
        (item) => item.status === "planned",
      ).length,
    },
  };
}
