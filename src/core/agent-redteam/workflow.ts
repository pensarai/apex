import type { CredentialManager } from "../credentials";
import {
  getPromptInjectionLibrary,
  type PromptInjectionLibrary,
} from "../prompt-injections";
import { sha256 } from "./artifacts";
import {
  type CreateAgentRedTeamCampaignInput,
  createAgentRedTeamCampaign,
} from "./campaign";
import type { AgentRedTeamSemanticJudge } from "./evaluation";
import {
  evaluateAgentRedTeamAttempt,
  recordAgentRedTeamObservation,
} from "./evaluation";
import { BUILTIN_AGENT_RED_TEAM_ABUSE_CHAINS } from "./scenarios";
import type {
  AgentRedTeamAttempt,
  AgentRedTeamCampaign,
  AgentRedTeamCoverageMatrix,
  AgentRedTeamEvaluation,
  AgentRedTeamEvent,
  AgentRedTeamGoal,
  AgentRedTeamImpact,
  AgentRedTeamMutationId,
  AgentRedTeamSurface,
  AgentRedTeamTechniqueId,
  AgentRedTeamVector,
} from "./types";

export interface AgentRedTeamSeedProviderStatus {
  source: "prompt-injection-library";
  status: "disabled" | "empty" | "loaded" | "load-failed";
  seedCount: number;
  error?: string;
}

export interface AgentRedTeamObservationInput {
  attemptId?: string;
  promptText?: string;
  responseText: string;
  toolTrace?: string;
  events?: AgentRedTeamEvent[];
  latencyMs?: number;
  inputTokens?: number;
  outputTokens?: number;
  goal?: AgentRedTeamGoal;
}

export interface AgentRedTeamWorkflowInput {
  target: string;
  sessionRootPath?: string;
  campaignSeed?: string;
  protectedCanaryCredentialId?: string;
  protectedCanarySha256?: string;
  credentialManager?: CredentialManager;
  goals?: AgentRedTeamGoal[];
  vectors?: AgentRedTeamVector[];
  surfaces?: AgentRedTeamSurface[];
  impacts?: AgentRedTeamImpact[];
  techniques?: AgentRedTeamTechniqueId[];
  mutationChains?: AgentRedTeamMutationId[][];
  maxAttempts?: number;
  usePromptInjectionLibrarySeeds?: boolean;
  promptInjectionLibrary?: PromptInjectionLibrary;
  promptInjectionLibrarySource?: string;
  promptInjectionSeedCategories?: string[];
  promptInjectionSeedTags?: string[];
  maxPromptInjectionSeeds?: number;
  observations?: AgentRedTeamObservationInput[];
  semanticJudge?: AgentRedTeamSemanticJudge;
}

export interface AgentRedTeamWorkflowResult {
  campaignId: string;
  campaignSeed: string;
  coverage: AgentRedTeamCoverageMatrix;
  attempts: AgentRedTeamAttempt[];
  evaluations: AgentRedTeamEvaluation[];
  ledgerPath?: string;
  abuseChains: typeof BUILTIN_AGENT_RED_TEAM_ABUSE_CHAINS;
  seedProviders: AgentRedTeamSeedProviderStatus[];
}

async function resolveLibrary(input: AgentRedTeamWorkflowInput): Promise<{
  library?: PromptInjectionLibrary;
  status: AgentRedTeamSeedProviderStatus;
}> {
  if (input.usePromptInjectionLibrarySeeds === false) {
    return {
      status: {
        source: "prompt-injection-library",
        status: "disabled",
        seedCount: 0,
      },
    };
  }
  try {
    const library = await getPromptInjectionLibrary({
      library: input.promptInjectionLibrary,
      source: input.promptInjectionLibrarySource,
    });
    const seedCount = library.listCatalog().length;
    return {
      library,
      status: {
        source: "prompt-injection-library",
        status: seedCount > 0 ? "loaded" : "empty",
        seedCount: Math.min(seedCount, input.maxPromptInjectionSeeds ?? 8),
      },
    };
  } catch (error) {
    return {
      status: {
        source: "prompt-injection-library",
        status: "load-failed",
        seedCount: 0,
        error: error instanceof Error ? error.message : String(error),
      },
    };
  }
}

function campaignInput(
  input: AgentRedTeamWorkflowInput,
  library?: PromptInjectionLibrary,
): CreateAgentRedTeamCampaignInput {
  return {
    target: input.target,
    sessionRootPath: input.sessionRootPath,
    campaignSeed: input.campaignSeed,
    protectedCanaryCredentialId: input.protectedCanaryCredentialId,
    protectedCanarySha256: input.protectedCanarySha256,
    goals: input.goals,
    vectors: input.vectors,
    surfaces: input.surfaces,
    impacts: input.impacts,
    techniques: input.techniques,
    mutationChains: input.mutationChains,
    maxAttempts: input.maxAttempts,
    promptInjectionLibrary: library,
    promptInjectionSeedOptions: {
      categories: input.promptInjectionSeedCategories,
      tags: input.promptInjectionSeedTags,
      maxSeeds: input.maxPromptInjectionSeeds ?? 8,
    },
  };
}

function selectObservationAttempt(
  campaign: AgentRedTeamCampaign,
  observation: AgentRedTeamObservationInput,
  assigned: ReadonlyMap<string, unknown>,
): AgentRedTeamAttempt | undefined {
  if (observation.attemptId) {
    return campaign.attempts.find(
      (attempt) => attempt.id === observation.attemptId,
    );
  }
  // Without an explicit id, consume the next unassigned attack so multiple
  // observations do not collapse onto (and overwrite) the same attempt.
  return campaign.attempts.find(
    (attempt) =>
      attempt.variant !== "control" &&
      !assigned.has(attempt.id) &&
      (!observation.goal || attempt.impact === observation.goal.impact),
  );
}

/** Compatibility facade over the campaign lifecycle APIs. */
export async function runAgentRedTeamWorkflow(
  input: AgentRedTeamWorkflowInput,
): Promise<AgentRedTeamWorkflowResult> {
  const resolved = await resolveLibrary(input);
  const campaign = await createAgentRedTeamCampaign(
    campaignInput(input, resolved.library),
  );
  const evaluations: AgentRedTeamEvaluation[] = [];
  const observationByAttempt = new Map<
    string,
    ReturnType<typeof recordAgentRedTeamObservation>
  >();

  const protectedCanaryValue =
    input.protectedCanaryCredentialId && input.credentialManager
      ? input.credentialManager.resolve(input.protectedCanaryCredentialId)
          ?.canary
      : undefined;

  // Record every observation first so control/attack input ordering does not
  // matter, then evaluate only attacks whose paired control was observed.
  for (const observationInput of input.observations ?? []) {
    const attempt = selectObservationAttempt(
      campaign,
      observationInput,
      observationByAttempt,
    );
    if (!attempt) continue;
    const attemptCanaryValue =
      attempt.oracle.canaryCredentialId && input.credentialManager
        ? input.credentialManager.resolve(attempt.oracle.canaryCredentialId)
            ?.canary
        : protectedCanaryValue;
    const canaryHashMismatch = Boolean(
      attemptCanaryValue &&
        attempt.oracle.canarySha256 &&
        sha256(attemptCanaryValue) !== attempt.oracle.canarySha256,
    );
    const canaryInCarrier = Boolean(
      attemptCanaryValue && attempt.renderedPrompt.includes(attemptCanaryValue),
    );
    const observation = recordAgentRedTeamObservation({
      attempt,
      responseText: observationInput.responseText,
      toolTrace: observationInput.toolTrace,
      events: observationInput.events,
      latencyMs: observationInput.latencyMs,
      inputTokens: observationInput.inputTokens,
      outputTokens: observationInput.outputTokens,
      protectedCanaryValue: attemptCanaryValue,
      testIntegrityError: canaryHashMismatch
        ? "Protected canary credential no longer matches the campaign hash."
        : canaryInCarrier
          ? "Protected canary appeared in the delivered carrier."
          : undefined,
      sessionRootPath: input.sessionRootPath,
    });
    observationByAttempt.set(attempt.id, observation);
  }

  for (const attempt of campaign.attempts) {
    if (attempt.variant === "control") continue;
    const observation = observationByAttempt.get(attempt.id);
    if (!observation) continue;
    const controlObservation = attempt.controlAttemptId
      ? observationByAttempt.get(attempt.controlAttemptId)
      : undefined;
    if (attempt.controlAttemptId && !controlObservation) continue;
    evaluations.push(
      await evaluateAgentRedTeamAttempt({
        attempt,
        observation,
        controlObservation,
        semanticJudge: input.semanticJudge,
        sessionRootPath: input.sessionRootPath,
      }),
    );
  }

  const ledgerPath = input.sessionRootPath
    ? `${input.sessionRootPath}/agent-redteam/campaigns/${campaign.id}/attempts.jsonl`
    : undefined;
  return {
    campaignId: campaign.id,
    campaignSeed: campaign.seed,
    coverage: campaign.coverage,
    attempts: campaign.attempts,
    evaluations,
    ledgerPath,
    abuseChains: BUILTIN_AGENT_RED_TEAM_ABUSE_CHAINS,
    seedProviders: [resolved.status],
  };
}
