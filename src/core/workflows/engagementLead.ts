import { z } from "zod";
import { OffensiveSecurityAgent } from "../agents/offSecAgent";
import { AgentEventBus } from "../eventBus";
import type { FindingsRegistry } from "../findings/registry";
import type { SwarmTarget } from "../session/persistence";
import {
  buildEngagementState,
  type EngagementCheckpoint,
  type EngagementCompletion,
  EngagementStore,
  restoreEngagementState,
} from "./engagementState";
import {
  createEngagementSurfaceTools,
  ENGAGEMENT_SURFACE_TOOL_NAMES,
  type EngagementSurfaceProvider,
} from "./engagementSurface";
import {
  createEngagementTools,
  ENGAGEMENT_TOOL_NAMES,
} from "./engagementTools";
import type { PentestWorkflowInput } from "./pentest";

export const EngagementLeadResult = z.object({
  summary: z.string(),
  coverageComplete: z.boolean(),
  chainExploreSummary: z.string(),
});

export type EngagementLeadOutcome = z.infer<typeof EngagementLeadResult> & {
  checkpoint: EngagementCheckpoint;
};

export const ENGAGEMENT_LEAD_SYSTEM_PROMPT = `You are the durable lead penetration tester for one authorized engagement. You own the complete attack surface, threat-model objectives, coverage ledger, finding quality, and final chain-and-explore pass.

Work directly and delegate selectively. You have the same exploitation tools as workers and should personally test high-value hypotheses, interpret cross-service evidence, and maintain continuity. Spawn focused workers when independent context windows improve coverage or speed. Run independent assignments concurrently when safe; resume the same worker for stateful follow-ups. Fast Strike workers prove one concrete impact objective—they never decide that the engagement is complete.

Use read_engagement_state as the source of truth. Ensure every objective is terminal on at least one relevant service and every in-scope service receives baseline exploration. Coverage is service-based, not a Cartesian endpoint checklist. Discover net-new vulnerabilities and attack paths beyond the supplied objectives. Record reusable primitives as capabilities and resolve every supported next step by consuming it in a chain or marking it blocked with evidence.

You may call document_vulnerability directly. Findings still pass through the shared finding judge: document only reproducible exploitable vulnerabilities with material impact. Every finding must carry the sourceTargetId returned by the engagement-surface tools. Record material impact separately with record_impact_proof, referencing accepted findings, capabilities, artifacts, or trace observations.

Before finishing, perform chain-and-explore: combine confirmed primitives across services and attempt to reach crown-jewel impact. Update the chain coverage status honestly. The response tool is accepted only when the deterministic coverage gate is complete.`;

const LEAD_TOOL_NAMES = [
  "execute_command",
  "http_request",
  "document_vulnerability",
  "browser_navigate",
  "browser_snapshot",
  "browser_screenshot",
  "browser_click",
  "browser_fill",
  "browser_get_cookies",
  "read_file",
  "list_files",
  "glob",
  "grep",
  "profile_codebase",
  "query_whitebox_catalog",
  "run_code_query",
  "web_search",
  "get_page",
  "checkpoint_state",
  ...ENGAGEMENT_TOOL_NAMES,
  ...ENGAGEMENT_SURFACE_TOOL_NAMES,
  "response",
] as const;

function completionMessage(completion: EngagementCompletion): string {
  return [
    completion.missingObjectiveIds.length > 0
      ? `Objectives without terminal relevant-service coverage: ${completion.missingObjectiveIds.join(", ")}`
      : "",
    completion.missingServiceIds.length > 0
      ? `Services without baseline exploration: ${completion.missingServiceIds.join(", ")}`
      : "",
    completion.unresolvedCapabilityIds.length > 0
      ? `Capabilities with supported open edges: ${completion.unresolvedCapabilityIds.join(", ")}`
      : "",
    completion.chainExplorePending ? "Chain-and-explore is not terminal." : "",
  ]
    .filter(Boolean)
    .join(" ");
}

export async function runEngagementLead(input: {
  workflow: PentestWorkflowInput;
  targets: SwarmTarget[];
  findingsRegistry: FindingsRegistry;
  eventBus?: AgentEventBus;
  surfaceProvider?: EngagementSurfaceProvider;
}): Promise<EngagementLeadOutcome> {
  const eventBus = input.eventBus ?? new AgentEventBus();
  const leadAgentId = input.workflow.session.id;
  const seed = restoreEngagementState(
    buildEngagementState(
      input.workflow.target,
      input.targets,
      input.workflow.session.config?.prompt,
    ),
    input.workflow.messages,
  );
  const store = EngagementStore.open(input.workflow.session.rootPath, seed);
  store.reconcileInterruptedWorkers();
  const surfaceTools = input.surfaceProvider
    ? createEngagementSurfaceTools(input.surfaceProvider)
    : undefined;
  const engagementTargetIds = input.targets
    .map((target) => target.id)
    .filter((id): id is string => Boolean(id));
  const engagementTools = createEngagementTools({
    input: input.workflow,
    store,
    findingsRegistry: input.findingsRegistry,
    eventBus,
    leadAgentId,
    surfaceTools,
    engagementTargetIds,
  });
  const state = store.snapshot();
  const prompt = [
    `Root target: ${input.workflow.target}`,
    "The persisted engagement contract follows. Use IDs exactly when calling coordination tools.",
    JSON.stringify(
      {
        services: state.services,
        objectives: state.objectives,
        coverage: state.coverage,
        operatorContext: state.operatorContext,
      },
      null,
      2,
    ),
    "Begin by orienting across the full surface. Establish service baselines, execute each objective against a relevant service, preserve promising primitives, then run chain-and-explore toward crown-jewel impact.",
  ].join("\n\n");

  const agent = new OffensiveSecurityAgent<
    z.infer<typeof EngagementLeadResult>
  >({
    system: ENGAGEMENT_LEAD_SYSTEM_PROMPT,
    prompt,
    model: input.workflow.model,
    session: input.workflow.session,
    target: input.workflow.target,
    activeTools: [...LEAD_TOOL_NAMES],
    directTools: [
      ...ENGAGEMENT_TOOL_NAMES,
      ...(surfaceTools ? ENGAGEMENT_SURFACE_TOOL_NAMES : []),
    ],
    extraTools: engagementTools,
    engagementTargetIds:
      engagementTargetIds.length > 0 ? engagementTargetIds : undefined,
    responseSchema: EngagementLeadResult,
    responseGuard: (result) => {
      const completion = store.completion();
      if (!completion.complete) return completionMessage(completion);
      const parsed = EngagementLeadResult.safeParse(result);
      if (!parsed.success || !parsed.data.coverageComplete) {
        return "The response must acknowledge that deterministic engagement coverage is complete.";
      }
      return undefined;
    },
    findingsRegistry: input.findingsRegistry,
    messages: input.workflow.messages,
    authConfig: input.workflow.authConfig,
    abortSignal: input.workflow.abortSignal,
    eventBus,
    onStepFinish: input.workflow.onStepFinish,
    onCacheMetrics: input.workflow.onCacheMetrics,
    enableThinking: input.workflow.enableThinking,
    thinkingEffort: input.workflow.thinkingEffort,
    openAIReasoningEffort: input.workflow.openAIReasoningEffort,
    toolProtocol: input.workflow.toolProtocol,
    environmentVariables: input.workflow.environmentVariables,
    secretValues: input.workflow.secretValues,
    sandbox: input.workflow.sandbox,
    display: input.workflow.display,
  });

  const result = await agent.consume();
  return { ...result, checkpoint: store.checkpoint() };
}
