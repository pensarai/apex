import { z } from "zod";
import { OffensiveSecurityAgent } from "../agents/offSecAgent";
import { AgentEventBus } from "../eventBus";
import type { FindingsRegistry } from "../findings/registry";
import type { SwarmTarget } from "../session/persistence";
import { runDeterministicEngagementCoverage } from "./engagementCoverage";
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
import { EngagementWorkerPool } from "./engagementWorkerPool";
import type { PentestWorkflowInput } from "./pentest";

export const EngagementLeadResult = z.object({
  summary: z.string(),
  coverageComplete: z.boolean(),
  chainExploreSummary: z.string(),
});

export type EngagementLeadOutcome = z.infer<typeof EngagementLeadResult> & {
  checkpoint: EngagementCheckpoint;
};

export const DEFAULT_ENGAGEMENT_WORKER_CONCURRENCY = 4;

export const ENGAGEMENT_LEAD_SYSTEM_PROMPT = `You are the durable lead penetration tester for one authorized engagement. You own the complete attack surface, threat-model objectives, coverage ledger, finding quality, and final chain-and-explore pass.

Deterministic endpoint-local coverage runs beside you automatically. Work directly and delegate selectively: personally test high-value hypotheses, resolve cells marked needs-lead, interpret cross-service evidence, and maintain continuity. Spawn focused workers when independent context windows improve validation or chaining; do not duplicate pending or running automatic coverage, and resume the same worker for stateful follow-ups. Fast Strike workers prove one concrete impact objective—they never decide that the engagement is complete.

Use read_engagement_state as the source of truth: every objective attached to every target must become terminal; objectives are never copied onto unrelated targets. Discover net-new vulnerabilities and attack paths beyond the supplied objectives. Record reusable primitives with their source target IDs as capabilities and resolve every supported next step by consuming it in a chain or marking it blocked with evidence. Give chain and validation workers exact target and capability IDs.

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
    completion.missingCoverageCellIds.length > 0
      ? `Target coverage cells still open: ${completion.missingCoverageCellIds.slice(0, 20).join(", ")}`
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
  concurrency?: number;
  onCheckpoint?: (checkpoint: EngagementCheckpoint) => void | Promise<void>;
}): Promise<EngagementLeadOutcome> {
  const eventBus = input.eventBus ?? new AgentEventBus();
  const internalAbort = new AbortController();
  const abortSignal = input.workflow.abortSignal
    ? AbortSignal.any([input.workflow.abortSignal, internalAbort.signal])
    : internalAbort.signal;
  const workflow = { ...input.workflow, abortSignal };
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
  const workerPool = new EngagementWorkerPool(
    input.concurrency ?? DEFAULT_ENGAGEMENT_WORKER_CONCURRENCY,
  );
  const engagementTools = createEngagementTools({
    input: workflow,
    store,
    findingsRegistry: input.findingsRegistry,
    eventBus,
    leadAgentId,
    surfaceTools,
    engagementTargetIds,
    workerPool,
    onCheckpoint: input.onCheckpoint,
  });
  const state = store.snapshot();
  const prompt = [
    `Root target: ${input.workflow.target}`,
    "The engagement summary follows. Use read_engagement_state and the engagement-surface tools to page through the complete contract; use IDs exactly when calling coordination tools.",
    JSON.stringify(
      {
        serviceCount: state.services.length,
        objectiveCount: state.objectives.length,
        services: state.services.slice(0, 10),
        objectives: state.objectives.slice(0, 10),
        operatorContext: state.operatorContext,
      },
      null,
      2,
    ),
    "Automatic endpoint-local coverage is already starting. Orient across the full surface, resolve needs-lead cells, preserve promising primitives, and run chain-and-explore toward threat-model-derived crown-jewel impact.",
  ].join("\n\n");

  const agent = new OffensiveSecurityAgent<
    z.infer<typeof EngagementLeadResult>
  >({
    system: ENGAGEMENT_LEAD_SYSTEM_PROMPT,
    prompt,
    model: workflow.model,
    session: workflow.session,
    target: workflow.target,
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
    messages: workflow.messages,
    authConfig: workflow.authConfig,
    abortSignal: workflow.abortSignal,
    eventBus,
    onStepFinish: workflow.onStepFinish,
    onCacheMetrics: workflow.onCacheMetrics,
    enableThinking: workflow.enableThinking,
    thinkingEffort: workflow.thinkingEffort,
    openAIReasoningEffort: workflow.openAIReasoningEffort,
    toolProtocol: workflow.toolProtocol,
    environmentVariables: workflow.environmentVariables,
    secretValues: workflow.secretValues,
    sandbox: workflow.sandbox,
    display: workflow.display,
  });

  const coverage = runDeterministicEngagementCoverage({
    workflow,
    store,
    pool: workerPool,
    findingsRegistry: input.findingsRegistry,
    eventBus,
    leadAgentId,
    surfaceTools,
    engagementTargetIds,
    onCheckpoint: input.onCheckpoint,
  });
  try {
    const [result] = await Promise.all([agent.consume(), coverage]);
    const checkpoint = store.checkpoint();
    await input.onCheckpoint?.(checkpoint);
    return { ...result, checkpoint };
  } catch (error) {
    internalAbort.abort();
    await agent.abortAndDrain();
    throw error;
  }
}
