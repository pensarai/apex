import { join } from "node:path";
import type { ModelMessage } from "ai";
import { z } from "zod";
import { OffensiveSecurityAgent } from "../agents/offSecAgent";
import { AgentEventBus } from "../eventBus";
import type { FindingsRegistry } from "../findings/registry";
import { getResumeMessages, normalizeMessages } from "../session";
import type { SwarmTarget } from "../session/persistence";
import { runDeterministicEngagementCoverage } from "./engagementCoverage";
import {
  applyEngagementModel,
  type EngagementModelConfig,
  engagementModelFromWorkflow,
} from "./engagementMissions";
import {
  createEngagementPlanningFileTools,
  ENGAGEMENT_PLAN_RELATIVE_PATH,
  ENGAGEMENT_PLANNING_PROMPT,
  prepareEngagementPlanningArtifacts,
  sealEngagementPlanArtifact,
} from "./engagementPlanning";
import {
  type DeploymentCapability,
  evaluateDeploymentPrerequisites,
  prepareDeploymentPreflightArtifact,
  sealDeploymentPreflightArtifact,
} from "./engagementPreflight";
import { EngagementRunMetrics } from "./engagementRunMetrics";
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
  EngagementContext,
  type EngagementSurfaceProvider,
} from "./engagementSurface";
import {
  createEngagementTools,
  ENGAGEMENT_TOOL_NAMES,
  findEngagementChainCoverageGaps,
  formatEngagementChainCoverageGaps,
} from "./engagementTools";
import { EngagementWorkerPool } from "./engagementWorkerPool";
import type { PentestWorkflowInput } from "./pentest";

export const EngagementLeadResult = z.object({
  summary: z.string(),
  coverageComplete: z.boolean(),
  chainExploreSummary: z.string(),
});

const EngagementPlanResult = z.object({
  summary: z.string(),
  planComplete: z.boolean(),
});

export type EngagementLeadOutcome = z.infer<typeof EngagementLeadResult> & {
  checkpoint: EngagementCheckpoint;
};

export const DEFAULT_ENGAGEMENT_WORKER_CONCURRENCY = 4;

export const ENGAGEMENT_LEAD_SYSTEM_PROMPT = `You are the durable lead penetration tester for one authorized engagement. You own the complete attack surface, threat-model objectives, coverage ledger, finding quality, and final chain-and-explore pass.

When grouped coverage is enabled, a restricted planning pass has already designed and sealed coherent missions from the complete attack surface. The bounded scheduler launches those missions. Check worker status and direct running workers as evidence changes. Preserve promising state: resume the same worker for stateful follow-ups.

In code mode, inspect ALL_TOOLS once and use exact capability names instead of guessing. Resume failed durable missions with follow_up_engagement_worker and their preserved worker IDs before doing replacement testing yourself.

Use wait_for_engagement_workers to yield while delegated work is running. Never monitor workers with execute_command, polling loops, or code-mode sleep timers; the host wakes you on durable activity. Code mode remains available for planning, analysis, and testing.

On legacy coverage modes, deterministic endpoint-local coverage runs beside you automatically. Work directly and delegate selectively: personally test high-value hypotheses, resolve cells marked needs-lead, interpret cross-service evidence, and maintain continuity. Coverage remains in the external ledger. Fast Strike workers prove one concrete impact objective—they never decide that the engagement is complete.

Use read_engagement_state as the source of truth: every objective attached to every target must become terminal; objectives are never copied onto unrelated targets. Discover net-new vulnerabilities and attack paths beyond the supplied objectives. Record reusable primitives with their source target IDs as capabilities and resolve every supported next step by consuming it in a chain or marking it blocked with evidence. Give chain and validation workers exact target and capability IDs.

You may call document_vulnerability directly. Findings still pass through the shared finding judge: document only reproducible exploitable vulnerabilities with material impact. Every finding must carry the sourceTargetId returned by the engagement-surface tools. Record material impact separately with record_impact_proof, referencing accepted findings, capabilities, artifacts, or trace observations.

Before finishing, perform chain-and-explore: combine confirmed primitives across services and attempt to reach crown-jewel impact. Record each meaningful terminal attack path with record_engagement_chain, including proven chains and material exhausted or blocked paths. Every canonical finding must have a dedicated attacker-path chain of its own, including single-finding paths, even when it also participates in a composite chain, and every impact proof must be represented in a chain. A finding or chain having appeared in prior authorized context is not a reason to omit it from the current engagement: validate it against the current target, document the current finding through the judge, and let finding consolidation handle true duplicates. A chain is separate from a vulnerability finding and must link accepted finding IDs when it uses them. Accepted finding IDs are durable evidence after resume when transient trace handles are unavailable. Do not record every payload attempt. Update the overall chain coverage status honestly only after those records are durable. The response tool is accepted only when the deterministic coverage gate is complete.`;

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
    completion.missionPlanningPending
      ? "The grouped mission plan is not sealed."
      : "",
    completion.activeMissionIds.length > 0
      ? `Missions still active: ${completion.activeMissionIds.join(", ")}`
      : "",
    completion.activeWorkerIds.length > 0
      ? `Workers still active: ${completion.activeWorkerIds.join(", ")}`
      : "",
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
  leadModel?: EngagementModelConfig;
  workerModel?: EngagementModelConfig;
  findingJudgeModel?: EngagementModelConfig;
  deploymentCapabilities?: DeploymentCapability[];
  loadCheckpoint?: () => Promise<EngagementCheckpoint | null>;
  onCheckpoint?: (checkpoint: EngagementCheckpoint) => void | Promise<void>;
}): Promise<EngagementLeadOutcome> {
  const eventBus = input.eventBus ?? new AgentEventBus();
  const internalAbort = new AbortController();
  const abortSignal = input.workflow.abortSignal
    ? AbortSignal.any([input.workflow.abortSignal, internalAbort.signal])
    : internalAbort.signal;
  const baseWorkflow = { ...input.workflow, abortSignal };
  const runMetrics = new EngagementRunMetrics(input.workflow.session.rootPath);
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
  const restoredCheckpoint = await input.loadCheckpoint?.();
  if (restoredCheckpoint) store.restore(restoredCheckpoint);
  const persistedModels = store.snapshot().models;
  const leadModel =
    persistedModels?.lead ??
    input.leadModel ??
    engagementModelFromWorkflow(baseWorkflow);
  const workerModel =
    persistedModels?.worker ??
    input.workerModel ??
    engagementModelFromWorkflow(baseWorkflow);
  const findingJudgeModel = persistedModels?.judge ?? input.findingJudgeModel;
  const workflow = applyEngagementModel(baseWorkflow, leadModel);
  store.reconcileInterruptedWorkers();
  if (!store.snapshot().actors) {
    const targetIds = store.snapshot().targets.map((target) => target.id);
    const serviceIds = store.snapshot().services.map((service) => service.id);
    const verifiedAt = new Date().toISOString();
    const credentialActors =
      workflow.session.credentialManager?.listReferences().map((reference) => ({
        id: `actor_${reference.id}`,
        label: reference.label ?? reference.username ?? reference.id,
        role: reference.role?.trim() || "authenticated-user",
        status: "ready" as const,
        credentialIds: [reference.id],
        targetIds,
        serviceIds,
        provenance: "operator" as const,
        verificationSummary: "Credential reference supplied by the operator.",
        verifiedAt,
      })) ?? [];
    store.configureActors([
      {
        id: "actor_anonymous",
        label: "Anonymous",
        role: "anonymous",
        status: "ready",
        credentialIds: [],
        targetIds,
        serviceIds,
        provenance: "operator",
        verificationSummary: "No authentication state required.",
        verifiedAt,
      },
      ...credentialActors,
    ]);
  }
  if (
    workflow.session.config?.engagementCoverageMode === "grouped" &&
    !store.snapshot().missions
  ) {
    store.saveMissions({ planningStatus: "pending", missions: [] });
  }
  store.saveModels({
    lead: leadModel,
    worker: workerModel,
    judge: findingJudgeModel,
  });
  const engagementTargetIds = store
    .snapshot()
    .targets.map((target) => target.id);
  const engagementContext = input.surfaceProvider
    ? new EngagementContext({
        provider: input.surfaceProvider,
        targetIds: engagementTargetIds,
        secretValues: workflow.secretValues,
        onRead: async ({ targetId, ...receipt }) => {
          store.recordContextRead(targetId, receipt);
          await input.onCheckpoint?.(store.checkpoint());
        },
      })
    : undefined;
  const surfaceTools = engagementContext
    ? createEngagementSurfaceTools(engagementContext)
    : undefined;
  const workerPool = new EngagementWorkerPool(
    input.concurrency ?? DEFAULT_ENGAGEMENT_WORKER_CONCURRENCY,
  );
  store.saveConcurrency(workerPool.maxConcurrency);
  await input.onCheckpoint?.(store.checkpoint());
  const workerJobs = new Set<Promise<unknown>>();
  const engagementRuntime = createEngagementTools({
    input: workflow,
    workerModel,
    findingJudgeModel,
    runMetrics,
    store,
    findingsRegistry: input.findingsRegistry,
    eventBus,
    leadAgentId,
    surfaceTools,
    engagementTargetIds,
    engagementContext,
    workerPool,
    onWorkerJob: (job) => {
      workerJobs.add(job);
      void job.then(
        () => workerJobs.delete(job),
        () => workerJobs.delete(job),
      );
    },
    onCheckpoint: input.onCheckpoint,
  });
  const engagementTools = engagementRuntime.tools;

  if (
    workflow.session.config?.engagementCoverageMode === "grouped" &&
    store.snapshot().missions?.planningStatus !== "complete"
  ) {
    const planningArtifacts = prepareEngagementPlanningArtifacts(
      workflow.session.rootPath,
      store,
    );
    const actorCapabilities: DeploymentCapability[] =
      store.snapshot().actors?.actors.map((actor) => ({
        id: `deployment_actor_${actor.id}`,
        kind: "actor",
        label: `${actor.role} actor`,
        status: actor.status === "ready" ? "available" : "unavailable",
        targetIds: actor.targetIds,
        evidence: [
          actor.status === "ready"
            ? actor.verificationSummary
            : (actor.unavailableReason ?? actor.verificationSummary),
        ],
        summary: actor.verificationSummary,
        observedAt: actor.verifiedAt,
      })) ?? [];
    const preflightArtifacts = prepareDeploymentPreflightArtifact(
      workflow.session.rootPath,
      {
        contractHash: planningArtifacts.contractHash,
        targetIds: engagementTargetIds,
        capabilities: [
          ...actorCapabilities,
          ...(input.deploymentCapabilities ?? []),
        ],
        status: "ready",
      },
    );
    const preflight = sealDeploymentPreflightArtifact(preflightArtifacts);
    const planningFileTools = createEngagementPlanningFileTools(
      workflow.session.rootPath,
      planningArtifacts,
      store,
      [preflightArtifacts.path],
    );
    const sealPlan = () => {
      const checkpointBeforeSeal = store.checkpoint();
      try {
        sealEngagementPlanArtifact(planningArtifacts, store);
        const requirements =
          store.snapshot().missions?.missions.flatMap((mission) =>
            (mission.requirements ?? []).map((requirement) => ({
              id: requirement.id,
              coverage: requirement.coverage,
              prerequisiteCapabilityIds:
                requirement.prerequisiteCapabilityIds ?? [],
            })),
          ) ?? [];
        store.applyDeploymentPreflight(
          preflight,
          evaluateDeploymentPrerequisites(requirements, preflight),
        );
      } catch (error) {
        store.restore(checkpointBeforeSeal);
        throw error;
      }
    };
    const planner = new OffensiveSecurityAgent<
      z.infer<typeof EngagementPlanResult>
    >({
      system: ENGAGEMENT_PLANNING_PROMPT,
      prompt: [
        `Plan the engagement for ${workflow.target}.`,
        `Read the complete immutable manifest at ${planningArtifacts.manifestRelativePath}.`,
        `Maintain the authoritative draft at ${planningArtifacts.planRelativePath}; replace it with create_file(overwrite=true) as the plan evolves.`,
        `Read the sealed deployment facts at ${preflightArtifacts.relativePath}. Treat unavailable capabilities as evidence-backed blockers and unknown capabilities as runnable unknowns.`,
        `The manifest contains ${store.snapshot().targets.length} authorized targets. Preserve contractHash ${planningArtifacts.contractHash}.`,
      ].join("\n"),
      model: workflow.model,
      session: workflow.session,
      target: workflow.target,
      activeTools: [
        "read_file",
        "create_file",
        ...(surfaceTools ? ENGAGEMENT_SURFACE_TOOL_NAMES : []),
        "response",
      ],
      nestedTools: [
        "read_file",
        "create_file",
        ...(surfaceTools ? ENGAGEMENT_SURFACE_TOOL_NAMES : []),
      ],
      extraTools: { ...surfaceTools, ...planningFileTools },
      engagementContext,
      responseSchema: EngagementPlanResult,
      responseGuard: (result) => {
        const parsed = EngagementPlanResult.safeParse(result);
        if (!parsed.success || !parsed.data.planComplete) {
          return "The response must acknowledge that the mission plan artifact is ready.";
        }
        try {
          sealPlan();
          return undefined;
        } catch (error) {
          return `Plan artifact validation failed: ${error instanceof Error ? error.message : String(error)}`;
        }
      },
      findingsRegistry: input.findingsRegistry,
      findingJudgeConfig: findingJudgeModel,
      authConfig: workflow.authConfig,
      abortSignal: workflow.abortSignal,
      eventBus,
      onStepFinish: (event) => {
        runMetrics.record("planner", workflow.model, event);
        workflow.onStepFinish?.(event);
      },
      onCodeCellComplete: (result) =>
        runMetrics.recordCode("planner", workflow.model, result),
      enableThinking: workflow.enableThinking,
      thinkingEffort: workflow.thinkingEffort,
      openAIReasoningEffort: workflow.openAIReasoningEffort,
      toolProtocol: workflow.toolProtocol,
      environmentVariables: workflow.environmentVariables,
      secretValues: workflow.secretValues,
      sandbox: workflow.sandbox,
      display: workflow.display,
    });
    try {
      await planner.consume();
      if (store.snapshot().missions?.planningStatus !== "complete") sealPlan();
      await input.onCheckpoint?.(store.checkpoint());
    } catch (error) {
      internalAbort.abort();
      engagementRuntime.dispose(error);
      runMetrics.finish("failed");
      await planner.abortAndDrain();
      throw error;
    }
  }
  const state = store.snapshot();
  const failedMissionResume = state.missions?.missions
    .filter(
      (mission) =>
        mission.status === "failed" && mission.workerId !== undefined,
    )
    .map(
      (mission) => `${mission.id} -> ${mission.workerId}: ${mission.purpose}`,
    );
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
    workflow.session.config?.engagementCoverageMode === "grouped"
      ? `The semantic mission plan is sealed at ${join(workflow.session.rootPath, ENGAGEMENT_PLAN_RELATIVE_PATH)} and bounded workers are starting. Read that artifact directly when you need cross-mission context. Monitor worker evidence, resolve needs-lead coverage, preserve flow state, and drive chain-and-explore.`
      : "Automatic endpoint-local coverage is already starting. Orient across the full surface, resolve needs-lead cells, preserve promising primitives, and run chain-and-explore toward threat-model-derived crown-jewel impact.",
    failedMissionResume && failedMissionResume.length > 0
      ? `Resume these failed durable missions first by calling follow_up_engagement_worker once per preserved worker ID:\n${failedMissionResume.join("\n")}`
      : "",
  ].join("\n\n");

  const coverage =
    workflow.session.config?.engagementCoverageMode === "grouped"
      ? engagementRuntime.startPlannedMissions()
      : runDeterministicEngagementCoverage({
          workflow,
          store,
          pool: workerPool,
          findingsRegistry: input.findingsRegistry,
          eventBus,
          leadAgentId,
          engagementContext,
          engagementTargetIds,
          mode: workflow.session.config?.engagementCoverageMode,
          onCheckpoint: input.onCheckpoint,
        });
  let activeAgent:
    | OffensiveSecurityAgent<z.infer<typeof EngagementLeadResult>>
    | undefined;
  let leadMessages = workflow.messages;
  let turn = 0;
  try {
    while (!abortSignal.aborted) {
      const handoffs = engagementRuntime.takeLeadHandoffs();
      let turnMessages: ModelMessage[] | undefined = leadMessages;
      if (turn > 0 || handoffs.length > 0) {
        const directive = [
          turn > 0
            ? "Continue leading this engagement from the durable ledger. The prior lead turn ended before the completion gate opened."
            : "Begin from the durable ledger and incorporate the worker handoffs below.",
          completionMessage(store.completion()),
          handoffs.length > 0
            ? `New worker handoffs:\n${handoffs
                .map(
                  (handoff) =>
                    `- ${handoff.senderAgentId} (${handoff.status ?? "update"}): ${handoff.payload}`,
                )
                .join("\n")}`
            : "No unread handoffs; inspect the current ledger and resolve its open work.",
        ]
          .filter(Boolean)
          .join("\n\n");
        turnMessages = getResumeMessages(
          normalizeMessages([
            ...(leadMessages ?? []),
            {
              role: "user",
              content: [{ type: "text", text: directive }],
            },
          ]),
        );
      }
      activeAgent = new OffensiveSecurityAgent<
        z.infer<typeof EngagementLeadResult>
      >({
        system: ENGAGEMENT_LEAD_SYSTEM_PROMPT,
        prompt,
        model: workflow.model,
        session: workflow.session,
        target: workflow.target,
        activeTools: [...LEAD_TOOL_NAMES],
        nestedTools: [
          ...ENGAGEMENT_TOOL_NAMES,
          ...(surfaceTools ? ENGAGEMENT_SURFACE_TOOL_NAMES : []),
        ],
        extraTools: engagementTools,
        engagementContext,
        engagementTargetIds:
          engagementTargetIds.length > 0 ? engagementTargetIds : undefined,
        responseSchema: EngagementLeadResult,
        responseGuard: (result) => {
          const completion = store.completion();
          if (!completion.complete) return completionMessage(completion);
          const chainGapMessage = formatEngagementChainCoverageGaps(
            findEngagementChainCoverageGaps(
              store.snapshot(),
              input.findingsRegistry,
            ),
          );
          if (chainGapMessage) return chainGapMessage;
          const parsed = EngagementLeadResult.safeParse(result);
          if (!parsed.success || !parsed.data.coverageComplete) {
            return "The response must acknowledge that deterministic engagement coverage is complete.";
          }
          return undefined;
        },
        findingsRegistry: input.findingsRegistry,
        findingJudgeConfig: findingJudgeModel,
        findingJudgeOnStepFinish: (event) =>
          runMetrics.record(
            "judge",
            findingJudgeModel?.model ?? workflow.model,
            event,
          ),
        findingJudgeOnCodeCellComplete: (result) =>
          runMetrics.recordCode(
            "judge",
            findingJudgeModel?.model ?? workflow.model,
            result,
          ),
        onCodeCellComplete: (result) =>
          runMetrics.recordCode("lead", workflow.model, result),
        messages: turnMessages,
        authConfig: workflow.authConfig,
        abortSignal: workflow.abortSignal,
        eventBus,
        onStepFinish: (event) => {
          if (event.response.messages) leadMessages = event.response.messages;
          runMetrics.record("lead", workflow.model, event);
          workflow.onStepFinish?.(event);
        },
        getPendingMessages: async () =>
          engagementRuntime.takeLeadHandoffs().map((handoff) => ({
            role: "user" as const,
            content: [
              {
                type: "text" as const,
                text: `Worker handoff from ${handoff.senderAgentId} (${handoff.status ?? "update"}): ${handoff.payload}`,
              },
            ],
          })),
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
      const candidate = await activeAgent.consume();
      const result = EngagementLeadResult.safeParse(candidate);
      if (store.completion().complete && result.success) {
        await coverage;
        await Promise.allSettled([...workerJobs]);
        const checkpoint = store.checkpoint();
        await input.onCheckpoint?.(checkpoint);
        engagementRuntime.dispose();
        runMetrics.finish("completed");
        return { ...result.data, checkpoint };
      }
      turn += 1;
      if (engagementRuntime.hasActiveWorkers()) {
        await engagementRuntime.waitForWorkerActivity();
      } else {
        await coverage;
      }
    }
    throw abortSignal.reason ?? new Error("Engagement lead aborted");
  } catch (error) {
    internalAbort.abort();
    engagementRuntime.dispose(error);
    runMetrics.finish("failed");
    await Promise.allSettled([
      activeAgent?.abortAndDrain(),
      coverage,
      ...workerJobs,
    ]);
    throw error;
  }
}
