import { mkdirSync, writeFileSync } from "fs";
import { join } from "path";
import { CodeAgent } from "../agents/specialized/codeAgent/agent";
import {
  ApplicationContextSchema,
  AttackPathsResultSchema,
  DeploymentContextSchema,
  SecurityControlsResultSchema,
  SystemArchitectureSchema,
  type ApplicationContext,
  type AttackPathsResult,
  type DeploymentContext,
  type SecurityControlsResult,
  type SystemArchitecture,
  type ThreatModel,
  type ThreatModelResult,
} from "../agents/specialized/threatModel/types";
import {
  WHITEBOX_CODE_AGENT_SYSTEM_PROMPT,
  DATA_SYNTHESIS_AGENT_SYSTEM_PROMPT,
  buildApplicationContextObjective,
  buildDeploymentContextObjective,
  buildSecurityControlsObjective,
  buildArchitectureSynthesisObjective,
  buildAttackPathSynthesisObjective,
} from "../agents/specialized/threatModel/prompts";
import {
  serializeThreatModelToMarkdown,
  serializeThreatModelToJson,
} from "../agents/specialized/threatModel/serialize";
import {
  runWhiteboxAttackSurfaceWorkflow,
  type WhiteboxAttackSurfaceWorkflowInput,
} from "./whiteboxAttackSurface";
import type { AgentEventBus } from "../agents/offSecAgent/eventBus";
import type { AIModel } from "../ai";
import type { AIAuthConfig } from "../ai/utils";
import type { SessionInfo } from "../session";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ThreatModelWorkflowInput {
  /** Local codebase path (absolute) */
  cwd: string;

  model: AIModel;
  session: SessionInfo;

  /** Optional user hint about what the app is */
  applicationIdentity?: string;

  authConfig?: AIAuthConfig;
  abortSignal?: AbortSignal;
  eventBus?: AgentEventBus;
}

// ---------------------------------------------------------------------------
// Workflow
// ---------------------------------------------------------------------------

/**
 * Deterministic threat model workflow.
 *
 * Phase 0: Application Context Discovery (CodeAgent reads source code)
 * Phase 1a: Attack Surface Reconnaissance (reuses whitebox workflow)
 * Phase 1b: Deployment Context (CodeAgent reads source code)
 * Phase 1c: Security Controls (CodeAgent reads source code + attack surface data)
 * Phase 2: Architecture Synthesis (CodeAgent reads JSON data files)
 * Phase 3: Attack Path Synthesis (CodeAgent reads JSON data files)
 * Phase 4: Assembly + Serialization (deterministic, no LLM)
 */
export async function runThreatModelWorkflow(
  input: ThreatModelWorkflowInput,
): Promise<ThreatModelResult> {
  const {
    cwd,
    model,
    session,
    applicationIdentity,
    authConfig,
    abortSignal,
    eventBus,
  } = input;

  const threatModelDir = join(session.rootPath, "threat-model");
  mkdirSync(threatModelDir, { recursive: true });

  const baseAgentInput = { model, session, authConfig, abortSignal };

  // =========================================================================
  // Phase 0: Application Context Discovery
  // =========================================================================

  emitPhase(eventBus, "application-context", "pending");

  const agent0 = new CodeAgent<ApplicationContext>({
    codebasePath: cwd,
    objective: buildApplicationContextObjective(cwd, applicationIdentity),
    system: WHITEBOX_CODE_AGENT_SYSTEM_PROMPT,
    responseSchema: ApplicationContextSchema,
    ...baseAgentInput,
    eventBus: eventBus?.child("application-context"),
  });
  const applicationContext = await agent0.consume();

  if (!applicationContext) {
    throw new Error("Phase 0 failed: no application context returned");
  }

  writeJSON(threatModelDir, "application-context.json", applicationContext);
  emitPhase(eventBus, "application-context", "completed");

  // =========================================================================
  // Phase 1a: Attack Surface Reconnaissance (reuses existing workflow)
  // =========================================================================

  emitPhase(eventBus, "attack-surface", "pending");

  const attackSurfaceInput: WhiteboxAttackSurfaceWorkflowInput = {
    codebasePath: cwd,
    ...baseAgentInput,
    eventBus: eventBus?.child("attack-surface"),
  };

  const attackSurfaceResult =
    await runWhiteboxAttackSurfaceWorkflow(attackSurfaceInput);

  // Persist for downstream phases that read JSON data files
  writeJSON(
    session.rootPath,
    "attack-surface-results.json",
    attackSurfaceResult,
  );
  emitPhase(eventBus, "attack-surface", "completed");

  // =========================================================================
  // Phase 1b: Deployment Context
  // =========================================================================

  emitPhase(eventBus, "deployment-context", "pending");

  const agent1b = new CodeAgent<DeploymentContext>({
    codebasePath: cwd,
    objective: buildDeploymentContextObjective(cwd),
    responseSchema: DeploymentContextSchema,
    ...baseAgentInput,
    eventBus: eventBus?.child("deployment-context"),
  });
  const deployment = (await agent1b.consume()) ?? emptyDeploymentContext();

  writeJSON(threatModelDir, "deployment-context.json", deployment);
  // Also write to session root for architecture synthesis prompt paths
  writeJSON(session.rootPath, "deployment-context.json", deployment);
  emitPhase(eventBus, "deployment-context", "completed");

  // =========================================================================
  // Phase 1c: Security Controls
  // =========================================================================

  emitPhase(eventBus, "security-controls", "pending");

  const agent1c = new CodeAgent<SecurityControlsResult>({
    codebasePath: cwd,
    objective: buildSecurityControlsObjective(
      cwd,
      deployment,
      session.rootPath,
    ),
    responseSchema: SecurityControlsResultSchema,
    ...baseAgentInput,
    eventBus: eventBus?.child("security-controls"),
  });
  const securityControls = (await agent1c.consume()) ?? { controls: [] };

  writeJSON(threatModelDir, "security-controls.json", securityControls);
  // Also write to session root for attack path synthesis prompt paths
  writeJSON(session.rootPath, "security-controls.json", securityControls);
  emitPhase(eventBus, "security-controls", "completed");

  // =========================================================================
  // Phase 2: Architecture Synthesis
  // =========================================================================

  emitPhase(eventBus, "architecture-synthesis", "pending");

  const agent2 = new CodeAgent<SystemArchitecture>({
    codebasePath: session.rootPath,
    objective: buildArchitectureSynthesisObjective(session.rootPath),
    system: DATA_SYNTHESIS_AGENT_SYSTEM_PROMPT,
    responseSchema: SystemArchitectureSchema,
    ...baseAgentInput,
    eventBus: eventBus?.child("architecture-synthesis"),
  });
  const architecture = (await agent2.consume()) ?? {
    components: [],
    trustBoundaries: [],
    dataFlows: [],
  };

  writeJSON(threatModelDir, "system-architecture.json", architecture);
  // Also write to session root for attack path synthesis prompt paths
  writeJSON(session.rootPath, "system-architecture.json", architecture);
  emitPhase(eventBus, "architecture-synthesis", "completed");

  // =========================================================================
  // Phase 3: Attack Path Synthesis
  // =========================================================================

  emitPhase(eventBus, "attack-path-synthesis", "pending");

  const agent3 = new CodeAgent<AttackPathsResult>({
    codebasePath: session.rootPath,
    objective: buildAttackPathSynthesisObjective(session.rootPath),
    system: DATA_SYNTHESIS_AGENT_SYSTEM_PROMPT,
    responseSchema: AttackPathsResultSchema,
    ...baseAgentInput,
    eventBus: eventBus?.child("attack-path-synthesis"),
  });
  const attackPathsResult = (await agent3.consume()) ?? { attackPaths: [] };

  writeJSON(threatModelDir, "attack-paths.json", attackPathsResult);
  emitPhase(eventBus, "attack-path-synthesis", "completed");

  // =========================================================================
  // Phase 4: Assembly (deterministic, no LLM)
  // =========================================================================

  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const ap of attackPathsResult.attackPaths) {
    bySeverity[ap.severity]++;
  }

  const severityOrder = ["critical", "high", "medium", "low"] as const;
  const sorted = [...attackPathsResult.attackPaths].sort(
    (a, b) =>
      severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity),
  );

  const threatModelResult: Omit<ThreatModelResult, "files"> = {
    metadata: {
      mode: "whitebox",
      target: cwd,
      generatedAt: new Date().toISOString(),
      modelUsed: model,
      schemaVersion: "2.0.0",
      repoType: attackSurfaceResult.repoType,
      packageManager: attackSurfaceResult.packageManager,
    },
    applicationContext,
    deployment,
    architecture,
    securityControls,
    attackPaths: attackPathsResult.attackPaths,
    summary: {
      totalAttackPaths: attackPathsResult.attackPaths.length,
      bySeverity,
      topRisks: sorted.slice(0, 10).map((ap) => ap.id),
    },
  };

  // Build serialization model
  const threatModel: ThreatModel = {
    metadata: {
      generatedAt: threatModelResult.metadata.generatedAt,
      codebasePath: cwd,
      repoType: attackSurfaceResult.repoType,
      packageManager: attackSurfaceResult.packageManager,
    },
    applicationContext,
    deployment,
    components: architecture.components,
    trustBoundaries: architecture.trustBoundaries,
    dataFlows: architecture.dataFlows,
    securityControls,
    attackPaths: attackPathsResult.attackPaths,
    summary: {
      totalComponents: architecture.components.length,
      totalDataFlows: architecture.dataFlows.length,
      totalAttackPaths: attackPathsResult.attackPaths.length,
      attackPathsBySeverity: bySeverity,
    },
  };

  const jsonPath = join(threatModelDir, "threat-model.json");
  const mdPath = join(threatModelDir, "threat-model.md");
  writeFileSync(jsonPath, serializeThreatModelToJson(threatModel));
  writeFileSync(mdPath, serializeThreatModelToMarkdown(threatModel));

  return { ...threatModelResult, files: { markdownPath: mdPath, jsonPath } };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function emitPhase(
  eventBus: AgentEventBus | undefined,
  phase: string,
  status: "pending" | "completed" | "failed",
): void {
  if (!eventBus) return;
  if (status === "pending") {
    eventBus.emit({
      type: "subagent-spawn",
      subagentId: phase,
      input: { phase },
      status: "pending",
    });
  } else {
    eventBus.emit({
      type: "subagent-complete",
      subagentId: phase,
      input: { phase },
      status,
    });
  }
}

function writeJSON(dir: string, filename: string, data: unknown): void {
  writeFileSync(join(dir, filename), JSON.stringify(data, null, 2));
}

function emptyDeploymentContext(): DeploymentContext {
  return {
    iac: [],
    cicd: [],
    databases: [],
    messageQueues: [],
    reverseProxy: "",
    environmentFiles: [],
  };
}
