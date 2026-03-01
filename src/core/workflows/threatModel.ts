import { existsSync, mkdirSync, writeFileSync } from "fs";
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
  BLACKBOX_RECON_AGENT_SYSTEM_PROMPT,
  DATA_SYNTHESIS_AGENT_SYSTEM_PROMPT,
  buildApplicationContextObjective,
  buildBlackboxApplicationContextObjective,
  buildDeploymentContextObjective,
  buildBlackboxDeploymentContextObjective,
  buildSecurityControlsObjective,
  buildBlackboxSecurityControlsObjective,
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
import { BlackboxAttackSurfaceAgent } from "../agents/specialized/attackSurface/blackboxAgent";
import type { AgentEventBus } from "../agents/offSecAgent/eventBus";
import type { AIModel } from "../ai";
import type { AIAuthConfig } from "../ai/utils";
import type { SessionInfo } from "../session";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ThreatModelWorkflowInput {
  /** Local codebase path (absolute) — required for whitebox mode */
  cwd?: string;

  /** Live target URL — required for blackbox mode */
  target?: string;

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
 * Supports two modes:
 * - **whitebox** (cwd provided): phases read source code via CodeAgent
 * - **blackbox** (target provided): phases infer context from attack surface
 *   data + live HTTP probing. Attack surface JSON must already exist at
 *   `session.rootPath/attack-surface-results.json`.
 *
 * Phase 0: Application Context Discovery
 * Phase 1a: Attack Surface Reconnaissance (whitebox only — blackbox skips)
 * Phase 1b: Deployment Context
 * Phase 1c: Security Controls
 * Phase 2: Architecture Synthesis (reads JSON data files)
 * Phase 3: Attack Path Synthesis (reads JSON data files)
 * Phase 4: Assembly + Serialization (deterministic, no LLM)
 */
export async function runThreatModelWorkflow(
  input: ThreatModelWorkflowInput,
): Promise<ThreatModelResult> {
  const {
    cwd,
    target,
    model,
    session,
    applicationIdentity,
    authConfig,
    abortSignal,
    eventBus,
  } = input;

  const mode: "whitebox" | "blackbox" = cwd ? "whitebox" : "blackbox";

  if (mode === "blackbox" && !target) {
    throw new Error(
      "Blackbox threat model requires a target URL (no cwd or target provided)",
    );
  }

  const threatModelDir = join(session.rootPath, "threat-model");
  mkdirSync(threatModelDir, { recursive: true });

  const baseAgentInput = { model, session, authConfig, abortSignal };
  const attackSurfaceDataPath = join(
    session.rootPath,
    "attack-surface-results.json",
  );

  // =========================================================================
  // Phase 0: Application Context Discovery
  // =========================================================================

  emitPhase(eventBus, "application-context", "pending");

  let agent0: CodeAgent<ApplicationContext>;

  if (mode === "whitebox") {
    agent0 = new CodeAgent<ApplicationContext>({
      codebasePath: cwd!,
      objective: buildApplicationContextObjective(cwd!, applicationIdentity),
      system: WHITEBOX_CODE_AGENT_SYSTEM_PROMPT,
      responseSchema: ApplicationContextSchema,
      ...baseAgentInput,
      eventBus: eventBus?.child("application-context"),
    });
  } else {
    agent0 = new CodeAgent<ApplicationContext>({
      codebasePath: session.rootPath,
      objective: buildBlackboxApplicationContextObjective(
        target!,
        attackSurfaceDataPath,
      ),
      system: BLACKBOX_RECON_AGENT_SYSTEM_PROMPT,
      responseSchema: ApplicationContextSchema,
      ...baseAgentInput,
      eventBus: eventBus?.child("application-context"),
    });
  }

  const applicationContext = await agent0.consume();

  if (!applicationContext) {
    throw new Error("Phase 0 failed: no application context returned");
  }

  writeJSON(threatModelDir, "application-context.json", applicationContext);
  // Also write to session root for downstream synthesis prompts
  writeJSON(session.rootPath, "application-context.json", applicationContext);
  emitPhase(eventBus, "application-context", "completed");

  // =========================================================================
  // Phase 1a: Attack Surface Reconnaissance
  //   - Whitebox: run the whitebox attack surface workflow
  //   - Blackbox: run blackbox discovery (skip if data already exists from
  //     a prior pentest run)
  // =========================================================================

  let attackSurfaceRepoType: string | undefined;
  let attackSurfacePackageManager: string | undefined;

  if (mode === "whitebox") {
    emitPhase(eventBus, "attack-surface", "pending");

    const attackSurfaceInput: WhiteboxAttackSurfaceWorkflowInput = {
      codebasePath: cwd!,
      ...baseAgentInput,
      eventBus: eventBus?.child("attack-surface"),
    };

    const attackSurfaceResult =
      await runWhiteboxAttackSurfaceWorkflow(attackSurfaceInput);

    attackSurfaceRepoType = attackSurfaceResult.repoType;
    attackSurfacePackageManager = attackSurfaceResult.packageManager;

    // Persist for downstream phases that read JSON data files
    writeJSON(
      session.rootPath,
      "attack-surface-results.json",
      attackSurfaceResult,
    );
    emitPhase(eventBus, "attack-surface", "completed");
  } else if (!existsSync(attackSurfaceDataPath)) {
    // Blackbox: run discovery if not already present from a prior pentest run
    emitPhase(eventBus, "attack-surface", "pending");

    const bbAgent = new BlackboxAttackSurfaceAgent({
      target: target!,
      model,
      session,
      authConfig,
      abortSignal,
      eventBus: eventBus?.child("attack-surface"),
    });

    // The agent writes attack-surface-results.json to session.rootPath internally
    await bbAgent.consume();

    emitPhase(eventBus, "attack-surface", "completed");
  }

  // =========================================================================
  // Phase 1b: Deployment Context
  // =========================================================================

  emitPhase(eventBus, "deployment-context", "pending");

  let agent1b: CodeAgent<DeploymentContext>;

  if (mode === "whitebox") {
    agent1b = new CodeAgent<DeploymentContext>({
      codebasePath: cwd!,
      objective: buildDeploymentContextObjective(cwd!),
      responseSchema: DeploymentContextSchema,
      ...baseAgentInput,
      eventBus: eventBus?.child("deployment-context"),
    });
  } else {
    agent1b = new CodeAgent<DeploymentContext>({
      codebasePath: session.rootPath,
      objective: buildBlackboxDeploymentContextObjective(
        target!,
        attackSurfaceDataPath,
      ),
      system: BLACKBOX_RECON_AGENT_SYSTEM_PROMPT,
      responseSchema: DeploymentContextSchema,
      ...baseAgentInput,
      eventBus: eventBus?.child("deployment-context"),
    });
  }

  const deployment = (await agent1b.consume()) ?? emptyDeploymentContext();

  writeJSON(threatModelDir, "deployment-context.json", deployment);
  // Also write to session root for architecture synthesis prompt paths
  writeJSON(session.rootPath, "deployment-context.json", deployment);
  emitPhase(eventBus, "deployment-context", "completed");

  // =========================================================================
  // Phase 1c: Security Controls
  // =========================================================================

  emitPhase(eventBus, "security-controls", "pending");

  let agent1c: CodeAgent<SecurityControlsResult>;

  if (mode === "whitebox") {
    agent1c = new CodeAgent<SecurityControlsResult>({
      codebasePath: cwd!,
      objective: buildSecurityControlsObjective(
        cwd!,
        deployment,
        session.rootPath,
      ),
      responseSchema: SecurityControlsResultSchema,
      ...baseAgentInput,
      eventBus: eventBus?.child("security-controls"),
    });
  } else {
    agent1c = new CodeAgent<SecurityControlsResult>({
      codebasePath: session.rootPath,
      objective: buildBlackboxSecurityControlsObjective(
        target!,
        attackSurfaceDataPath,
        deployment,
        session.rootPath,
      ),
      system: BLACKBOX_RECON_AGENT_SYSTEM_PROMPT,
      responseSchema: SecurityControlsResultSchema,
      ...baseAgentInput,
      eventBus: eventBus?.child("security-controls"),
    });
  }

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
      mode,
      target: mode === "whitebox" ? cwd! : target!,
      generatedAt: new Date().toISOString(),
      modelUsed: model,
      schemaVersion: "2.0.0",
      ...(attackSurfaceRepoType ? { repoType: attackSurfaceRepoType } : {}),
      ...(attackSurfacePackageManager
        ? { packageManager: attackSurfacePackageManager }
        : {}),
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
      mode,
      ...(mode === "whitebox"
        ? { codebasePath: cwd! }
        : { target: target! }),
      ...(attackSurfaceRepoType ? { repoType: attackSurfaceRepoType } : {}),
      ...(attackSurfacePackageManager
        ? { packageManager: attackSurfacePackageManager }
        : {}),
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
