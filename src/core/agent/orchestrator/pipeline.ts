import { join } from "path";
import { existsSync, writeFileSync, readFileSync } from "fs";
import type { AIModel } from "../../ai";
import type { Session } from "../../session";
import { runOrchestrator } from "./orchestrator";
import { runSubAgent, runSubAgentsParallel, runSubAgentsParallelWithCallbacks, type RunSubAgentResult } from "../subagent";
import type { SubAgentManifest, Finding, FileAccessConfig } from "../subagent/types";

export interface PipelineInput {
  attackSurfacePath: string;
  session: Session.SessionInfo;
  model: AIModel;
  workspace: string;
  whiteboxMode?: boolean;
  sourceCodePath?: string;
  focusEndpoint?: string;
  concurrencyLimit?: number;
  abortSignal?: AbortSignal;
  /** Timeout in ms for each subagent (default: 20 minutes) */
  subagentTimeout?: number;
  /** Tool override for sandboxing execute_command */
  toolOverride?: {
    execute_command?: (opts: any) => Promise<any>;
  };
  /** Paths to block from file access (for blackbox sandbox) */
  blockedPaths?: string[];
  onOrchestratorComplete?: (manifest: SubAgentManifest) => void;
  onSubAgentStart?: (subagentId: string, endpoint: string, vulnClass: string) => void;
  onSubAgentComplete?: (result: RunSubAgentResult) => void;
}

export interface PipelineResult {
  success: boolean;
  manifest: SubAgentManifest;
  subAgentResults: RunSubAgentResult[];
  allFindings: Finding[];
  summary: string;
  error?: string;
}

export async function runPentestPipeline(input: PipelineInput): Promise<PipelineResult> {
  const {
    attackSurfacePath,
    session,
    model,
    workspace,
    whiteboxMode,
    sourceCodePath,
    focusEndpoint,
    concurrencyLimit = 10,
    abortSignal,
    subagentTimeout,
    toolOverride,
    blockedPaths,
    onOrchestratorComplete,
    onSubAgentStart,
    onSubAgentComplete,
  } = input;

  // Build file access config for sandboxing read_file/write_file/append_file
  const fileAccessConfig: FileAccessConfig | undefined =
    (blockedPaths?.length || whiteboxMode) ? {
      allowedPaths: [
        session.rootPath,
        ...(whiteboxMode && sourceCodePath ? [sourceCodePath] : []),
      ],
      blockedPaths: blockedPaths || [],
    } : undefined;

  const orchestratorResult = await runOrchestrator(
    {
      attackSurfacePath,
      session: { id: session.id, rootPath: session.rootPath },
      whiteboxMode,
      sourceCodePath,
      focusEndpoint,
      abortSignal,
    },
    model
  );

  if (!orchestratorResult.success) {
    return {
      success: false,
      manifest: orchestratorResult.manifest,
      subAgentResults: [],
      allFindings: [],
      summary: `Orchestrator failed: ${orchestratorResult.error}`,
      error: orchestratorResult.error,
    };
  }

  onOrchestratorComplete?.(orchestratorResult.manifest);

  const { manifest } = orchestratorResult;

  if (manifest.subagents.length === 0) {
    return {
      success: true,
      manifest,
      subAgentResults: [],
      allFindings: [],
      summary: "No sub-agents to spawn - attack surface may be empty or no testable endpoints found",
    };
  }

  // Track completed results for real-time callbacks
  const completedResults: RunSubAgentResult[] = [];

  const subagentInputs = manifest.subagents.map((config) => ({
    config,
    session,
    workspace,
    model,
    abortSignal,
    timeout: subagentTimeout,
    toolOverride,
    fileAccessConfig,
    onInitComplete: () => {
      onSubAgentStart?.(config.id, config.endpoint, config.vulnerabilityClass);
    },
    onAttackComplete: (result: any) => {},
  }));

  // Wrap runSubAgentsParallel to get real-time completion callbacks
  const subAgentResults = await runSubAgentsParallelWithCallbacks(
    subagentInputs,
    concurrencyLimit,
    (result) => {
      completedResults.push(result);
      onSubAgentComplete?.(result);
    }
  );

  const allFindings: Finding[] = [];
  for (const result of subAgentResults) {
    allFindings.push(...result.findings);
  }

  const summaryPath = join(session.rootPath, "pipeline-summary.json");
  const summaryData = {
    sessionId: session.id,
    completedAt: new Date().toISOString(),
    totalSubAgents: subAgentResults.length,
    successfulSubAgents: subAgentResults.filter((r) => r.success).length,
    totalFindings: allFindings.length,
    findingsBySeverity: {
      critical: allFindings.filter((f) => f.severity === "critical").length,
      high: allFindings.filter((f) => f.severity === "high").length,
      medium: allFindings.filter((f) => f.severity === "medium").length,
      low: allFindings.filter((f) => f.severity === "low").length,
      info: allFindings.filter((f) => f.severity === "info").length,
    },
    findingsByClass: allFindings.reduce((acc, f) => {
      acc[f.vulnerabilityClass] = (acc[f.vulnerabilityClass] || 0) + 1;
      return acc;
    }, {} as Record<string, number>),
  };
  writeFileSync(summaryPath, JSON.stringify(summaryData, null, 2));

  const summary = `Pipeline complete. ${subAgentResults.length} sub-agents ran, ${allFindings.length} findings discovered.
Findings by severity: Critical(${summaryData.findingsBySeverity.critical}), High(${summaryData.findingsBySeverity.high}), Medium(${summaryData.findingsBySeverity.medium}), Low(${summaryData.findingsBySeverity.low})`;

  return {
    success: true,
    manifest,
    subAgentResults,
    allFindings,
    summary,
  };
}

export async function runPipelineFromManifest(
  manifestPath: string,
  session: Session.SessionInfo,
  model: AIModel,
  workspace: string,
  concurrencyLimit: number = 10,
  abortSignal?: AbortSignal
): Promise<PipelineResult> {
  const manifest = JSON.parse(readFileSync(manifestPath, "utf-8")) as SubAgentManifest;

  const subagentInputs = manifest.subagents.map((config) => ({
    config,
    session,
    workspace,
    model,
    abortSignal,
  }));

  const subAgentResults = await runSubAgentsParallel(subagentInputs, concurrencyLimit);

  const allFindings: Finding[] = [];
  for (const result of subAgentResults) {
    allFindings.push(...result.findings);
  }

  return {
    success: true,
    manifest,
    subAgentResults,
    allFindings,
    summary: `Resumed from manifest. ${subAgentResults.length} sub-agents ran, ${allFindings.length} findings.`,
  };
}
