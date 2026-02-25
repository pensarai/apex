import { join } from "path";
import { CodeAgent } from "../agents/specialized/codeAgent/agent";
import { Storage } from "../storage";
import {
  ApplicationContextSchema,
  DeploymentContextSchema,
  SecurityControlsResultSchema,
  SystemArchitectureSchema,
  AttackPathsResultSchema,
  type ApplicationContext,
  type DeploymentContext,
  type SecurityControlsResult,
  type SystemArchitecture,
  type AttackPathsResult,
  type ThreatModel,
} from "../agents/specialized/threatModel/types";
import { serializeThreatModelToMarkdown } from "../agents/specialized/threatModel/serialize";
import type { WhiteboxAttackSurfaceResult } from "../agents/specialized/whiteboxAttackSurface/types";
import type { AIModel } from "../ai";
import type { AIAuthConfig } from "../ai/utils";
import type { SessionInfo } from "../session";
import type { ConsumeCallbacks } from "../agents/offSecAgent/types";
import {
  buildApplicationContextObjective,
  buildDeploymentContextObjective,
  buildSecurityControlsObjective,
  DATA_SYNTHESIS_AGENT_SYSTEM_PROMPT,
  buildArchitectureSynthesisObjective,
  buildAttackPathSynthesisObjective,
} from "../agents/specialized/threatModel/prompts";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const WHITEBOX_CODE_AGENT_SYSTEM_PROMPT = `You are an expert source-code analyst with direct filesystem access. You will be given a specific objective — focus exclusively on completing it.

Your focus is on **deployed applications and services** — APIs, web apps, microservices — that listen on a port and serve traffic. Ignore libraries, shared packages, SDKs, CLI tools, build scripts, and test suites unless they are part of a deployable service.

# Tool Usage Guide

## read_file
Read the contents of any file. You can read the whole file or a specific line range.
- When a file is large, read it in chunks using startLine / endLine to stay focused.
- Follow imports and references — when you see an interesting function call, read its source.

## list_files
List files and directories. Use this to orient yourself in the codebase.
- Start by listing the project root or relevant subdirectory to understand the structure.
- Use recursive=true sparingly on targeted subdirectories to avoid flooding context.

## grep
Search file contents by pattern. This is your most powerful navigation tool.
- Use it to find route definitions, middleware, controllers, endpoint registrations, etc.
- Use -i for case-insensitive searches.
- Use --include="*.ext" to narrow to relevant file types.
- Use -C 3 or -C 5 to get context around matches.
- Use -rn (default for directories) for recursive search with line numbers.
- Use -l to get just file paths when you need a broad overview of where something appears.

## execute_command
Run shell commands when needed.
- Use for build tools, git operations, package managers, linters, etc.

## document_asset
**Use this to document every significant asset you discover.** Each call persists a JSON record to the session's assets directory.

## response
When your objective includes structured output, call \`response\` with your final results once you are done. This ends your run — make sure all data is included.

# Working Approach
1. **Orient first** — list files and read key entry points to understand the structure.
2. **Ignore submodules** — check for a \`.gitmodules\` file or run \`git submodule status\`. Any directories that are git submodules are external dependencies and must be **completely excluded** from your analysis.
3. **Search, then read** — use grep to locate what you need, then read the relevant files.
4. **Document as you go** — call document_asset for every significant asset you discover.
5. **Follow the trail** — trace through imports, function calls, and references to build full understanding.
6. **Be thorough** — don't stop at the first match. Cover everything relevant to the objective.
`;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ThreatModelWorkflowInput {
  codebasePath: string;
  model: AIModel;
  session: SessionInfo;
  applicationIdentity?: string;
  authConfig?: AIAuthConfig;
  abortSignal?: AbortSignal;
  callbacks?: ConsumeCallbacks;
}

export interface ThreatModelWorkflowResult {
  threatModel: ThreatModel;
  markdownPath: string;
  jsonPath: string;
}

// ---------------------------------------------------------------------------
// Workflow
// ---------------------------------------------------------------------------

/**
 * Application-centric threat model generation workflow.
 *
 * Expects `attack-surface-results.json` to already exist in `session.rootPath`.
 *
 * Phase 0: Discover application context via CodeAgent.
 * Phase 1: Extract deployment/infrastructure context via CodeAgent.
 * Phase 2: Extract security controls via CodeAgent (reads attack surface from disk).
 * Phase 3a: Synthesize system architecture via CodeAgent (reads data files).
 * Phase 3b: Synthesize attack paths via CodeAgent (reads data files + application context).
 * Phase 4: Assemble, serialize to markdown + JSON, and write to session root.
 */
export async function runThreatModelWorkflow(
  input: ThreatModelWorkflowInput,
): Promise<ThreatModelWorkflowResult> {
  const {
    codebasePath,
    model,
    session,
    applicationIdentity,
    authConfig,
    abortSignal,
    callbacks,
  } = input;

  // =========================================================================
  // Phase 0: Discover application context
  // =========================================================================

  const appContextAgent = new CodeAgent<ApplicationContext>({
    codebasePath,
    objective: buildApplicationContextObjective(codebasePath, applicationIdentity),
    system: WHITEBOX_CODE_AGENT_SYSTEM_PROMPT,
    model,
    session,
    authConfig,
    abortSignal,
    callbacks,
    responseSchema: ApplicationContextSchema,
  });

  const applicationContext = await appContextAgent.consume({
    onTextDelta: (d) => callbacks?.onTextDelta?.(d),
    onToolCall: (d) => callbacks?.onToolCall?.(d),
    onToolResult: (d) => callbacks?.onToolResult?.(d),
    onError: (e) => callbacks?.onError?.(e),
    subagentCallbacks: callbacks?.subagentCallbacks,
  });

  // Write application context for downstream phases
  await Storage.write(
    ["executions", session.id, "application-context"],
    applicationContext,
  );

  // =========================================================================
  // Phase 1: Extract deployment context
  // =========================================================================

  const deploymentAgent = new CodeAgent<DeploymentContext>({
    codebasePath,
    objective: buildDeploymentContextObjective(codebasePath),
    system: WHITEBOX_CODE_AGENT_SYSTEM_PROMPT,
    model,
    session,
    authConfig,
    abortSignal,
    callbacks,
    responseSchema: DeploymentContextSchema,
  });

  const deploymentContext = await deploymentAgent.consume({
    onTextDelta: (d) => callbacks?.onTextDelta?.(d),
    onToolCall: (d) => callbacks?.onToolCall?.(d),
    onToolResult: (d) => callbacks?.onToolResult?.(d),
    onError: (e) => callbacks?.onError?.(e),
    subagentCallbacks: callbacks?.subagentCallbacks,
  });

  // Write deployment context for downstream phases
  await Storage.write(
    ["executions", session.id, "deployment-context"],
    deploymentContext,
  );

  // =========================================================================
  // Phase 2: Extract security controls (reads attack surface from disk)
  // =========================================================================

  const controlsAgent = new CodeAgent<SecurityControlsResult>({
    codebasePath,
    objective: buildSecurityControlsObjective(
      codebasePath,
      deploymentContext,
      session.rootPath,
    ),
    system: WHITEBOX_CODE_AGENT_SYSTEM_PROMPT,
    model,
    session,
    authConfig,
    abortSignal,
    callbacks,
    responseSchema: SecurityControlsResultSchema,
  });

  const securityControls = await controlsAgent.consume({
    onTextDelta: (d) => callbacks?.onTextDelta?.(d),
    onToolCall: (d) => callbacks?.onToolCall?.(d),
    onToolResult: (d) => callbacks?.onToolResult?.(d),
    onError: (e) => callbacks?.onError?.(e),
    subagentCallbacks: callbacks?.subagentCallbacks,
  });

  // Write security controls for downstream phases
  await Storage.write(
    ["executions", session.id, "security-controls"],
    securityControls,
  );

  // =========================================================================
  // Phase 3a: Synthesize system architecture (reads data files)
  // =========================================================================

  const architectureAgent = new CodeAgent<SystemArchitecture>({
    codebasePath: session.rootPath,
    objective: buildArchitectureSynthesisObjective(session.rootPath),
    system: DATA_SYNTHESIS_AGENT_SYSTEM_PROMPT,
    model,
    session,
    authConfig,
    abortSignal,
    callbacks,
    responseSchema: SystemArchitectureSchema,
  });

  const architecture = await architectureAgent.consume({
    onTextDelta: (d) => callbacks?.onTextDelta?.(d),
    onToolCall: (d) => callbacks?.onToolCall?.(d),
    onToolResult: (d) => callbacks?.onToolResult?.(d),
    onError: (e) => callbacks?.onError?.(e),
    subagentCallbacks: callbacks?.subagentCallbacks,
  });

  // Write system architecture for downstream phases
  await Storage.write(
    ["executions", session.id, "system-architecture"],
    architecture,
  );

  // =========================================================================
  // Phase 3b: Synthesize attack paths (reads all data files + app context)
  // =========================================================================

  const attackPathsAgent = new CodeAgent<AttackPathsResult>({
    codebasePath: session.rootPath,
    objective: buildAttackPathSynthesisObjective(session.rootPath),
    system: DATA_SYNTHESIS_AGENT_SYSTEM_PROMPT,
    model,
    session,
    authConfig,
    abortSignal,
    callbacks,
    responseSchema: AttackPathsResultSchema,
  });

  const attackPathsResult = await attackPathsAgent.consume({
    onTextDelta: (d) => callbacks?.onTextDelta?.(d),
    onToolCall: (d) => callbacks?.onToolCall?.(d),
    onToolResult: (d) => callbacks?.onToolResult?.(d),
    onError: (e) => callbacks?.onError?.(e),
    subagentCallbacks: callbacks?.subagentCallbacks,
  });

  // =========================================================================
  // Phase 4: Assemble full model, serialize, and write to disk
  // =========================================================================

  const attackPaths = attackPathsResult.attackPaths;

  // Compute summary deterministically
  const attackPathsBySeverity = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  };
  for (const ap of attackPaths) {
    attackPathsBySeverity[ap.severity]++;
  }

  // Read attack surface from disk for repoType/packageManager metadata
  const attackSurface = await Storage.read<WhiteboxAttackSurfaceResult>(
    ["executions", session.id, "attack-surface-results"],
  );
  const repoType = attackSurface.repoType;
  const packageManager = attackSurface.packageManager;

  const threatModel: ThreatModel = {
    metadata: {
      generatedAt: new Date().toISOString(),
      codebasePath: codebasePath,
      repoType,
      packageManager,
    },
    applicationContext,
    deployment: deploymentContext,
    components: architecture.components,
    trustBoundaries: architecture.trustBoundaries,
    dataFlows: architecture.dataFlows,
    securityControls,
    attackPaths,
    summary: {
      totalComponents: architecture.components.length,
      totalDataFlows: architecture.dataFlows.length,
      totalAttackPaths: attackPaths.length,
      attackPathsBySeverity,
    },
  };

  const markdown = serializeThreatModelToMarkdown(threatModel);

  await Storage.writeRaw(
    ["executions", session.id, "threat-model.md"],
    markdown,
  );
  await Storage.write(
    ["executions", session.id, "threat-model"],
    threatModel,
  );

  const markdownPath = join(session.rootPath, "threat-model.md");
  const jsonPath = join(session.rootPath, "threat-model.json");

  return {
    threatModel,
    markdownPath,
    jsonPath,
  };
}
