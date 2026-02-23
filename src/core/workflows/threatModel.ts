import { writeFileSync } from "fs";
import { join } from "path";
import { CodeAgent } from "../agents/specialized/codeAgent/agent";
import {
  DeploymentContextSchema,
  SecurityControlsResultSchema,
  STRIDEThreatModelSchema,
  type DeploymentContext,
  type SecurityControlsResult,
  type STRIDEThreatModel,
} from "../agents/specialized/threatModel/types";
import {
  serializeThreatModelToMarkdown,
  serializeThreatModelToJson,
} from "../agents/specialized/threatModel/serialize";
import type { WhiteboxAttackSurfaceResult } from "../agents/specialized/whiteboxAttackSurface/types";
import type { AIModel } from "../ai";
import { generateObjectResponse } from "../ai/ai";
import type { AIAuthConfig } from "../ai/utils";
import type { SessionInfo } from "../session";
import type { ConsumeCallbacks } from "../agents/offSecAgent/types";
import {
  buildDeploymentContextObjective,
  buildSecurityControlsObjective,
  THREAT_MODEL_SYNTHESIS_SYSTEM_PROMPT,
  buildThreatModelSynthesisPrompt,
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
  attackSurface: WhiteboxAttackSurfaceResult;
  model: AIModel;
  session: SessionInfo;
  authConfig?: AIAuthConfig;
  abortSignal?: AbortSignal;
  callbacks?: ConsumeCallbacks;
}

export interface ThreatModelWorkflowResult {
  threatModel: STRIDEThreatModel;
  markdownPath: string;
  jsonPath: string;
}

// ---------------------------------------------------------------------------
// Workflow
// ---------------------------------------------------------------------------

/**
 * Deterministic STRIDE threat model generation workflow.
 *
 * Phase 1: Extract deployment/infrastructure context via CodeAgent.
 * Phase 2: Extract security controls via CodeAgent (receives Phase 1 output).
 * Phase 3: Synthesize full STRIDE threat model via generateObjectResponse.
 * Phase 4: Serialize to markdown + JSON and write to session root.
 */
export async function runThreatModelWorkflow(
  input: ThreatModelWorkflowInput,
): Promise<ThreatModelWorkflowResult> {
  const {
    codebasePath,
    attackSurface,
    model,
    session,
    authConfig,
    abortSignal,
    callbacks,
  } = input;

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

  // =========================================================================
  // Phase 2: Extract security controls (receives deployment context)
  // =========================================================================

  const controlsAgent = new CodeAgent<SecurityControlsResult>({
    codebasePath,
    objective: buildSecurityControlsObjective(
      codebasePath,
      deploymentContext,
      attackSurface,
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

  // =========================================================================
  // Phase 3: Synthesize STRIDE threat model
  // =========================================================================

  const threatModel = (await generateObjectResponse({
    model,
    schema: STRIDEThreatModelSchema,
    system: THREAT_MODEL_SYNTHESIS_SYSTEM_PROMPT,
    prompt: buildThreatModelSynthesisPrompt(
      deploymentContext,
      securityControls,
      attackSurface,
    ),
    authConfig,
  })) as STRIDEThreatModel;

  // =========================================================================
  // Phase 4: Serialize and write to disk
  // =========================================================================

  const markdownPath = join(session.rootPath, "stride-threat-model.md");
  const jsonPath = join(session.rootPath, "stride-threat-model.json");

  const markdown = serializeThreatModelToMarkdown(threatModel);
  const json = serializeThreatModelToJson(threatModel);

  writeFileSync(markdownPath, markdown, "utf-8");
  writeFileSync(jsonPath, json, "utf-8");

  return {
    threatModel,
    markdownPath,
    jsonPath,
  };
}
