import {
  stepCountIs,
  type StreamTextResult,
  type ToolSet,
  type StreamTextOnStepFinishCallback,
} from "ai";
import { streamResponse, type AIModel } from "../../ai";
import { SYSTEM } from "./prompts";
import { createSession, type Session } from "../sessions";
import { createBenchmarkTools } from "./tools";
import { detectOSAndEnhancePrompt } from "../utils";

export interface RunAgentProps {
  repoPath: string;
  branch?: string;
  model: AIModel;
  onStepFinish?: StreamTextOnStepFinishCallback<ToolSet>;
  abortSignal?: AbortSignal;
}

export interface RunAgentResult extends StreamTextResult<ToolSet, never> {
  session: Session;
}

export function runAgent(opts: RunAgentProps): {
  streamResult: RunAgentResult;
  session: Session;
} {
  const { repoPath, branch, model, onStepFinish, abortSignal } = opts;

  // Create a new session for this benchmark run
  const branchName = branch || "main";
  const session = createSession(
    repoPath,
    `Benchmark testing for ${repoPath} on branch ${branchName}`,
    `benchmark-${branchName}`
  );

  console.log(`[Benchmark] Created session: ${session.id}`);
  console.log(`[Benchmark] Session path: ${session.rootPath}`);

  // Create benchmark tools
  const tools = createBenchmarkTools(session, model, abortSignal);

  // Build the enhanced prompt
  const enhancedPrompt = `
REPO_PATH: ${repoPath}
BRANCH: ${branchName}

Session Information:
- Session ID: ${session.id}
- Session Path: ${session.rootPath}

You are the BENCHMARK ORCHESTRATOR agent for automated security testing evaluation.

Your mission:
1. Locate and load expected results from the repository (expected_results/*.json)
2. Start the development environment using docker compose
3. Run the thoroughPentestAgent on the running application
4. Extract findings from the completed pentest session
5. Compare actual findings with expected findings
6. Stop and clean up the development environment
7. Generate a comprehensive benchmark report with accuracy metrics

Begin by loading the expected results and starting the development environment.
`.trim();

  const streamResult = streamResponse({
    prompt: enhancedPrompt,
    system: SYSTEM,
    model,
    tools,
    stopWhen: stepCountIs(10000),
    toolChoice: "auto",
    onStepFinish,
    abortSignal,
  });

  // Attach the session directly to the stream result object
  (streamResult as any).session = session;

  return { streamResult: streamResult as RunAgentResult, session };
}
