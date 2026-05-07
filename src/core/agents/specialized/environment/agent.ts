import { OffensiveSecurityAgent } from "../../offSecAgent";
import {
  buildEnvironmentSystemPrompt,
  buildEnvironmentPrompt,
} from "./prompts";
import {
  EnvironmentResultSchema,
  type EnvironmentResult,
  type EnvironmentAgentInput,
} from "./types";

/**
 * A dev-environment setup agent that starts and validates development
 * environments inside a sandbox.
 *
 * Shares the same filesystem and execution tools as {@link PatchingAgent}
 * (`read_file`, `list_files`, `grep`, `create_file`, `update_file`,
 * `execute_command`, `response`) but uses prompts tailored for DevOps tasks
 * — Docker Compose assessment, dependency installation, service startup,
 * and authentication testing.
 *
 * When an optional `sandbox` is provided, tools automatically route
 * operations through the sandbox instead of the local filesystem.
 *
 * Returns a structured {@link EnvironmentResult} with the application URL,
 * status, steps taken, and authentication details.
 *
 * @example
 * ```ts
 * const agent = new EnvironmentAgent({
 *   cwd: "/tmp/cloned-repo",
 *   model: "claude-sonnet-4-20250514",
 *   session,
 *   sandbox, // optional — tools route through sandbox when provided
 *   config: { startCommand: "npm run dev" },
 * });
 *
 * const result = await agent.consume({
 *   onTextDelta: (d) => process.stdout.write(d.text),
 * });
 * // result.url, result.status, result.stepsTaken, result.authenticationDetails
 * ```
 */
export class EnvironmentAgent extends OffensiveSecurityAgent<EnvironmentResult> {
  constructor(opts: EnvironmentAgentInput) {
    const {
      model,
      cwd,
      config,
      session,
      authConfig,
      onStepFinish,
      abortSignal,
      eventBus,
      subagentId,
      sandbox,
      enableThinking,
    } = opts;

    super({
      system: buildEnvironmentSystemPrompt(),
      prompt: buildEnvironmentPrompt(cwd, config),
      model,
      session,
      authConfig,
      onStepFinish,
      abortSignal,
      eventBus,
      subagentId,
      sandbox,
      enableThinking,

      activeTools: [
        "read_file",
        "list_files",
        "grep",
        "create_file",
        "update_file",
        "execute_command",
        "response",
        // Web search tools — look up tool installation, environment configuration docs
        "web_search",
        "get_page",
      ],

      responseSchema: EnvironmentResultSchema,
    });
  }
}
