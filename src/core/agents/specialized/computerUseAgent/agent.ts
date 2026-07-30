import { stepCountIs } from "ai";
import {
  COMPUTER_USE_TOOL_NAMES,
  OffensiveSecurityAgent,
} from "../../offSecAgent";
import {
  buildComputerUsePrompt,
  COMPUTER_USE_AGENT_SYSTEM_PROMPT,
} from "./prompts";
import {
  type ComputerUseAgentInput,
  type ComputerUseResult,
  ComputerUseResultSchema,
} from "./types";

/**
 * Specialized subagent for desktop GUI interaction.
 *
 * Drives an already-installed-and-launched application under test through the
 * computer-use tools (screenshot, mouse, keyboard, scroll) following an
 * observe → plan → act → verify loop. Spawned by a parent agent via
 * `delegate_to_computer_use_agent` for tasks that require visual desktop
 * interaction (thick clients, native dialogs, embedded UIs).
 *
 * Returns a structured {@link ComputerUseResult} via the `response` tool.
 *
 * @example
 * ```ts
 * const agent = new ComputerUseAgent({
 *   objective: "Log into the desktop app with the seeded admin account",
 *   model: "claude-sonnet-4-20250514",
 *   session,
 *   eventBus,
 *   subagentId: "computer-use-agent",
 * });
 * const result = await agent.consume(); // { status, summary }
 * ```
 */
export class ComputerUseAgent extends OffensiveSecurityAgent<ComputerUseResult> {
  constructor(opts: ComputerUseAgentInput) {
    const {
      model,
      objective,
      context,
      session,
      authConfig,
      messages,
      onStepFinish,
      onCacheMetrics,
      abortSignal,
      eventBus,
      subagentId,
      subagentName,
      enableThinking,
      thinkingEffort,
      openAIReasoningEffort,
    } = opts;

    super({
      system: COMPUTER_USE_AGENT_SYSTEM_PROMPT,
      prompt: buildComputerUsePrompt(objective, context),
      model,
      session,
      authConfig,
      messages,
      onStepFinish,
      onCacheMetrics,
      abortSignal,
      eventBus,
      subagentId,
      subagentName,
      enableThinking,
      thinkingEffort,
      openAIReasoningEffort,
      stopWhen: stepCountIs(200),
      activeTools: [
        ...COMPUTER_USE_TOOL_NAMES,
        "read_file",
        "execute_command",
        "response",
      ],
      responseSchema: ComputerUseResultSchema,
    });
  }
}
