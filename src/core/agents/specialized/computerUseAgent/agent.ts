import { stepCountIs } from "ai";
import { OffensiveSecurityAgent } from "../../offSecAgent/offensiveSecurityAgent";
import type { ComputerUseAgentInput } from "./types";
import { COMPUTER_USE_AGENT_SYSTEM_PROMPT } from "./prompts";
import { COMPUTER_USE_TOOL_NAMES } from "../../offSecAgent/tools/computerUse";

/**
 * Specialized subagent for desktop GUI interaction.
 *
 * Uses computer use tools (screenshot, mouse, keyboard, scroll) to
 * interact with graphical applications. Follows an observe-plan-act loop:
 * screenshot → identify elements → interact → verify.
 *
 * Designed to be spawned by a parent agent via `delegate_to_computer_use_agent`
 * for tasks that require visual desktop interaction (thick clients, VNC, RDP,
 * native OS dialogs, etc.).
 *
 * @example
 * ```ts
 * const agent = new ComputerUseAgent({
 *   objective: "Open Firefox, navigate to example.com, and take a screenshot",
 *   model: "claude-sonnet-4-20250514",
 *   session,
 *   eventBus,
 *   subagentId: "computer-use-agent",
 * });
 * await agent.consume();
 * ```
 */
export class ComputerUseAgent extends OffensiveSecurityAgent<void> {
  constructor(opts: ComputerUseAgentInput) {
    const {
      model,
      objective,
      context,
      session,
      authConfig,
      onStepFinish,
      onCacheMetrics,
      abortSignal,
      eventBus,
      subagentId,
    } = opts;

    const activeTools: string[] = [
      ...COMPUTER_USE_TOOL_NAMES,
      "execute_command",
    ];

    super({
      system: COMPUTER_USE_AGENT_SYSTEM_PROMPT,
      prompt: buildPrompt(objective, context),
      model,
      session,
      authConfig,
      onStepFinish,
      onCacheMetrics,
      abortSignal,
      eventBus,
      subagentId,
      stopWhen: stepCountIs(200),
      activeTools,
    });
  }
}

function buildPrompt(objective: string, context?: string): string {
  let prompt = `# Objective

${objective}`;

  if (context) {
    prompt += `

## Context
${context}`;
  }

  prompt += `

## Instructions
1. Start by taking a screenshot to see the current desktop state.
2. Work through the objective step by step, verifying each action with screenshots.
3. Report what you accomplished when done.

Begin now.`;

  return prompt;
}
