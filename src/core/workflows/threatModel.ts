import { stepCountIs } from "ai";
import {
  ALL_TOOL_NAMES,
  ASK_USER_QUESTIONS_TOOL_NAME,
  buildBaseSystemPrompt,
  SKILL_TOOL_NAMES,
} from "../agents/offSecAgent";
import type { AIAuthConfig, AIModel } from "../ai";
import { runOffensiveSecurityAgent } from "../api";
import type { AgentEventBus } from "../eventBus";
import type { SessionInfo } from "../session";
import { sessions } from "../session";
import { createSkillsRegistry } from "../skills";
import { buildThreatModelPrompt } from "../skills/builtins";

// Headless — no TTY, so strip ask_user_questions from the active set.
const HEADLESS_TOOL_NAMES = ALL_TOOL_NAMES.filter(
  (name) => name !== ASK_USER_QUESTIONS_TOOL_NAME,
);

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ThreatModelWorkflowInput {
  /** Path to the codebase to analyze */
  codebasePath: string;

  /** Where to write the threat model markdown file */
  outputPath: string;

  /** AI model (defaults to claude-sonnet-4-5) */
  model?: AIModel;

  /** Optional existing session to reuse — auto-created if omitted */
  session?: SessionInfo;

  /** Per-provider API key overrides */
  authConfig?: AIAuthConfig;

  /** AbortSignal to cancel the workflow */
  abortSignal?: AbortSignal;

  /** Optional event bus for streaming agent output */
  eventBus?: AgentEventBus;
}

export interface ThreatModelWorkflowResult {
  /** The session used (whether provided or auto-created) */
  session: SessionInfo;

  /** Absolute path where the threat model was written */
  outputPath: string;
}

// ---------------------------------------------------------------------------
// Workflow
// ---------------------------------------------------------------------------

export async function runThreatModelWorkflow(
  input: ThreatModelWorkflowInput,
): Promise<ThreatModelWorkflowResult> {
  const model: AIModel = input.model ?? "claude-sonnet-4-5";

  // Load skill content
  const registry = createSkillsRegistry();
  await registry.load({ projectRoot: input.codebasePath });
  const { content } = await registry.readSkillContent("threat-model");

  // Build the prompt with runtime context
  const prompt = buildThreatModelPrompt({
    outputPath: input.outputPath,
    codebasePath: input.codebasePath,
    skillContent: content,
  });

  // Create or reuse session
  const session =
    input.session ??
    (await sessions.create({
      name: "Threat Model",
      targets: [input.codebasePath],
      config: { mode: "operator", agentCwd: input.codebasePath },
    }));

  // Build system prompt
  const system = `${buildBaseSystemPrompt({ sandboxMode: false })}

# Threat Model Mode

You are generating an application-centric threat model from source code analysis.
Working directory: ${input.codebasePath}`;

  await runOffensiveSecurityAgent({
    system,
    prompt,
    model,
    session,
    activeTools: [...HEADLESS_TOOL_NAMES, ...SKILL_TOOL_NAMES] as string[],
    authConfig: input.authConfig,
    abortSignal: input.abortSignal,
    skillsRegistry: registry,
    eventBus: input.eventBus,
    stopWhen: stepCountIs(10000),
  });

  return { session, outputPath: input.outputPath };
}
