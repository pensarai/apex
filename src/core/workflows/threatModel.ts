import type { AIModel } from "../ai";
import type { AIAuthConfig } from "../ai/utils";
import type { SessionInfo } from "../session";
import type { ConsumeCallbacks } from "../agents/offSecAgent";
import { ALL_TOOL_NAMES, SKILL_TOOL_NAMES } from "../agents/offSecAgent";
import { buildBaseSystemPrompt } from "../agents/offSecAgent/prompt";
import { runOffensiveSecurityAgent } from "../api/offesecAgent";
import { sessions } from "../session";
import { createSkillsRegistry } from "../skills";

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

  /** Stream callbacks */
  callbacks?: ConsumeCallbacks;
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
  const runtimeContext = [
    `IMPORTANT: You MUST write the output to exactly this path: ${input.outputPath}`,
    `Use create_file with path="${input.outputPath}" and overwrite=true.`,
    `Working directory (codebase root): ${input.codebasePath}`,
  ].join("\n");
  const prompt = `<skill name="threat-model">\n${runtimeContext}\n\n${content}\n</skill>`;

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

  // Run the agent
  await runOffensiveSecurityAgent({
    system,
    prompt,
    model,
    session,
    activeTools: [...ALL_TOOL_NAMES, ...SKILL_TOOL_NAMES] as string[],
    authConfig: input.authConfig,
    abortSignal: input.abortSignal,
    skillsRegistry: registry,
    callbacks: input.callbacks,
  });

  return { session, outputPath: input.outputPath };
}
