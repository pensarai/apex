import { tool } from "ai";
import { z } from "zod";
import { AgentEventBus } from "../../../eventBus";
import { createLogger } from "../../../logger/structured";
import { isMemoryEnabled } from "../../../memory";
import { scopedLogger } from "../../../util/lazyLogger";
import type { ToolContext } from "./types";

const log = scopedLogger(() => createLogger("generate-next-objectives"));

// ---------------------------------------------------------------------------
// Response schema — the planning sub-agent calls "response" when done
// ---------------------------------------------------------------------------

const NextObjectivesResultSchema = z.object({
  newObjectives: z
    .array(z.string())
    .describe(
      "Focused, self-contained pentest objectives for the NEXT run of this endpoint. " +
        "Each entry is one objective string the pentest agent can act on directly. " +
        "MUST NOT duplicate or restate anything already tested this run or already marked " +
        "completed. Return an empty array if no productive new testing remains.",
    ),
  reasoning: z
    .string()
    .optional()
    .describe(
      "Brief explanation of why these are the right next objectives and how they avoid " +
        "redundancy with prior coverage.",
    ),
});

type NextObjectivesResult = z.infer<typeof NextObjectivesResultSchema>;

// ---------------------------------------------------------------------------
// System prompt
// ---------------------------------------------------------------------------

const OBJECTIVE_GENERATION_SYSTEM_PROMPT = `You are a penetration-test planning agent. Your sole job: given a single endpoint and a record of what has ALREADY been tested on it, propose the most valuable NEW testing objectives for the NEXT run.

You do NOT perform any testing, exploitation, or documentation yourself. You reason about coverage gaps and emit a focused, deduplicated objective list.

Principles:
- Non-redundant: never restate an objective that was already tested this run or already marked completed. Your value is finding the gaps that remain.
- Grounded: base new objectives on the observed behavior, confirmed/ruled-out findings, technology fingerprints, and unexplored anomalies described in the brief — not generic OWASP filler.
- Specific: each objective names a concrete attack class against a concrete part of the endpoint (a parameter, header, auth flow, or sibling behavior), phrased as something a pentester can execute directly. Avoid vague one-liners like "test for XSS" with no target.
- Bounded: emit a small, high-signal set (typically 2-6). Prefer breadth across distinct, untested attack classes over payload variants of something already covered.
- Honest: if the endpoint is genuinely exhausted — everything material has been tested and either confirmed or conclusively ruled out — return an empty array rather than inventing low-value work.

You MAY use web_search / get_page to look up attack techniques or CVEs relevant to the observed technology before deciding. When finished, call the response tool with newObjectives and a brief reasoning.`;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export interface GenerateNextObjectivesInput {
  /** Endpoint URL. */
  target: string;
  /** What was tested this run and the outcomes. */
  testingSummary: string;
  /** Objectives already completed — not to be re-proposed. */
  alreadyCoveredObjectives?: string[];
}

/** Spawn a planning sub-agent that proposes next-run objectives. Returns [] on failure. */
export async function runObjectiveGenerationAgent(
  ctx: ToolContext,
  input: GenerateNextObjectivesInput,
): Promise<string[]> {
  if (!ctx.model) return [];
  const model = ctx.model;

  // Lazy import: breaks the tools-barrel circular dependency.
  const { OffensiveSecurityAgent } = await import("../offensiveSecurityAgent");

  const subagentId = ctx.subagentId
    ? `${ctx.subagentId}-objectives`
    : "objective-generation";

  ctx.eventBus?.emit("subagent-spawn", {
    subagentId,
    name: "Generate next objectives",
    input: { target: input.target },
    parentSubagentId: ctx.subagentId,
  });

  const localBus = new AgentEventBus();
  AgentEventBus.attachChild(localBus, ctx.eventBus, subagentId);

  const tools = isMemoryEnabled()
    ? ["web_search", "get_page", "list_memories", "get_memory"]
    : ["web_search", "get_page"];

  try {
    const agent = new OffensiveSecurityAgent<NextObjectivesResult>({
      system: OBJECTIVE_GENERATION_SYSTEM_PROMPT,
      prompt: buildObjectiveGenerationPrompt(input),
      model,
      session: ctx.session,
      target: input.target,
      authConfig: ctx.authConfig,
      abortSignal: ctx.abortSignal,
      eventBus: localBus,
      subagentId,
      sandbox: ctx.sandbox,
      activeTools: tools,
      responseSchema: NextObjectivesResultSchema,
    });

    const result = await agent.consume();

    ctx.eventBus?.emit("subagent-complete", {
      subagentId,
      status: "completed",
      parentSubagentId: ctx.subagentId,
    });

    const objectives = (result?.newObjectives ?? [])
      .map((o) => o.trim())
      .filter((o) => o.length > 0);

    log.info(`Generated ${objectives.length} next-run objective(s)`, {
      target: input.target,
    });

    return objectives;
  } catch (error) {
    ctx.eventBus?.emit("subagent-complete", {
      subagentId,
      status: "failed",
      parentSubagentId: ctx.subagentId,
    });
    log.warn(
      `Objective generation failed for ${input.target}: ${error instanceof Error ? error.message : String(error)}`,
    );
    return [];
  }
}

// ---------------------------------------------------------------------------
// Tool factory — orchestrator-facing
// ---------------------------------------------------------------------------

/** `generate_next_objectives` tool — orchestrator calls it once at end of run. */
export function generateNextObjectives(ctx: ToolContext) {
  return tool({
    description: `Generate the NEXT run's testing objectives for this endpoint based on what was already tested.

Call this EXACTLY ONCE, at the very end of your run — after every worker (including the final chain & explore worker) has completed and BEFORE you call the response tool. It spawns a focused planning sub-agent that reviews coverage and returns a small, deduplicated set of new objectives for the next run.

Pass a thorough \`testingSummary\`: which objectives were tested this run and their outcomes, what each worker confirmed or conclusively ruled out, and any anomalies from recon that nobody investigated. Pass \`alreadyCoveredObjectives\` with the objectives already marked completed in your assignment context so the planner does not re-propose them.

Returns \`newObjectives\` (a string array). Copy these verbatim into your final response's \`newObjectives\` field.`,
    inputSchema: z.object({
      target: z
        .string()
        .describe(
          "Full target URL of the endpoint, same as your assignment target.",
        ),
      testingSummary: z
        .string()
        .describe(
          "Synthesized brief of what was tested this run and the outcomes: objectives covered, what each worker confirmed or ruled out, and unexplored anomalies observed during recon.",
        ),
      alreadyCoveredObjectives: z
        .array(z.string())
        .optional()
        .describe(
          "Objectives already marked completed on this endpoint (from your assignment context). The planner will avoid re-proposing these.",
        ),
      toolCallDescription: z
        .string()
        .describe(
          "Concise, human-readable description of this step (shown in the UI).",
        ),
    }),
    execute: async ({ target, testingSummary, alreadyCoveredObjectives }) => {
      if (!ctx.model) {
        return {
          success: false,
          message:
            "generate_next_objectives requires a model in the tool context.",
          newObjectives: [],
        };
      }

      const newObjectives = await runObjectiveGenerationAgent(ctx, {
        target,
        testingSummary,
        alreadyCoveredObjectives,
      });

      return {
        success: true,
        newObjectives,
        count: newObjectives.length,
        message:
          newObjectives.length > 0
            ? `Generated ${newObjectives.length} objective(s) for the next run. Include them verbatim in your response's newObjectives field.`
            : "No productive new objectives — the endpoint appears exhausted. Set newObjectives to an empty array in your response.",
      };
    },
  });
}

// ---------------------------------------------------------------------------
// Prompt construction
// ---------------------------------------------------------------------------

function buildObjectiveGenerationPrompt(
  input: GenerateNextObjectivesInput,
): string {
  const covered =
    input.alreadyCoveredObjectives && input.alreadyCoveredObjectives.length > 0
      ? input.alreadyCoveredObjectives.map((o) => `- ${o}`).join("\n")
      : "None recorded.";

  return `# Endpoint
${input.target}

# What was tested this run (with outcomes)
${input.testingSummary}

# Already-completed objectives (do NOT propose these again)
${covered}

Identify the coverage gaps and propose the next iteration's objectives. Call the response tool with \`newObjectives\` (and a brief \`reasoning\`). Return an empty array if the endpoint is genuinely exhausted.`;
}
