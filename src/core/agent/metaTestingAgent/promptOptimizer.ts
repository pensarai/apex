/**
 * Prompt Optimizer (Meta-Prompting)
 *
 * Metaprompting
 * - Analyzes what approaches worked vs failed
 * - Generates an optimized execution prompt
 * - Removes dead-end tactics
 * - Emphasizes working approaches
 * - Records learned constraints
 *
 * The optimized prompt is written to execution_prompt_optimized.md in the session directory.
 */

import { tool } from "ai";
import { z } from "zod";
import { join } from "path";
import { existsSync, writeFileSync, readFileSync } from "fs";
import { Logger } from "../logger";
import type {
  Adaptation,
  PromptOptimization,
  MetaTestingSessionInfo,
} from "./types";
import { loadAdaptations } from "./planMemory";

const BASE_OPTIMIZATION_PROMPT = `
## Runtime Learned Patterns

This section contains patterns learned during this testing session.
Use this information to guide your approach selection.
`;

export function createPromptOptimizerTool(
  session: MetaTestingSessionInfo,
  logger: Logger
) {
  const optimizedPromptPath = join(
    session.rootPath,
    "execution_prompt_optimized.md"
  );

  const optimize_prompt = tool({
    description: `Analyze what worked vs failed and update execution guidance.

**When to call:**
- After 3+ failed attempts on similar approaches
- At budget checkpoints (20%/40%/60%/80%)
- When pivoting to a new approach
- After discovering a significant constraint

**What this does:**
1. Reads all adaptations (store_adaptation records)
2. Categorizes approaches by success/failure
3. Extracts learned constraints
4. Generates optimized execution guidance
5. Writes to execution_prompt_optimized.md

**The optimized prompt includes:**
- KNOWN CONSTRAINTS: Approaches that definitely won't work
- WORKING APPROACHES: Tactics that succeeded (prioritize these)
- EXHAUSTED APPROACHES: Tactics that failed (skip these)

This is meta-prompting: the agent optimizing its own guidance based on experience.`,
    inputSchema: z.object({
      toolCallDescription: z
        .string()
        .describe(
          "A concise, human-readable description of what this tool call is doing (e.g., 'Optimizing execution prompt based on learned patterns')"
        ),
    }),
    execute: async () => {
      try {
        const adaptations = loadAdaptations(session.rootPath);

        if (adaptations.length === 0) {
          return {
            success: false,
            error: "NO_ADAPTATIONS",
            message: `No adaptations recorded yet.

Record approach outcomes with store_adaptation:
- worked=true for successful approaches
- worked=false for failed approaches
- constraint_learned for discovered blockers

Then call optimize_prompt to generate optimized guidance.`,
          };
        }

        // Categorize adaptations
        const worked = adaptations.filter((a) => a.worked);
        const failed = adaptations.filter((a) => !a.worked);
        const constraints = adaptations
          .filter((a) => a.constraint_learned)
          .map((a) => a.constraint_learned!)
          .filter((v, i, arr) => arr.indexOf(v) === i); // unique

        // Generate optimization
        const optimization: PromptOptimization = {
          remove_tactics: failed.map((f) => f.approach),
          emphasize_tactics: worked.map((w) => w.approach),
          constraints,
          timestamp: new Date().toISOString(),
        };

        const optimizedPrompt = generateOptimizedPrompt(optimization);

        writeFileSync(optimizedPromptPath, optimizedPrompt);
        logger.info(
          `Optimized prompt generated: ${worked.length} working, ${failed.length} failed, ${constraints.length} constraints`
        );

        const optimizationPath = join(
          session.rootPath,
          "prompt_optimization.json"
        );
        writeFileSync(optimizationPath, JSON.stringify(optimization, null, 2));

        return {
          success: true,
          optimization,
          message: `Execution guidance optimized!

**Analysis:**
- Working approaches: ${worked.length}
- Failed approaches: ${failed.length}
- Constraints learned: ${constraints.length}

**Generated guidance saved to:** execution_prompt_optimized.md

**Summary of optimizations:**

${
  constraints.length > 0
    ? `**CONSTRAINTS (avoid):**
${constraints.map((c) => `- ${c}`).join("\n")}
`
    : ""
}
${
  worked.length > 0
    ? `**WORKING APPROACHES (prioritize):**
${worked.map((w) => `- ${w.approach}`).join("\n")}
`
    : ""
}
${
  failed.length > 0
    ? `**EXHAUSTED APPROACHES (skip):**
${failed
  .slice(-5)
  .map((f) => `- ${f.approach}`)
  .join("\n")}${
        failed.length > 5 ? `\n  ... and ${failed.length - 5} more` : ""
      }
`
    : ""
}

**Next steps:**
1. Apply these learnings to your next hypothesis
2. Avoid exhausted approaches
3. Build on working approaches`,
        };
      } catch (error: any) {
        logger.error(`Failed to optimize prompt: ${error.message}`);
        return {
          success: false,
          error: error.message,
          message: `Failed to optimize prompt: ${error.message}`,
        };
      }
    },
  });

  return { optimize_prompt };
}


function generateOptimizedPrompt(opt: PromptOptimization): string {
  let prompt = `# Optimized Execution Guidance

Generated: ${opt.timestamp}

This guidance is based on patterns learned during this testing session.
Use this to inform your approach selection and avoid dead ends.

---
`;

  // Add learned constraints (highest priority - things that definitely won't work)
  if (opt.constraints.length > 0) {
    prompt += `
## KNOWN CONSTRAINTS (Avoid These Approaches)

The following blockers have been discovered during testing.
Do NOT attempt approaches that violate these constraints.

`;
    for (const constraint of opt.constraints) {
      prompt += `- **BLOCKED:** ${constraint}\n`;
    }
    prompt += "\n";
  }

  // Add working tactics (prioritize these)
  if (opt.emphasize_tactics.length > 0) {
    prompt += `
## WORKING APPROACHES (Prioritize These)

The following approaches have been successful during this session.
Consider similar techniques for remaining targets.

`;
    // Deduplicate and show unique working approaches
    const uniqueWorking = Array.from(new Set(opt.emphasize_tactics));
    for (const tactic of uniqueWorking) {
      prompt += `- **SUCCESS:** ${tactic}\n`;
    }
    prompt += "\n";
  }

  // Add failed tactics (skip these)
  if (opt.remove_tactics.length > 0) {
    prompt += `
## EXHAUSTED APPROACHES (Skip These)

The following approaches have been tried and failed.
Do NOT retry these exact approaches - pivot to different techniques.

`;
    // Deduplicate and show recent failures
    const uniqueFailed = Array.from(new Set(opt.remove_tactics));
    const recentFailed = uniqueFailed.slice(-10); // Show last 10 unique failures
    for (const tactic of recentFailed) {
      prompt += `- **FAILED:** ${tactic}\n`;
    }
    if (uniqueFailed.length > 10) {
      prompt += `- ... and ${
        uniqueFailed.length - 10
      } more failed approaches\n`;
    }
    prompt += "\n";
  }

  // Add guidance on how to use this information
  prompt += `
---

## How to Apply This Guidance

1. **Before each hypothesis:**
   - Check if your planned approach matches a KNOWN CONSTRAINT
   - If so, choose a different technique

2. **Prioritize working patterns:**
   - If a similar approach worked before, try variations of it
   - Successful approaches often reveal productive attack vectors

3. **Avoid exhausted approaches:**
   - Don't retry exact approaches that failed
   - However, variations or different targets may still work

4. **Update this guidance:**
   - Call store_adaptation after each significant attempt
   - Call optimize_prompt to regenerate this guidance

Remember: Direct-first economics - always prefer the shortest path to your objective.
`;

  return prompt;
}

export function loadOptimizedPrompt(sessionRootPath: string): string | null {
  const optimizedPromptPath = join(
    sessionRootPath,
    "execution_prompt_optimized.md"
  );

  if (!existsSync(optimizedPromptPath)) {
    return null;
  }

  try {
    return readFileSync(optimizedPromptPath, "utf-8");
  } catch {
    return null;
  }
}

export function loadOptimization(
  sessionRootPath: string
): PromptOptimization | null {
  const optimizationPath = join(sessionRootPath, "prompt_optimization.json");

  if (!existsSync(optimizationPath)) {
    return null;
  }

  try {
    return JSON.parse(readFileSync(optimizationPath, "utf-8"));
  } catch {
    return null;
  }
}
