/**
 * Prompt Registry
 *
 * Maps source file paths to the agent IDs whose prompts they contain.
 * Used by scripts/detect-affected-agents.ts to determine which agents
 * are affected by a given set of file changes (e.g., in a PR).
 */

export type EvalAgentId =
  | "pentest"
  | "attack-surface"
  | "authentication"
  | "code"
  | "whitebox"
  | "patching"
  | "environment"
  | "finding-judge"
  | "cvss-scorer"
  | "base";

/**
 * Maps normalized file paths (relative to repo root) to the agent IDs
 * whose prompts live in that file. A single file may affect multiple agents.
 */
export const PROMPT_FILE_MAP: Record<string, EvalAgentId[]> = {
  "src/core/agents/specialized/pentest/agent.ts": ["pentest"],
  "src/core/agents/specialized/attackSurface/prompts.ts": ["attack-surface"],
  "src/core/agents/specialized/authenticationAgent/prompts.ts": [
    "authentication",
  ],
  "src/core/agents/specialized/codeAgent/prompts.ts": ["code"],
  "src/core/agents/specialized/whiteboxAttackSurface/prompts.ts": ["whitebox"],
  "src/core/agents/specialized/patching/prompts.ts": ["patching"],
  "src/core/agents/specialized/environment/prompts.ts": ["environment"],
  "src/core/agents/specialized/findingJudge/index.ts": ["finding-judge"],
  "src/core/agents/specialized/cvssScorer/index.ts": ["cvss-scorer"],
  "src/core/agents/offSecAgent/prompt.ts": ["base"],
};

/**
 * Given a list of changed file paths, returns the deduplicated set of
 * agent IDs whose prompts may have been affected.
 */
export function getAffectedAgents(changedFiles: string[]): EvalAgentId[] {
  const agents = new Set<EvalAgentId>();
  for (const file of changedFiles) {
    const normalized = file.replace(/^\.\//, "");
    const match = PROMPT_FILE_MAP[normalized];
    if (match) {
      for (const id of match) agents.add(id);
    }
  }
  return [...agents];
}
