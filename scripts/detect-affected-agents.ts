#!/usr/bin/env bun

/**
 * Detect Affected Agents
 *
 * Reads changed file paths from stdin (one per line) and outputs a
 * comma-separated list of agent IDs whose prompts were affected.
 *
 * Usage:
 *   git diff --name-only origin/canary...HEAD | bun run scripts/detect-affected-agents.ts
 *   echo "src/core/agents/specialized/findingJudge/index.ts" | bun run scripts/detect-affected-agents.ts
 */

import { getAffectedAgents } from "../src/core/evals/promptRegistry";

const input = await Bun.stdin.text();
const files = input
  .split("\n")
  .map((l) => l.trim())
  .filter(Boolean);

const agents = getAffectedAgents(files);

if (agents.length > 0) {
  process.stdout.write(agents.join(","));
}
