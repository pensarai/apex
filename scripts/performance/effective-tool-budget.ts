#!/usr/bin/env bun

/**
 * Effective-toolset context-budget benchmark (PR02).
 *
 * Measures the production context-fitting layer (`fitMessagesToContext` +
 * `estimateToolsOverheadTokens`) against the real tool catalog with a
 * boundary-sized conversation — the audit scenario where a tool-light agent
 * (7 selected tools) previously had all ~74 catalog schemas counted toward
 * its budget, forcing Layer-1 truncation work (and, one estimate notch
 * larger, an unnecessary summarization model call) before the provider call.
 *
 * Modes (fresh process per invocation):
 *   all       — fit against the full catalog (pre-PR02 streamResponse shape)
 *   effective — fit against the 7-tool selection streamResponse resolves now
 *
 * The end-to-end wiring (provider schemas, avoided summary, recovery paths)
 * is pinned by the deterministic CI gate in
 * `src/core/ai/ai.effective-tools.test.ts`; this script quantifies the
 * fitting-layer work difference with real constructors and real messages.
 *
 * Usage: bun run scripts/performance/effective-tool-budget.ts [all|effective] [trials]
 */

import { mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ModelMessage } from "ai";
import { createAllTools } from "../../src/core/agents/offSecAgent/tools";
import { getContextWindow, resolveEffectiveTools } from "../../src/core/ai/ai";
import {
  estimateToolsOverheadTokens,
  fitMessagesToContext,
} from "../../src/core/ai/contextManagement";
import { getMaxOutputTokens } from "../../src/core/ai/models";

const MODEL = "claude-sonnet-4-5";
const JUDGE_TOOLS = [
  "execute_command",
  "http_request",
  "read_file",
  "list_files",
  "grep",
  "web_search",
  "get_page",
];

const mode = process.argv[2] ?? "effective";
const trials = Number(process.argv[3] ?? 8);
if (
  !["all", "effective"].includes(mode) ||
  !Number.isInteger(trials) ||
  trials < 1
) {
  throw new Error(
    "Usage: bun run scripts/performance/effective-tool-budget.ts [all|effective] [trials]",
  );
}

const root = mkdtempSync(join(tmpdir(), "apex-tool-budget-"));
const ctx = {
  session: {
    id: "fixture",
    rootPath: root,
    logsPath: join(root, "logs"),
    scratchpadPath: join(root, "scratchpad"),
    findingsPath: join(root, "findings"),
    config: {},
  },
  agentCwd: root,
  sandbox: {
    type: "linux",
    execute: async () => {
      throw new Error("unexpected execution");
    },
  },
} as never;

const all = createAllTools(ctx);
const effective = resolveEffectiveTools(all, JUDGE_TOOLS).tools ?? {};

const contextWindow = getContextWindow(MODEL);
const maxOutputTokens = getMaxOutputTokens(MODEL);
const allOverhead = estimateToolsOverheadTokens(all);
const activeOverhead = estimateToolsOverheadTokens(effective);
const budgetFor = (overhead: number) =>
  contextWindow - maxOutputTokens - overhead - 1_000 - 10_000;
const fullBudget = budgetFor(allOverhead);
const activeBudget = budgetFor(activeOverhead);

// Conversation between the two budgets: fits the effective selection, over
// the full catalog. Includes tool results so Layer 1 has compaction work.
const between = Math.floor((fullBudget + activeBudget) / 2);
const messages: ModelMessage[] = [
  { role: "user", content: "x".repeat((between - 3_000) * 4 - 8) },
  ...Array.from({ length: 6 }, (_, i) => [
    {
      role: "assistant" as const,
      content: [
        {
          type: "tool-call" as const,
          toolName: "http_request",
          toolCallId: `c${i}`,
          input: {},
        },
      ],
    },
    {
      role: "tool" as const,
      content: [
        {
          type: "tool-result" as const,
          toolName: "http_request",
          toolCallId: `c${i}`,
          output: { type: "text" as const, value: "evidence ".repeat(350) },
        },
      ],
    },
  ]).flat(),
];

// Warmup (schema JSON serialization caches, JIT).
for (let i = 0; i < 3; i++) {
  fitMessagesToContext(messages, {
    contextWindow,
    maxOutputTokens,
    tools: mode === "all" ? all : effective,
    sessionPath: root,
  });
}

const results: Array<Record<string, unknown>> = [];
for (let trial = 0; trial < trials; trial++) {
  const trialRoot = join(root, `t${trial}`);
  const cpuStart = process.cpuUsage();
  const t = performance.now();
  const fitted = fitMessagesToContext(messages, {
    contextWindow,
    maxOutputTokens,
    tools: mode === "all" ? all : effective,
    sessionPath: trialRoot,
  });
  const cpu = process.cpuUsage(cpuStart);
  const wallMs = performance.now() - t;
  let persistedFiles = 0;
  try {
    persistedFiles = readdirSync(join(trialRoot, "tool-results")).length;
  } catch {
    persistedFiles = 0;
  }
  results.push({
    mode,
    trial,
    toolsCount:
      mode === "all" ? Object.keys(all).length : Object.keys(effective).length,
    fitsBudget: fitted.fitsBudget,
    modified: fitted.modified,
    estimatedInputTokens: fitted.estimatedInputTokens,
    messageBudget: mode === "all" ? fullBudget : activeBudget,
    persistedToolResults: persistedFiles,
    wallMs,
    cpuMs: (cpu.user + cpu.system) / 1000,
  });
}

console.log(
  "TOOL_BUDGET_BENCH",
  JSON.stringify({
    mode,
    trials,
    model: MODEL,
    contextWindow,
    maxOutputTokens,
    catalogTools: Object.keys(all).length,
    effectiveTools: Object.keys(effective).length,
    allOverheadTokens: allOverhead,
    activeOverheadTokens: activeOverhead,
    fullCatalogMessageBudget: fullBudget,
    effectiveMessageBudget: activeBudget,
    boundaryMessageTokens: between,
    results,
  }),
);

rmSync(root, { recursive: true, force: true });
