#!/usr/bin/env bun

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { type LanguageModelMiddleware, tool } from "ai";
import { z } from "zod";
import { normalizeStepUsage, streamResponse } from "../../src/core/ai/ai";
import { AVAILABLE_MODELS, getMaxOutputTokens } from "../../src/core/ai/models";

const fixtureCommit = "6bd9a0ebe859eb724b3f7261a9ba3ffc685174a7";
const fixtureFiles = [
  "src/core/ai/ai.ts",
  "src/core/ai/contextManagement.ts",
  "src/core/agents/offSecAgent/offensiveSecurityAgent.ts",
  "src/core/agents/offSecAgent/prompt.ts",
  "src/core/agents/offSecAgent/runtimeContext.ts",
  "src/core/agents/offSecAgent/streamDiagnostics.ts",
  "src/core/agents/offSecAgent/subagentSpawner.ts",
  "src/core/agents/offSecAgent/tools/fileWorkspace.ts",
  "src/core/agents/offSecAgent/tools/grepImpl.ts",
  "src/core/agents/offSecAgent/tools/executeCommand.ts",
  "src/core/agents/offSecAgent/tools/applyPatchImpl.ts",
  "src/core/agents/offSecAgent/tools/browserToolFactories.ts",
] as const;
const searchTerms = ["context", "session", "tool", "stream", "error"];
const requestedSteps = Number(process.argv[2] ?? 30);
const declaredContextWindow = Number(process.argv[3] ?? 96_000);
const model = process.argv[4] ?? "claude-haiku-4-5";
const maxInputTokens = Number(
  process.argv[5] ?? (requestedSteps > 60 ? 5_000_000 : 1_000_000),
);
const resultCharacterLimit = Number(process.argv[6] ?? 1_500);
const cacheRunTag = process.env.APEX_CACHE_RUN_TAG ?? "";
const cacheToolChoice = process.env.APEX_CACHE_TOOL_CHOICE ?? "required";
if (
  ![15, 30, 60, 120].includes(requestedSteps) ||
  !Number.isSafeInteger(declaredContextWindow) ||
  declaredContextWindow < 96_000 ||
  declaredContextWindow > 1_000_000 ||
  !Number.isSafeInteger(maxInputTokens) ||
  maxInputTokens < 100_000 ||
  !Number.isSafeInteger(resultCharacterLimit) ||
  resultCharacterLimit < 1_500 ||
  resultCharacterLimit > 96_000
) {
  throw new Error(
    "Usage: operator-context-workflow-live.ts [steps: 15|30|60|120] [local window: 96000..1000000] [model] [input token cap] [result character limit: 1500..96000]",
  );
}
if (cacheRunTag && !/^[a-zA-Z0-9_-]{1,32}$/.test(cacheRunTag)) {
  throw new Error("APEX_CACHE_RUN_TAG must be 1–32 alphanumeric characters");
}
if (cacheToolChoice !== "required" && cacheToolChoice !== "auto") {
  throw new Error("APEX_CACHE_TOOL_CHOICE must be required or auto");
}
if (!process.env.ANTHROPIC_API_KEY) {
  throw new Error("Set ANTHROPIC_API_KEY before running the live benchmark");
}
const modelInfo = AVAILABLE_MODELS.find((entry) => entry.id === model);
if (!modelInfo) throw new Error("Benchmark model is missing from the catalog");
modelInfo.contextLength = declaredContextWindow;

const sessionPath = mkdtempSync(join(tmpdir(), "apex-context-workflow-"));
const snapshotPath = join(sessionPath, "repository");
const snapshotHash = createHash("sha256");
const toolResultHash = createHash("sha256");
let toolCalls = 0;
let readOps = 0;
let searchOps = 0;
let listOps = 0;
let toolResultChars = 0;
let totalInputTokens = 0;
let totalOutputTokens = 0;
let cacheReadTokens = 0;
let cacheWriteTokens = 0;
let uncachedInputTokens = 0;
let stepsWithoutCacheUsage = 0;
let summaryCalls = 0;
let summaryEvents = 0;
let stopForBudget = false;
let providerStreamAttempts = 0;
let providerGenerateAttempts = 0;
const mainStepInputTokens: number[] = [];
const mainStepCacheReadTokens: number[] = [];
const mainStepCacheWriteTokens: number[] = [];
const mainStepUncachedInputTokens: number[] = [];
const summaryInputTokens: number[] = [];
const summaryCacheReadTokens: number[] = [];
const summaryCacheWriteTokens: number[] = [];
const started = performance.now();
const attemptCounter: LanguageModelMiddleware = {
  specificationVersion: "v3",
  wrapStream: async ({ doStream }) => {
    providerStreamAttempts++;
    return doStream();
  },
  wrapGenerate: async ({ doGenerate }) => {
    providerGenerateAttempts++;
    return doGenerate();
  },
};

function inspectNext(): string {
  const index = toolCalls++;
  let result: string;
  if (index % 10 === 0) {
    listOps++;
    const directory =
      index % 20 === 0 ? "src/core/ai" : "src/core/agents/offSecAgent/tools";
    const names = readdirSync(join(snapshotPath, directory)).sort();
    result = `list_files ${directory}\n${names.join("\n")}`;
  } else if (index % 10 === 1) {
    searchOps++;
    const term = searchTerms[Math.floor(index / 10) % searchTerms.length];
    const matches: string[] = [];
    for (const path of fixtureFiles) {
      const lines = readFileSync(join(snapshotPath, path), "utf8").split("\n");
      for (let line = 0; line < lines.length; line++) {
        if (lines[line].toLowerCase().includes(term)) {
          matches.push(`${path}:${line + 1}: ${lines[line].slice(0, 180)}`);
        }
      }
    }
    result = `search_files ${term}\n${matches.join("\n").slice(0, resultCharacterLimit)}`;
  } else {
    readOps++;
    const path = fixtureFiles[(index * 7) % fixtureFiles.length];
    const lines = readFileSync(join(snapshotPath, path), "utf8").split("\n");
    const first = (Math.floor(index / 10) * 35) % lines.length;
    const excerpt: string[] = [];
    let length = 0;
    for (let line = first; line < lines.length; line++) {
      const entry = `${line + 1}: ${lines[line]}\n`;
      if (length + entry.length > resultCharacterLimit) break;
      excerpt.push(entry);
      length += entry.length;
    }
    result = `read_file ${path}:${first + 1}\n${excerpt.join("")}`;
  }
  toolResultChars += result.length;
  toolResultHash.update(result);
  return result;
}

try {
  for (const path of fixtureFiles) {
    const content = execFileSync("git", ["show", `${fixtureCommit}:${path}`], {
      encoding: "utf8",
    });
    const destination = join(snapshotPath, path);
    mkdirSync(dirname(destination), { recursive: true });
    writeFileSync(destination, content);
    snapshotHash.update(path).update("\0").update(content).update("\0");
  }

  const stream = streamResponse({
    model,
    prompt: `Inspect the repository for ${requestedSteps} steps. Call inspect_next once per step to follow the fixed file workflow.${cacheRunTag ? ` Run ${cacheRunTag}.` : ""}`,
    system:
      "This is a controlled repository-inspection benchmark. Call inspect_next once per step and do not visit an external target.",
    tools: {
      inspect_next: tool({
        description:
          "Execute the next fixed directory listing, source search, or file read",
        inputSchema: z.object({}),
        execute: async () => inspectNext(),
      }),
    },
    toolChoice:
      cacheToolChoice === "auto"
        ? "auto"
        : { type: "tool", toolName: "inspect_next" },
    stopWhen: () => toolCalls >= requestedSteps || stopForBudget,
    sessionPath,
    languageModelMiddleware: attemptCounter,
    silent: true,
    onStepFinish: (step) => {
      const usage = normalizeStepUsage(step);
      if (usage.inputTokens <= 0) {
        throw new Error(
          "Provider did not report input tokens for a completed call",
        );
      }
      totalInputTokens += usage.inputTokens;
      totalOutputTokens += usage.outputTokens;
      cacheReadTokens += usage.cacheReadTokens;
      cacheWriteTokens += usage.cacheWriteTokens;
      const uncached =
        usage.inputTokens - usage.cacheReadTokens - usage.cacheWriteTokens;
      if (uncached < 0) {
        throw new Error("Provider cache buckets exceed total input tokens");
      }
      uncachedInputTokens += uncached;
      const anthropicMetadata = (
        step.providerMetadata as
          | { anthropic?: Record<string, unknown> }
          | undefined
      )?.anthropic;
      const inputDetails = step.usage.inputTokenDetails;
      if (
        typeof anthropicMetadata?.cacheReadInputTokens !== "number" &&
        typeof inputDetails?.cacheReadTokens !== "number"
      ) {
        stepsWithoutCacheUsage++;
      }
      if (step.response.id === "summarization") {
        summaryCalls++;
        summaryInputTokens.push(usage.inputTokens);
        summaryCacheReadTokens.push(usage.cacheReadTokens);
        summaryCacheWriteTokens.push(usage.cacheWriteTokens);
      } else {
        mainStepInputTokens.push(usage.inputTokens);
        mainStepCacheReadTokens.push(usage.cacheReadTokens);
        mainStepCacheWriteTokens.push(usage.cacheWriteTokens);
        mainStepUncachedInputTokens.push(uncached);
      }
      const last = mainStepInputTokens.at(-1) ?? 0;
      const previous = mainStepInputTokens.at(-2) ?? 0;
      const projectedNext = last + Math.max(0, last - previous);
      stopForBudget =
        totalInputTokens + projectedNext > maxInputTokens - 25_000;
    },
  });

  for await (const part of stream.fullStream) {
    if (
      part.type === "tool-call" &&
      part.toolName === "summarize_conversation"
    ) {
      summaryEvents++;
    }
  }

  if (
    toolCalls !== requestedSteps ||
    mainStepInputTokens.length !== requestedSteps
  ) {
    throw new Error(
      `Incomplete workload: ${toolCalls} tool calls and ${mainStepInputTokens.length} model steps`,
    );
  }
  if (summaryCalls !== summaryEvents) {
    throw new Error("Summary usage and compaction event counts differ");
  }
  if (totalInputTokens > maxInputTokens) {
    throw new Error("Live benchmark exceeded the input token budget");
  }

  console.log(
    "OPERATOR_CONTEXT_WORKFLOW",
    JSON.stringify({
      runtimeSha: execFileSync("git", ["rev-parse", "HEAD"], {
        encoding: "utf8",
      }).trim(),
      fixtureCommit,
      snapshotSha256: snapshotHash.digest("hex"),
      toolResultsSha256: toolResultHash.digest("hex"),
      model,
      cacheRunTag,
      cacheToolChoice,
      declaredContextWindow,
      maxOutputTokens: getMaxOutputTokens(model),
      requestedSteps,
      maxInputTokens,
      resultCharacterLimit,
      toolCalls,
      readOps,
      searchOps,
      listOps,
      toolResultChars,
      mainProviderCalls: mainStepInputTokens.length,
      providerStreamAttempts,
      providerGenerateAttempts,
      summaryCalls,
      totalInputTokens,
      totalOutputTokens,
      cacheReadTokens,
      cacheWriteTokens,
      uncachedInputTokens,
      stepsWithoutCacheUsage,
      mainStepCacheReadTokens,
      mainStepCacheWriteTokens,
      mainStepUncachedInputTokens,
      summaryCacheReadTokens,
      summaryCacheWriteTokens,
      peakMainStepInputTokens: Math.max(...mainStepInputTokens),
      firstMainStepInputTokens: mainStepInputTokens[0],
      lastMainStepInputTokens: mainStepInputTokens.at(-1),
      mainStepInputTokens,
      summaryInputTokens,
      elapsedMs: Math.round(performance.now() - started),
    }),
  );
} catch (error) {
  console.log(
    "OPERATOR_CONTEXT_WORKFLOW_FAILURE",
    JSON.stringify({
      model,
      cacheRunTag,
      requestedSteps,
      declaredContextWindow,
      resultCharacterLimit,
      toolCalls,
      mainProviderCalls: mainStepInputTokens.length,
      providerStreamAttempts,
      providerGenerateAttempts,
      summaryCalls,
      totalInputTokens,
      cacheReadTokens,
      cacheWriteTokens,
      uncachedInputTokens,
      errorName: error instanceof Error ? error.name : "unknown",
      elapsedMs: Math.round(performance.now() - started),
    }),
  );
  throw error;
} finally {
  rmSync(sessionPath, { recursive: true, force: true });
}
