#!/usr/bin/env bun

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { type ModelMessage, stepCountIs, tool } from "ai";
import { z } from "zod";
import {
  normalizeStepUsage,
  type StreamResponseOpts,
  streamResponse,
} from "../../src/core/ai/ai";
import { estimateMessageTokens } from "../../src/core/ai/contextManagement";
import {
  createSummarizationStream,
  getProviderModel,
} from "../../src/core/ai/utils";

const fixtureCommit = "6bd9a0ebe859eb724b3f7261a9ba3ffc685174a7";
const sourcePath = "src/core/ai/contextManagement.ts";
const model = "claude-haiku-4-5";
const marker = "MAPLE-ORBIT-47";
const runTag = process.env.APEX_CACHE_RUN_TAG ?? "";
const forceSummary = process.env.APEX_FORCE_SUMMARY === "1";
if (!process.env.ANTHROPIC_API_KEY) {
  throw new Error("Set ANTHROPIC_API_KEY before running the live benchmark");
}
if (!/^[a-zA-Z0-9_-]{1,32}$/.test(runTag)) {
  throw new Error("Set APEX_CACHE_RUN_TAG to 1–32 alphanumeric characters");
}

const source = execFileSync("git", ["show", `${fixtureCommit}:${sourcePath}`], {
  encoding: "utf8",
});
const sourceExcerpt = source
  .repeat(Math.ceil(12_000 / source.length))
  .slice(0, 12_000);
const resultHash = createHash("sha256");
const messages: ModelMessage[] = [
  {
    role: "user",
    content: `Inspect the fixed source excerpts. The audit marker in the first file result must be recalled later. Run ${runTag}.`,
  },
];
let index = 0;
function addRead(): void {
  const toolCallId = `read-${index}`;
  const result = `read_file ${sourcePath}:${index * 35 + 1}\n${
    index === 0 ? `AUDIT_MARKER=${marker}\n` : ""
  }${sourceExcerpt}`;
  resultHash.update(result);
  messages.push(
    {
      role: "assistant",
      content: [
        { type: "tool-call", toolCallId, toolName: "inspect_file", input: {} },
      ],
    },
    {
      role: "tool",
      content: [
        {
          type: "tool-result",
          toolCallId,
          toolName: "inspect_file",
          output: { type: "text", value: result },
        },
      ],
    },
  );
  index++;
}
while (estimateMessageTokens(messages) < 90_000) addRead();
const warmHistory = [...messages];
while (estimateMessageTokens(messages) < 105_000) addRead();

const sessionPath = mkdtempSync(join(tmpdir(), "apex-summary-cache-"));
const calls: Array<{
  phase: "warm" | "summary";
  input: number;
  read: number;
  write: number;
}> = [];
const tools = {
  inspect_file: tool({
    description: "Read the next source excerpt",
    inputSchema: z.object({}),
  }),
};
const system =
  "Controlled public-source compaction benchmark. Do not call tools.";
const options = {
  model,
  prompt: "What is the audit marker in the first file result?",
  system,
  tools,
  toolChoice: "auto" as const,
  stopWhen: stepCountIs(1),
  sessionPath,
  silent: true,
};
try {
  const warm = streamResponse({
    ...options,
    messages: warmHistory,
    onStepFinish: (step) => {
      const usage = normalizeStepUsage(step);
      calls.push({
        phase: "warm",
        input: usage.inputTokens,
        read: usage.cacheReadTokens,
        write: usage.cacheWriteTokens,
      });
    },
  });
  for await (const _part of warm.fullStream) void _part;

  let summaries = 0;
  const answer: string[] = [];
  const onStepFinish: NonNullable<StreamResponseOpts["onStepFinish"]> = (
    step,
  ) => {
    const usage = normalizeStepUsage(step);
    if (step.response.id === "summarization") summaries++;
    calls.push({
      phase: "summary",
      input: usage.inputTokens,
      read: usage.cacheReadTokens,
      write: usage.cacheWriteTokens,
    });
  };
  const resumedOptions = { ...options, messages, onStepFinish };
  const resumed = forceSummary
    ? createSummarizationStream(
        messages,
        resumedOptions,
        getProviderModel(model),
      )
    : streamResponse(resumedOptions);
  for await (const part of resumed.fullStream) {
    if (part.type === "text-delta") answer.push(part.text);
  }
  console.log(
    "OPERATOR_SUMMARY_CACHE",
    JSON.stringify({
      runtimeSha: execFileSync("git", ["rev-parse", "HEAD"], {
        encoding: "utf8",
      }).trim(),
      fixtureCommit,
      resultSha256: resultHash.digest("hex"),
      model,
      runTag,
      forceSummary,
      warmReads: (warmHistory.length - 1) / 2,
      totalReads: (messages.length - 1) / 2,
      warmEstimatedTokens: estimateMessageTokens(warmHistory),
      totalEstimatedTokens: estimateMessageTokens(messages),
      summaries,
      calls,
      recalledMarker: answer.join("").includes(marker),
    }),
  );
} finally {
  rmSync(sessionPath, { recursive: true, force: true });
}
