import {
  mkdir,
  mkdtemp,
  readFile as read,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  type ModelMessage,
  simulateReadableStream,
  stepCountIs,
  streamText,
  tool,
} from "ai";
import { MockLanguageModelV3 } from "ai/test";
import { afterEach, describe, expect, it, vi } from "vitest";
import { z } from "zod";
import { grep } from "../agents/offSecAgent/tools/grep";
import { readFile } from "../agents/offSecAgent/tools/readFile";
import { resolveToolOutput } from "../agents/offSecAgent/tools/toolOutput";
import type { ToolContext } from "../agents/offSecAgent/tools/types";
import { LocalBackends } from "../tools/backends/local";
import {
  applyToolResultBudget,
  fitMessagesToContext,
} from "./contextManagement";

const roots: string[] = [];
const options = {
  context: {},
  toolCallId: "inspect-compacted",
  messages: [],
};
const original = `${"noise\n".repeat(500)}COMPACTION_EVIDENCE\n${"noise\n".repeat(500)}`;
function history(): ModelMessage[] {
  return [
    {
      role: "tool",
      content: [
        {
          type: "tool-result",
          toolCallId: "browser-snapshot",
          toolName: "browser_snapshot",
          output: { type: "text", value: original },
        },
      ],
    },
  ];
}
function resultText(messages: ModelMessage[]): string {
  const message = messages[0];
  if (message.role !== "tool") throw new Error("expected tool message");
  const part = message.content[0];
  if (part.type !== "tool-result" || part.output.type !== "text")
    throw new Error("expected text result");
  return part.output.value;
}
afterEach(async () => {
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true })),
  );
});

describe("compaction output references", () => {
  it.each([
    "sandbox-root",
    "sandbox-child",
    "injected-root",
    "injected-child",
  ])("keeps a real host spill readable through %s without widening file scope", async (transport) => {
    const root = await mkdtemp(join(tmpdir(), "apex-compaction-output-"));
    roots.push(root);
    const ctx = {
      agentCwd: root,
      fileWorkspaceRoot: join(root, "helpers"),
      session: { rootPath: root, logsPath: join(root, "logs") },
      ...(transport.endsWith("child") ? { subagentId: "owned-worker" } : {}),
    } as ToolContext;
    await mkdir(ctx.fileWorkspaceRoot!, { recursive: true });
    const remote = vi.fn(async () => {
      throw new Error("artifact retrieval must stay on host");
    });
    ctx.sandbox = { type: "windows", execute: remote };
    if (transport.startsWith("injected")) {
      const backend = LocalBackends(ctx);
      ctx.backends = {
        ...backend,
        fs: { ...backend.fs, read: remote, grep: remote },
      };
    }
    const sessionPath = ctx.subagentId
      ? join(root, "subagents", ctx.subagentId)
      : root;
    let compacted = applyToolResultBudget(history(), {
      sessionPath,
      maxResultChars: 500,
    });
    const text = resultText(compacted);
    const ref = text.match(/full output saved to (.+?)\]$/)?.[1];
    expect(ref).toMatch(/^tool-output:[0-9a-f-]{36}$/);
    if (!ref) throw new Error("missing retained output reference");
    expect(text).not.toContain(root);
    const artifact = await resolveToolOutput(ctx, ref);
    expect(await read(artifact!, "utf8")).toBe(original);
    const page = await readFile(ctx).execute?.(
      {
        path: ref,
        startLine: 499,
        endLine: 502,
        toolCallDescription: "Read compacted evidence",
      },
      options,
    );
    expect(page).toMatchObject({
      success: true,
      content: expect.stringContaining("COMPACTION_EVIDENCE"),
    });
    const found = await grep(ctx).execute?.(
      {
        directory: ref,
        pattern: "COMPACTION_EVIDENCE",
        toolCallDescription: "Search compacted evidence",
      },
      options,
    );
    expect(found).toMatchObject({
      success: true,
      output: expect.stringContaining("COMPACTION_EVIDENCE"),
    });
    expect(JSON.stringify([page, found])).not.toContain(root);
    const bytes = await readFile(ctx).execute?.(
      {
        path: ref,
        byteOffset: Buffer.byteLength("noise\n".repeat(500)),
        byteCount: 20,
        toolCallDescription: "Read compacted bytes",
      },
      options,
    );
    expect(bytes).toMatchObject({
      success: true,
      content: expect.stringContaining("COMPACTION_EVIDENCE"),
    });
    expect(remote).not.toHaveBeenCalled();
    compacted = applyToolResultBudget(compacted, {
      sessionPath,
      maxResultChars: 200,
    });
    expect(resultText(compacted)).toContain(ref);
    expect(await read(artifact!, "utf8")).toBe(original);
    const local = { ...ctx, sandbox: undefined, backends: undefined };
    expect(
      await readFile(local).execute?.(
        { path: artifact!, toolCallDescription: "Reject absolute host path" },
        options,
      ),
    ).toMatchObject({
      success: false,
      error: expect.stringContaining("Path escapes file workspace"),
    });
    expect(
      await grep(local).execute?.(
        {
          directory: artifact!,
          pattern: "COMPACTION_EVIDENCE",
          toolCallDescription: "Reject absolute host search",
        },
        options,
      ),
    ).toMatchObject({
      success: false,
      error: expect.stringContaining("Path escapes file workspace"),
    });
    const other = { ...ctx, subagentId: "another-worker" };
    expect(
      await readFile(other).execute?.(
        { path: ref, toolCallDescription: "Reject another owner" },
        options,
      ),
    ).toMatchObject({ success: false });
  });

  it("reuses one artifact when the real streaming SDK rebuilds raw tool history each step", async () => {
    const root = await mkdtemp(join(tmpdir(), "apex-sdk-compaction-output-"));
    roots.push(root);
    let calls = 0;
    const usage = {
      inputTokens: { total: 1, noCache: 1, cacheRead: 0, cacheWrite: 0 },
      outputTokens: { total: 1, text: 1, reasoning: 0 },
    };
    const model = new MockLanguageModelV3({
      doStream: async () => {
        const step = calls++;
        return {
          stream: simulateReadableStream({
            chunks: [
              ...(step < 2
                ? [
                    {
                      type: "tool-call" as const,
                      toolCallId: `call-${step}`,
                      toolName:
                        step === 0 ? "browser_snapshot" : "continue_work",
                      input: "{}",
                    },
                  ]
                : [
                    { type: "text-start" as const, id: "done" },
                    { type: "text-delta" as const, id: "done", delta: "done" },
                    { type: "text-end" as const, id: "done" },
                  ]),
              {
                type: "finish" as const,
                finishReason: {
                  unified:
                    step < 2 ? ("tool-calls" as const) : ("stop" as const),
                  raw: "stop",
                },
                usage,
              },
            ],
          }),
        };
      },
    });
    const refs: string[] = [];
    const rawResults: string[] = [];
    const result = streamText({
      model,
      prompt: "Inspect a synthetic snapshot, continue, then finish",
      tools: {
        browser_snapshot: tool({
          inputSchema: z.object({}),
          execute: async () => original,
        }),
        continue_work: tool({
          inputSchema: z.object({}),
          execute: async () => "continued",
        }),
      },
      stopWhen: stepCountIs(3),
      prepareStep: ({ initialMessages, responseMessages, stepNumber }) => {
        const messages = [...initialMessages, ...responseMessages];
        if (stepNumber === 0) return;
        const raw = messages.find((message) => message.role === "tool");
        if (!raw || raw.role !== "tool")
          throw new Error("missing raw tool result");
        const part = raw.content[0];
        if (part.type !== "tool-result" || part.output.type !== "text")
          throw new Error("expected raw text result");
        rawResults.push(part.output.value);
        const fitted = fitMessagesToContext(messages, {
          sessionPath: root,
          contextWindow: 500,
          maxOutputTokens: 0,
          overheadTokens: 0,
          safetyMarginTokens: 0,
        });
        const ref = JSON.stringify(fitted.messages).match(
          /tool-output:[0-9a-f-]{36}/,
        )?.[0];
        if (!ref) throw new Error("missing compacted reference");
        refs.push(ref);
        return { messages: fitted.messages };
      },
    });
    await result.consumeStream();
    expect(await result.text).toBe("done");
    expect(rawResults).toEqual([original, original]);
    expect(refs).toHaveLength(2);
    expect(new Set(refs).size).toBe(1);
    expect(await readdir(join(root, "logs", "tool-output"))).toHaveLength(1);
  });

  it("keeps changed original bytes separate without changing an earlier reference", async () => {
    const root = await mkdtemp(join(tmpdir(), "apex-compaction-content-"));
    roots.push(root);
    const ctx = {
      session: { rootPath: root, logsPath: join(root, "logs") },
    } as ToolContext;
    const compact = (messages: ModelMessage[]) =>
      resultText(
        applyToolResultBudget(messages, {
          sessionPath: root,
          maxResultChars: 500,
        }),
      ).match(/tool-output:[0-9a-f-]{36}/)?.[0];
    const first = compact(history());
    const same = compact(history());
    expect(same).toBe(first);
    expect(await readdir(join(root, "logs", "tool-output"))).toHaveLength(1);
    const changed = history();
    const message = changed[0];
    if (message.role !== "tool" || message.content[0].type !== "tool-result")
      throw new Error("expected tool result");
    message.content[0].output = { type: "text", value: `${original}CHANGED` };
    const second = compact(changed);
    expect(second).not.toBe(first);
    if (!first || !second) throw new Error("missing references");
    expect(await read((await resolveToolOutput(ctx, first))!, "utf8")).toBe(
      original,
    );
    expect(await read((await resolveToolOutput(ctx, second))!, "utf8")).toBe(
      `${original}CHANGED`,
    );
    expect(await readdir(join(root, "logs", "tool-output"))).toHaveLength(2);
  });

  it("rejects mismatched existing bytes instead of reusing a phantom preserved result", async () => {
    const root = await mkdtemp(
      join(tmpdir(), "apex-compaction-reuse-failure-"),
    );
    roots.push(root);
    const ctx = {
      session: { rootPath: root, logsPath: join(root, "logs") },
    } as ToolContext;
    const opts = { sessionPath: root, maxResultChars: 500 };
    const ref = resultText(applyToolResultBudget(history(), opts)).match(
      /tool-output:[0-9a-f-]{36}/,
    )?.[0];
    if (!ref) throw new Error("missing reference");
    const artifact = await resolveToolOutput(ctx, ref);
    await writeFile(artifact!, "corrupt");
    expect(() => applyToolResultBudget(history(), opts)).toThrow(
      "Referenced tool output is unavailable",
    );
    expect(await readdir(join(root, "logs", "tool-output"))).toHaveLength(1);
  });

  it("does not claim a readable reference after a host spill write fails", async () => {
    const root = await mkdtemp(join(tmpdir(), "apex-compaction-failure-"));
    roots.push(root);
    await mkdir(join(root, "logs"));
    await writeFile(join(root, "logs", "tool-output"), "not a directory");
    expect(() =>
      applyToolResultBudget(history(), {
        sessionPath: root,
        maxResultChars: 500,
      }),
    ).toThrow(/Referenced tool output is unavailable/);
  });
});
