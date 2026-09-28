import { randomUUID } from "node:crypto";
import {
  mkdir,
  mkdtemp,
  readFile as read,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateText, stepCountIs } from "ai";
import { MockLanguageModelV3 } from "ai/test";
import { afterEach, describe, expect, it, vi } from "vitest";
import { applyToolResultBudget } from "../../../ai/contextManagement";
import { executeCommand } from "./executeCommand";
import { grep } from "./grep";
import { type ReadFileResult, readFile } from "./readFile";
import {
  boundedOutputPreview,
  resolveToolOutput,
  TOOL_OUTPUT_MAX_BYTES,
  TOOL_OUTPUT_MAX_LINES,
  toolOutputForModel,
} from "./toolOutput";
import type { ToolContext } from "./types";

const roots: string[] = [];
async function context(): Promise<ToolContext> {
  const root = await mkdtemp(join(tmpdir(), "apex-output-test-"));
  roots.push(root);
  await mkdir(join(root, "helpers"));
  return {
    agentCwd: root,
    fileWorkspaceRoot: join(root, "helpers"),
    session: { rootPath: root, logsPath: join(root, "logs") },
  } as ToolContext;
}
afterEach(async () => {
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true })),
  );
});
const options = { toolCallId: "output-test", messages: [] };
function reference(text: string): string {
  const ref = text.match(/tool-output:[0-9a-f-]{36}/)?.[0];
  expect(ref).toBeDefined();
  return ref as string;
}

describe("bounded model output", () => {
  it("leaves small results intact and keeps the reported probe sizes inline", async () => {
    const ctx = await context();
    for (const size of [0, 6_500, 8_400]) {
      const output = { success: true, error: "", stdout: "x".repeat(size) };
      expect(await toolOutputForModel(ctx, output)).toEqual({
        type: "json",
        value: output,
      });
    }
    const escaped = { success: true, error: "", stdout: "\\".repeat(26_000) };
    const projected = await toolOutputForModel(ctx, escaped);
    expect(projected.type).toBe("text");
    expect(String(projected.value).includes(escaped.stdout)).toBe(true);
    expect(String(projected.value).includes("output omitted")).toBe(false);
  });

  it("bounds bytes and lines, preserves both ends, and never splits Unicode", () => {
    for (const text of [
      `first\n${"row\n".repeat(4_000)}last`,
      `first${"🔐界".repeat(50_000)}last`,
    ]) {
      const preview = boundedOutputPreview(text, "[omitted]");
      expect(Buffer.byteLength(preview)).toBeLessThanOrEqual(
        TOOL_OUTPUT_MAX_BYTES,
      );
      expect(preview.split("\n").length).toBeLessThanOrEqual(
        TOOL_OUTPUT_MAX_LINES,
      );
      expect(preview.startsWith("first")).toBe(true);
      expect(preview.endsWith("last")).toBe(true);
      expect(preview).not.toContain("�");
    }
    expect(boundedOutputPreview("short", "[omitted]", 100, 20)).toBe("short");
  });

  it("retains middle evidence, stderr, and incomplete status without mutating the original", async () => {
    const ctx = await context();
    const output = {
      success: false,
      exitCode: 124,
      error: "Command timed out",
      stdout: `${"a".repeat(70_000)}DECISIVE_MIDDLE${"b".repeat(70_000)}`,
      stderr: "e".repeat(70_000),
      stdoutTruncated: true,
    };
    const original = structuredClone(output);
    const projected = await toolOutputForModel(ctx, output);
    expect(projected.type).toBe("text");
    const text = String(projected.value);
    expect(text).toContain("success=false; exitCode=124; capture=INCOMPLETE");
    expect(text).not.toContain("DECISIVE_MIDDLE");
    const file = await resolveToolOutput(ctx, reference(text));
    const captured = await read(file as string, "utf8");
    expect(captured).toContain(output.stdout);
    expect(captured).toContain(output.stderr);
    expect(output).toEqual(original);
    expect(Buffer.byteLength(text)).toBeLessThanOrEqual(TOOL_OUTPUT_MAX_BYTES);
    let history = [
      {
        role: "tool" as const,
        content: [
          {
            type: "tool-result" as const,
            toolCallId: "captured",
            toolName: "execute_command",
            output: projected,
          },
        ],
      },
    ];
    for (const maxResultChars of [10_000, 5_000, 2_000, 500]) {
      history = applyToolResultBudget(history, {
        sessionPath: ctx.session.rootPath,
        maxResultChars,
      }) as typeof history;
      expect(JSON.stringify(history)).toContain(reference(text));
    }
  });

  it("reads and searches owned host artifacts from a sandbox worker without widening ordinary file access", async () => {
    const ctx = await context();
    const remote = vi.fn(async () => {
      throw new Error("artifact retrieval must stay on host");
    });
    ctx.sandbox = { type: "windows", execute: remote };
    const output = {
      success: true,
      error: "",
      stdout: `${"noise\n".repeat(3_000)}MIDDLE_EVIDENCE\n${"noise\n".repeat(3_000)}`,
    };
    const projected = await toolOutputForModel(ctx, output);
    const ref = reference(String(projected.value));
    const found = await grep(ctx).execute?.(
      {
        directory: ref,
        pattern: "MIDDLE_EVIDENCE",
        flags: "-n",
        toolCallDescription: "Find evidence",
      },
      options,
    );
    expect(found).toMatchObject({
      success: true,
      output: expect.stringContaining("MIDDLE_EVIDENCE"),
    });
    const page = await readFile(ctx).execute?.(
      {
        path: ref,
        startLine: 2990,
        endLine: 3020,
        toolCallDescription: "Read evidence",
      },
      options,
    );
    expect(page).toMatchObject({
      success: true,
      content: expect.stringContaining("MIDDLE_EVIDENCE"),
    });
    expect(remote).not.toHaveBeenCalled();
    const other = { ...ctx, subagentId: "other-worker" };
    expect(
      await readFile(other).execute?.(
        { path: ref, toolCallDescription: "Wrong owner" },
        options,
      ),
    ).toMatchObject({ success: false });
    const local = { ...ctx, sandbox: undefined };
    await writeFile(join(ctx.agentCwd, "outside.txt"), "private");
    expect(
      await readFile(local).execute?.(
        {
          path: join(ctx.agentCwd, "outside.txt"),
          toolCallDescription: "Outside scope",
        },
        options,
      ),
    ).toMatchObject({ success: false });
  });

  it("provides bounded byte continuation through a giant Unicode line", async () => {
    const ctx = await context();
    const projected = await toolOutputForModel(ctx, {
      success: true,
      error: "",
      stdout: "🔐".repeat(30_000),
    });
    const ref = reference(String(projected.value));
    const file = await resolveToolOutput(ctx, ref);
    let reconstructed = "";
    let offset = 0;
    for (let i = 0; i < 20; i++) {
      const page = (await readFile(ctx).execute?.(
        {
          path: ref,
          byteOffset: offset,
          byteCount: 512 * 1024,
          toolCallDescription: "Read next bytes",
        },
        options,
      )) as { success: boolean; content: string; stoppedAtByte?: number };
      expect(page.success).toBe(true);
      expect(Buffer.byteLength(page.content)).toBeLessThanOrEqual(
        TOOL_OUTPUT_MAX_BYTES,
      );
      reconstructed += page.content;
      if (page.stoppedAtByte === undefined) break;
      expect(page.stoppedAtByte).toBeGreaterThan(offset);
      offset = page.stoppedAtByte;
    }
    expect(reconstructed).toBe(await read(file as string, "utf8"));
  });

  it("marks artifact byte pages truncated only when the output cap omits requested bytes", async () => {
    const ctx = await context();
    const projected = await toolOutputForModel(ctx, {
      success: true,
      error: "",
      stdout: "x".repeat(TOOL_OUTPUT_MAX_BYTES * 2),
    });
    const ref = reference(String(projected.value));
    const capped = await readFile(ctx).execute?.(
      {
        path: ref,
        byteOffset: 0,
        byteCount: TOOL_OUTPUT_MAX_BYTES * 3,
        toolCallDescription: "Read oversized artifact window",
      },
      options,
    );
    expect(capped).toMatchObject({
      success: true,
      truncated: true,
      byteCaptured: TOOL_OUTPUT_MAX_BYTES,
      stoppedAtByte: TOOL_OUTPUT_MAX_BYTES,
    });
    const requested = (await readFile(ctx).execute?.(
      {
        path: ref,
        byteOffset: 0,
        byteCount: 100,
        toolCallDescription: "Read small artifact window",
      },
      options,
    )) as ReadFileResult;
    expect(requested).toMatchObject({ success: true, byteCaptured: 100 });
    expect(requested?.truncated).toBeUndefined();
    const file = await resolveToolOutput(ctx, ref);
    const bytes = Buffer.byteLength(await read(file as string, "utf8"));
    const final = (await readFile(ctx).execute?.(
      {
        path: ref,
        byteOffset: bytes - 100,
        byteCount: TOOL_OUTPUT_MAX_BYTES * 3,
        toolCallDescription: "Read remaining artifact bytes",
      },
      options,
    )) as ReadFileResult;
    expect(final).toMatchObject({ success: true, byteCaptured: 100 });
    expect(final?.truncated).toBeUndefined();
    expect(final?.stoppedAtByte).toBe(bytes);
  });

  it("uses distinct exclusive files and rejects traversal and symlinks", async () => {
    const ctx = await context();
    const output = { success: true, error: "", stdout: "x".repeat(80_000) };
    const results = await Promise.all(
      Array.from({ length: 10 }, () => toolOutputForModel(ctx, output)),
    );
    expect(new Set(results.map((r) => reference(String(r.value)))).size).toBe(
      10,
    );
    await expect(
      resolveToolOutput(ctx, "tool-output:../secret"),
    ).rejects.toThrow("Invalid");
    const id = randomUUID();
    await symlink(
      join(ctx.agentCwd, "secret"),
      join(ctx.session.logsPath, "tool-output", `${id}.txt`),
    );
    await expect(resolveToolOutput(ctx, `tool-output:${id}`)).rejects.toThrow(
      "ordinary owned file",
    );
  });

  it("enforces the boundary in real SDK steps and reuses identical earlier results", async () => {
    const ctx = await context();
    ctx.commandShell = {
      execute: async () => ({
        exitCode: 0,
        stdout: "x".repeat(100_000),
        stderr: "",
      }),
    } as unknown as ToolContext["commandShell"];
    const seen: unknown[] = [];
    let step = 0;
    const model = new MockLanguageModelV3({
      doGenerate: async ({ prompt }) => {
        seen.push(prompt.filter((m) => m.role === "tool"));
        step++;
        return {
          content:
            step < 3
              ? [
                  {
                    type: "tool-call" as const,
                    toolCallId: `call-${step}`,
                    toolName: "execute_command",
                    input: JSON.stringify({
                      command: "fixture",
                      toolCallDescription: "Fixture",
                    }),
                  },
                ]
              : [{ type: "text" as const, text: "done" }],
          finishReason: {
            unified: step < 3 ? ("tool-calls" as const) : ("stop" as const),
            raw: "stop",
          },
          usage: {
            inputTokens: { total: 1, noCache: 1, cacheRead: 0, cacheWrite: 0 },
            outputTokens: { total: 1, text: 1, reasoning: 0 },
          },
          warnings: [],
        };
      },
    });
    const result = await generateText({
      model,
      tools: { execute_command: executeCommand(ctx) },
      prompt: "Inspect outputs",
      stopWhen: stepCountIs(3),
    });
    expect(result.text).toBe("done");
    const second = seen[1] as {
      content: { output: { type: string; value: string } }[];
    }[];
    const third = seen[2] as typeof second;
    expect(second[0].content[0].output.type).toBe("text");
    expect(
      Buffer.byteLength(second[0].content[0].output.value),
    ).toBeLessThanOrEqual(TOOL_OUTPUT_MAX_BYTES);
    expect(third[0]).toEqual(second[0]);
    expect(
      (result.steps[0].toolResults[0].output as { stdout: string }).stdout
        .length,
    ).toBe(100_000);
  });
});
