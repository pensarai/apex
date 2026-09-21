import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import type { ToolBackends } from "../../../tools/backends/types";
import type { ToolContext } from "./types";
import { type UpdateFileResult, updateFile } from "./updateFile";

function makeCtx(agentCwd: string): ToolContext {
  return {
    agentCwd,
    session: { id: "ses_test", rootPath: agentCwd },
  } as ToolContext;
}

describe("updateFile (golden, LocalBackends)", () => {
  it("replaces the first occurrence by default", async () => {
    const root = mkdtempSync(join(tmpdir(), "apex-update-"));
    writeFileSync(join(root, "a.ts"), "foo\nfoo\n");

    const tool = updateFile(makeCtx(root));
    const result = (await tool.execute?.(
      {
        toolCallDescription: "test",
        path: "a.ts",
        oldContent: "foo",
        newContent: "bar",
      },
      { toolCallId: "t1", messages: [] },
    )) as UpdateFileResult;

    expect(result.success).toBe(true);
    expect(result.replacements).toBe(1);
    expect(result.path).toBe(join(root, "a.ts"));
    expect(readFileSync(join(root, "a.ts"), "utf-8")).toBe("bar\nfoo\n");
  });

  it("replaces every occurrence when replaceAll=true", async () => {
    const root = mkdtempSync(join(tmpdir(), "apex-update-all-"));
    writeFileSync(join(root, "a.ts"), "foo\nfoo\nfoo\n");

    const tool = updateFile(makeCtx(root));
    const result = (await tool.execute?.(
      {
        toolCallDescription: "test",
        path: "a.ts",
        oldContent: "foo",
        newContent: "bar",
        replaceAll: true,
      },
      { toolCallId: "t1", messages: [] },
    )) as UpdateFileResult;

    expect(result.success).toBe(true);
    expect(result.replacements).toBe(3);
    expect(readFileSync(join(root, "a.ts"), "utf-8")).toBe("bar\nbar\nbar\n");
  });

  it("fails loudly when oldContent is not found", async () => {
    const root = mkdtempSync(join(tmpdir(), "apex-update-miss-"));
    writeFileSync(join(root, "a.ts"), "hello\n");

    const tool = updateFile(makeCtx(root));
    const result = (await tool.execute?.(
      {
        toolCallDescription: "test",
        path: "a.ts",
        oldContent: "goodbye",
        newContent: "hi",
      },
      { toolCallId: "t1", messages: [] },
    )) as UpdateFileResult;

    expect(result.success).toBe(false);
    expect(result.error).toMatch(/not found/);
    expect(result.replacements).toBe(0);
    expect(readFileSync(join(root, "a.ts"), "utf-8")).toBe("hello\n");
  });

  it("fails loudly when the file does not exist", async () => {
    const root = mkdtempSync(join(tmpdir(), "apex-update-nofile-"));
    const tool = updateFile(makeCtx(root));
    const result = (await tool.execute?.(
      {
        toolCallDescription: "test",
        path: "nope.ts",
        oldContent: "a",
        newContent: "b",
      },
      { toolCallId: "t1", messages: [] },
    )) as UpdateFileResult;

    expect(result.success).toBe(false);
    expect(result.replacements).toBe(0);
  });
});

describe("updateFile backend injection", () => {
  it("calls the injected fs backend (readRaw + write) instead of touching disk", async () => {
    const readRaw = vi.fn().mockResolvedValue({
      success: true,
      error: "",
      content: "foo bar",
      path: "/sandbox/a.ts",
    });
    const write = vi.fn().mockResolvedValue({
      success: true,
      error: "",
      path: "/sandbox/a.ts",
    });
    const backends = { fs: { readRaw, write } } as unknown as ToolBackends;

    // A directory that does not exist on the host filesystem — if the tool
    // fell through to real I/O instead of the injected backend, readRaw's
    // "foo bar" content could never have been produced by a real read.
    const ctx = {
      agentCwd: "/nonexistent/apex-sandbox-path",
      session: {
        id: "ses_test",
        rootPath: "/nonexistent/apex-sandbox-path",
      },
      backends,
    } as ToolContext;

    const tool = updateFile(ctx);
    const result = (await tool.execute?.(
      {
        toolCallDescription: "test",
        path: "a.ts",
        oldContent: "foo",
        newContent: "baz",
      },
      { toolCallId: "t1", messages: [] },
    )) as UpdateFileResult;

    expect(readRaw).toHaveBeenCalledWith("a.ts");
    expect(write).toHaveBeenCalledWith("/sandbox/a.ts", "baz bar", {
      mode: "overwrite",
    });
    expect(result.success).toBe(true);
    expect(result.replacements).toBe(1);
  });
});
