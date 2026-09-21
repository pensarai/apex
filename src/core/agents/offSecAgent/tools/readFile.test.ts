import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import type { ToolBackends } from "../../../tools/backends/types";
import { type ReadFileResult, readFile } from "./readFile";
import type { ToolContext } from "./types";

function makeCtx(agentCwd: string): ToolContext {
  return {
    agentCwd,
    session: { id: "ses_test", rootPath: agentCwd },
  } as ToolContext;
}

describe("readFile (golden, LocalBackends)", () => {
  it("reads a whole file with line numbers", async () => {
    const root = mkdtempSync(join(tmpdir(), "apex-read-"));
    writeFileSync(join(root, "a.ts"), "line1\nline2\nline3\n");

    const tool = readFile(makeCtx(root));
    const result = (await tool.execute?.(
      { path: "a.ts", toolCallDescription: "Read a.ts" },
      { toolCallId: "t1", messages: [] },
    )) as ReadFileResult;

    expect(result.success).toBe(true);
    expect(result.path).toBe("a.ts");
    expect(result.totalLines).toBe(4);
    expect(result.linesReturned).toBe(4);
    expect(result.content).toBe(
      "     1|line1\n     2|line2\n     3|line3\n     4|",
    );
  });

  it("reads a line range", async () => {
    const root = mkdtempSync(join(tmpdir(), "apex-read-range-"));
    writeFileSync(join(root, "a.ts"), "a\nb\nc\nd\ne\n");

    const tool = readFile(makeCtx(root));
    const result = (await tool.execute?.(
      { toolCallDescription: "test", path: "a.ts", startLine: 2, endLine: 4 },
      { toolCallId: "t1", messages: [] },
    )) as ReadFileResult;

    expect(result.success).toBe(true);
    expect(result.linesReturned).toBe(3);
    expect(result.content).toBe("     2|b\n     3|c\n     4|d");
  });

  it("fails loudly on a missing file, reporting the original path", async () => {
    const root = mkdtempSync(join(tmpdir(), "apex-read-miss-"));
    const tool = readFile(makeCtx(root));
    const result = (await tool.execute?.(
      { toolCallDescription: "test", path: "nope.ts" },
      { toolCallId: "t1", messages: [] },
    )) as ReadFileResult;

    expect(result.success).toBe(false);
    expect(result.path).toBe("nope.ts");
    expect(result.content).toBe("");
  });

  it("reads an absolute path outside agentCwd", async () => {
    const root = mkdtempSync(join(tmpdir(), "apex-read-cwd-"));
    const outside = join(
      mkdtempSync(join(tmpdir(), "apex-read-out-")),
      "o.txt",
    );
    writeFileSync(outside, "outside");
    const tool = readFile(makeCtx(root));
    const result = (await tool.execute?.(
      { toolCallDescription: "test", path: outside },
      { toolCallId: "t1", messages: [] },
    )) as ReadFileResult;

    expect(result.success).toBe(true);
    expect(result.content).toBe("     1|outside");
  });
});

describe("readFile backend injection", () => {
  it("calls the injected fs backend instead of reading from disk", async () => {
    const read = vi.fn().mockResolvedValue({
      success: true,
      error: "",
      content: "injected content",
      path: "a.ts",
      totalLines: 1,
      linesReturned: 1,
    } satisfies ReadFileResult);
    const backends = { fs: { read } } as unknown as ToolBackends;

    // A path that does not exist on the host filesystem — if the tool fell
    // through to real I/O instead of the injected backend, this would fail.
    const ctx = {
      agentCwd: "/nonexistent/apex-sandbox-path",
      session: {
        id: "ses_test",
        rootPath: "/nonexistent/apex-sandbox-path",
      },
      backends,
    } as ToolContext;

    const tool = readFile(ctx);
    const result = (await tool.execute?.(
      { toolCallDescription: "test", path: "a.ts", startLine: 1, endLine: 5 },
      { toolCallId: "t1", messages: [] },
    )) as ReadFileResult;

    expect(read).toHaveBeenCalledWith("a.ts", { startLine: 1, endLine: 5 });
    expect(result.content).toBe("injected content");
    expect(result.success).toBe(true);
  });
});
