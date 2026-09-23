import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import type { ToolBackends } from "../../../tools/backends/types";
import { type ListFilesResult, listFiles } from "./listFiles";
import type { ToolContext } from "./types";

function makeCtx(agentCwd: string): ToolContext {
  return {
    agentCwd,
    session: { id: "ses_test", rootPath: agentCwd },
  } as ToolContext;
}

describe("listFiles (golden, LocalBackends)", () => {
  it("lists the immediate contents of a directory", async () => {
    const root = mkdtempSync(join(tmpdir(), "apex-list-"));
    writeFileSync(join(root, "a.ts"), "x");
    mkdirSync(join(root, "sub"));

    const tool = listFiles(makeCtx(root));
    const result = (await tool.execute?.(
      { toolCallDescription: "List root" },
      { toolCallId: "t1", messages: [] },
    )) as ListFilesResult;

    expect(result.success).toBe(true);
    expect(result.directory).toBe(root);
    expect(result.files.sort()).toEqual(["a.ts", "sub/"]);
  });

  it("lists recursively when recursive=true", async () => {
    const root = mkdtempSync(join(tmpdir(), "apex-list-rec-"));
    mkdirSync(join(root, "src"));
    writeFileSync(join(root, "src", "a.ts"), "x");

    const tool = listFiles(makeCtx(root));
    const result = (await tool.execute?.(
      { toolCallDescription: "test", recursive: true },
      { toolCallId: "t1", messages: [] },
    )) as ListFilesResult;

    expect(result.success).toBe(true);
    expect(result.files.sort()).toEqual(["src/", "src/a.ts"]);
  });

  it("fails when the target is not a directory", async () => {
    const root = mkdtempSync(join(tmpdir(), "apex-list-file-"));
    writeFileSync(join(root, "a.ts"), "x");

    const tool = listFiles(makeCtx(root));
    const result = (await tool.execute?.(
      { toolCallDescription: "test", directory: "a.ts" },
      { toolCallId: "t1", messages: [] },
    )) as ListFilesResult;

    expect(result.success).toBe(false);
    expect(result.error).toMatch(/not a directory/);
  });
});

describe("listFiles backend injection", () => {
  it("calls the injected fs backend instead of listing from disk", async () => {
    const list = vi.fn().mockResolvedValue({
      success: true,
      error: "",
      files: ["injected.ts"],
      directory: "/sandbox",
      count: 1,
    } satisfies ListFilesResult);
    const backends = { fs: { list } } as unknown as ToolBackends;

    // A directory that does not exist on the host filesystem — if the tool
    // fell through to real I/O instead of the injected backend, this would fail.
    const ctx = {
      agentCwd: "/nonexistent/apex-sandbox-path",
      session: {
        id: "ses_test",
        rootPath: "/nonexistent/apex-sandbox-path",
      },
      backends,
    } as ToolContext;

    const tool = listFiles(ctx);
    const result = (await tool.execute?.(
      { toolCallDescription: "test", directory: "sub", recursive: true },
      { toolCallId: "t1", messages: [] },
    )) as ListFilesResult;

    expect(list).toHaveBeenCalledWith("sub", { recursive: true });
    expect(result.files).toEqual(["injected.ts"]);
    expect(result.success).toBe(true);
  });
});
