import { existsSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import type { ToolBackends } from "../../../tools/backends/types";
import { type DeleteFileResult, deleteFile } from "./deleteFile";
import type { ToolContext } from "./types";

function makeCtx(agentCwd: string): ToolContext {
  return {
    agentCwd,
    session: { id: "ses_test", rootPath: agentCwd },
  } as ToolContext;
}

describe("deleteFile", () => {
  it("deletes an existing file", async () => {
    const root = mkdtempSync(join(tmpdir(), "apex-del-"));
    const path = join(root, "doomed.ts");
    writeFileSync(path, "export {}");

    const tool = deleteFile(makeCtx(root));
    const result = (await tool.execute?.(
      { path: "doomed.ts", toolCallDescription: "Remove doomed file" },
      { toolCallId: "t1", messages: [] },
    )) as DeleteFileResult;

    expect(result.success).toBe(true);
    expect(existsSync(path)).toBe(false);
  });

  it("fails loudly when the file is missing", async () => {
    const root = mkdtempSync(join(tmpdir(), "apex-del-miss-"));
    const tool = deleteFile(makeCtx(root));
    const result = (await tool.execute?.(
      { path: "missing.ts", toolCallDescription: "Try delete missing" },
      { toolCallId: "t1", messages: [] },
    )) as DeleteFileResult;

    expect(result.success).toBe(false);
    expect(result.error.length).toBeGreaterThan(0);
  });

  it("rejects paths outside agentCwd", async () => {
    const root = mkdtempSync(join(tmpdir(), "apex-del-esc-"));
    const tool = deleteFile(makeCtx(root));
    const result = (await tool.execute?.(
      { path: "../escape.ts", toolCallDescription: "Escape attempt" },
      { toolCallId: "t1", messages: [] },
    )) as DeleteFileResult;

    expect(result.success).toBe(false);
    expect(result.error).toMatch(/escapes/);
  });
});

describe("deleteFile backend injection", () => {
  it("calls the injected fs backend instead of unlinking from disk", async () => {
    const del = vi.fn().mockResolvedValue(undefined);
    const backends = { fs: { delete: del } } as unknown as ToolBackends;

    // A directory that does not exist on the host filesystem — if the tool
    // fell through to a real unlink instead of the injected backend, it
    // would reject with ENOENT instead of succeeding.
    const ctx = {
      agentCwd: "/nonexistent/apex-sandbox-path",
      session: {
        id: "ses_test",
        rootPath: "/nonexistent/apex-sandbox-path",
      },
      backends,
    } as ToolContext;

    const tool = deleteFile(ctx);
    const result = (await tool.execute?.(
      { toolCallDescription: "test", path: "doomed.ts" },
      { toolCallId: "t1", messages: [] },
    )) as DeleteFileResult;

    expect(del).toHaveBeenCalledWith("doomed.ts");
    expect(result.success).toBe(true);
  });

  it("surfaces a backend rejection as a failed result", async () => {
    const del = vi.fn().mockRejectedValue(new Error("boom"));
    const backends = { fs: { delete: del } } as unknown as ToolBackends;
    const ctx = {
      agentCwd: "/sandbox",
      session: { id: "ses_test", rootPath: "/sandbox" },
      backends,
    } as ToolContext;

    const tool = deleteFile(ctx);
    const result = (await tool.execute?.(
      { toolCallDescription: "test", path: "doomed.ts" },
      { toolCallId: "t1", messages: [] },
    )) as DeleteFileResult;

    expect(result.success).toBe(false);
    expect(result.error).toBe("boom");
  });
});
