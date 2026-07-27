import { existsSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
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
