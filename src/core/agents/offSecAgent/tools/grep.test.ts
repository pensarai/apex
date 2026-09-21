import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import type { ToolBackends } from "../../../tools/backends/types";
import { type GrepResult, grep } from "./grep";
import type { ToolContext } from "./types";

function makeCtx(agentCwd: string): ToolContext {
  return {
    agentCwd,
    session: { id: "ses_test", rootPath: agentCwd },
  } as ToolContext;
}

describe("grep (golden, LocalBackends)", () => {
  it("finds matches recursively by default", async () => {
    const root = mkdtempSync(join(tmpdir(), "apex-grep-"));
    writeFileSync(join(root, "a.ts"), "const password = 1;\n");

    const tool = grep(makeCtx(root));
    const result = (await tool.execute?.(
      { pattern: "password", toolCallDescription: "Search for password" },
      { toolCallId: "t1", messages: [] },
    )) as GrepResult;

    expect(result.success).toBe(true);
    expect(result.matchCount).toBe(1);
    expect(result.output).toContain("password");
    expect(result.command).toBe("grep -r -- password .");
  });

  it("reports no error when there are no matches", async () => {
    const root = mkdtempSync(join(tmpdir(), "apex-grep-none-"));
    writeFileSync(join(root, "a.ts"), "nothing here\n");

    const tool = grep(makeCtx(root));
    const result = (await tool.execute?.(
      { toolCallDescription: "test", pattern: "notfound" },
      { toolCallId: "t1", messages: [] },
    )) as GrepResult;

    expect(result.success).toBe(true);
    expect(result.error).toBe("");
    expect(result.output).toBe("(no matches)");
  });
});

describe("grep backend injection", () => {
  it("calls the injected fs backend instead of spawning a host grep", async () => {
    const grepFn = vi.fn().mockResolvedValue({
      success: true,
      error: "",
      output: "injected match",
      matchCount: 1,
      command: "grep -r -- x .",
    } satisfies GrepResult);
    const backends = { fs: { grep: grepFn } } as unknown as ToolBackends;

    // A directory that does not exist on the host filesystem — if the tool
    // fell through to spawning a real `grep` instead of the injected
    // backend, it would surface as an empty/error result, not the mock.
    const ctx = {
      agentCwd: "/nonexistent/apex-sandbox-path",
      session: {
        id: "ses_test",
        rootPath: "/nonexistent/apex-sandbox-path",
      },
      backends,
    } as ToolContext;

    const tool = grep(ctx);
    const result = (await tool.execute?.(
      {
        toolCallDescription: "test",
        pattern: "x",
        directory: "src",
        flags: "-i",
      },
      { toolCallId: "t1", messages: [] },
    )) as GrepResult;

    expect(grepFn).toHaveBeenCalledWith({
      pattern: "x",
      directory: "src",
      flags: "-i",
    });
    expect(result.output).toBe("injected match");
  });
});
