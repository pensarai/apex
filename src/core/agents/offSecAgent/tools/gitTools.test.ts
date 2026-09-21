import { execSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import type { ToolBackends } from "../../../tools/backends/types";
import { type GitDiffResult, gitDiff } from "./gitDiff";
import { type GitStatusResult, gitStatus } from "./gitStatus";
import { PersistentShell } from "./persistentShell";
import type { ToolContext } from "./types";

function makeGitRepo(): string {
  const root = mkdtempSync(join(tmpdir(), "apex-git-"));
  execSync("git init", { cwd: root });
  execSync('git config user.email "test@example.com"', { cwd: root });
  execSync('git config user.name "Test"', { cwd: root });
  writeFileSync(join(root, "a.ts"), "export const a = 1;\n");
  execSync("git add a.ts && git commit -m init", { cwd: root });
  writeFileSync(join(root, "a.ts"), "export const a = 2;\n");
  return root;
}

function makeCtx(agentCwd: string): ToolContext {
  const shell = new PersistentShell({ cwd: agentCwd });
  return {
    agentCwd,
    session: { id: "ses_test", rootPath: agentCwd },
    persistentShell: shell,
  } as ToolContext;
}

describe("git_status / git_diff", () => {
  it("reports porcelain status for modified files", async () => {
    const root = makeGitRepo();
    const ctx = makeCtx(root);
    try {
      const tool = gitStatus(ctx);
      const result = (await tool.execute?.(
        { toolCallDescription: "status" },
        { toolCallId: "t1", messages: [] },
      )) as GitStatusResult;
      expect(result.success).toBe(true);
      expect(result.status).toMatch(/a\.ts/);
    } finally {
      ctx.persistentShell?.dispose();
    }
  });

  it("returns an unstaged diff", async () => {
    const root = makeGitRepo();
    const ctx = makeCtx(root);
    try {
      const tool = gitDiff(ctx);
      const result = (await tool.execute?.(
        { toolCallDescription: "diff" },
        { toolCallId: "t1", messages: [] },
      )) as GitDiffResult;
      expect(result.success).toBe(true);
      expect(result.diff).toContain("-export const a = 1;");
      expect(result.diff).toContain("+export const a = 2;");
    } finally {
      ctx.persistentShell?.dispose();
    }
  });
});

describe("git_status / git_diff backend injection", () => {
  it("gitStatus calls the injected fs backend", async () => {
    const git = vi.fn().mockResolvedValue({
      success: true,
      stdout: " M injected.ts",
      stderr: "",
      cwd: "/sandbox",
    });
    const backends = { fs: { git } } as unknown as ToolBackends;
    const ctx = {
      agentCwd: "/sandbox",
      session: { id: "ses_test", rootPath: "/sandbox" },
      backends,
    } as ToolContext;

    const tool = gitStatus(ctx);
    const result = (await tool.execute?.(
      { toolCallDescription: "status" },
      { toolCallId: "t1", messages: [] },
    )) as GitStatusResult;

    expect(git).toHaveBeenCalledWith("status");
    expect(result.status).toBe("M injected.ts");
    expect(result.cwd).toBe("/sandbox");
  });

  it("gitDiff calls the injected fs backend with path/staged args", async () => {
    const git = vi.fn().mockResolvedValue({
      success: true,
      stdout: "injected diff",
      stderr: "",
      cwd: "/sandbox",
    });
    const backends = { fs: { git } } as unknown as ToolBackends;
    const ctx = {
      agentCwd: "/sandbox",
      session: { id: "ses_test", rootPath: "/sandbox" },
      backends,
    } as ToolContext;

    const tool = gitDiff(ctx);
    const result = (await tool.execute?.(
      { toolCallDescription: "test", path: "a.ts", staged: true },
      { toolCallId: "t1", messages: [] },
    )) as GitDiffResult;

    expect(git).toHaveBeenCalledWith("diff", { path: "a.ts", staged: true });
    expect(result.diff).toBe("injected diff");
  });
});
