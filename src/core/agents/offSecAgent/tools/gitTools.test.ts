import { execSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
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
