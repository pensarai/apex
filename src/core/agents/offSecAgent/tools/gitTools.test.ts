import { execSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { type GitDiffResult, gitDiff } from "./gitDiff";
import { type GitStatusResult, gitStatus } from "./gitStatus";
import { PerCommandShell } from "./perCommandShell";
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
  const shell = new PerCommandShell({ cwd: agentCwd });
  return {
    agentCwd,
    session: { id: "ses_test", rootPath: agentCwd },
    commandShell: shell,
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
      await ctx.commandShell?.dispose();
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
      await ctx.commandShell?.dispose();
    }
  });
});

// Truncation at the tool boundary: a 1 MiB runner capture prefix must never
// masquerade as the complete porcelain list — especially never "(clean)".
describe("git_status truncated capture evidence", () => {
  type RunnerOutcome = {
    exitCode: number;
    stdout: string;
    stderr: string;
    stdoutTruncated: boolean;
  };

  function stubCtx(runner: RunnerOutcome): ToolContext {
    return {
      agentCwd: "/workspace/session",
      session: { id: "ses_test", rootPath: "/workspace/session" },
      commandShell: {
        execute: async () => ({
          ...runner,
          timedOut: false,
          stderrTruncated: false,
          cleanupUnconfirmed: false,
        }),
      },
    } as unknown as ToolContext;
  }

  const call = async (ctx: ToolContext) =>
    (await gitStatus(ctx).execute?.(
      { toolCallDescription: "status" },
      { toolCallId: "t1", messages: [] },
    )) as GitStatusResult;

  it("reports incomplete evidence for a truncated nonempty prefix", async () => {
    const result = await call(
      stubCtx({
        exitCode: 0,
        stdout: "M a.ts\nM b.ts\n",
        stderr: "",
        stdoutTruncated: true,
      }),
    );
    expect(result.success).toBe(true);
    // The partial list is kept as evidence…
    expect(result.status).toContain("M a.ts");
    // …and explicitly labeled incomplete — never a clean complete status.
    expect(result.status).toContain("INCOMPLETE");
    expect(result.error).toContain("INCOMPLETE");
    expect(result.error).toContain("truncated");
  });

  it("never reports (clean) for a truncated empty prefix", async () => {
    const result = await call(
      stubCtx({
        exitCode: 0,
        stdout: "",
        stderr: "",
        stdoutTruncated: true,
      }),
    );
    // An empty 1 MiB prefix can hide any number of entries past the cap.
    expect(result.status).not.toBe("(clean)");
    expect(result.status).not.toContain("(clean)");
    expect(result.status).toContain("INCOMPLETE");
    expect(result.error).toContain("INCOMPLETE");
  });

  it("preserves failure when git fails with a truncated capture", async () => {
    const result = await call(
      stubCtx({
        exitCode: 128,
        stdout: "M partial\n",
        stderr: "fatal: not a git repository",
        stdoutTruncated: true,
      }),
    );
    expect(result.success).toBe(false);
    expect(result.error).toContain("fatal: not a git repository");
    expect(result.error).toContain("INCOMPLETE");
    expect(result.status).toContain("M partial");
  });

  it("ordinary clean status is unchanged for a complete capture", async () => {
    const result = await call(
      stubCtx({
        exitCode: 0,
        stdout: "",
        stderr: "",
        stdoutTruncated: false,
      }),
    );
    expect(result.success).toBe(true);
    expect(result.error).toBe("");
    expect(result.status).toBe("(clean)");
  });

  it("git_diff keeps its preview semantics over the extended runGit result", async () => {
    // The runner-level truncation flag must not alter git_diff's behavior:
    // its own character preview decides the truncation message.
    const ctx = {
      agentCwd: "/workspace/session",
      session: { id: "ses_test", rootPath: "/workspace/session" },
      commandShell: {
        execute: async () => ({
          exitCode: 0,
          stdout: "-removed\n+added\n",
          stderr: "",
          stdoutTruncated: false,
          timedOut: false,
          stderrTruncated: false,
          cleanupUnconfirmed: false,
        }),
      },
    } as unknown as ToolContext;
    const result = (await gitDiff(ctx).execute?.(
      { toolCallDescription: "diff" },
      { toolCallId: "t1", messages: [] },
    )) as GitDiffResult;
    expect(result.success).toBe(true);
    expect(result.error).toBe("");
    expect(result.diff).toContain("+added");
  });
});
