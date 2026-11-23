import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { BackgroundJobs } from "./backgroundJobs";
import {
  type ExecuteCommandInput,
  type ExecuteCommandResult,
  executeCommand,
} from "./executeCommand";
import { PerCommandShell } from "./perCommandShell";
import type { ToolContext } from "./types";

const cleanup: (() => Promise<void>)[] = [];
afterEach(async () => {
  for (const clean of cleanup.splice(0)) await clean();
});
function fixture(onChange?: ConstructorParameters<typeof BackgroundJobs>[0]) {
  const root = mkdtempSync(join(tmpdir(), "apex-bg-tool-"));
  const jobs = new BackgroundJobs(onChange);
  const shell = new PerCommandShell({ cwd: root });
  cleanup.push(async () => {
    await jobs.dispose();
    await shell.dispose();
    rmSync(root, { recursive: true, force: true });
  });
  const ctx = {
    session: { rootPath: root, logsPath: join(root, "logs"), targets: [] },
    agentCwd: root,
    backgroundJobs: jobs,
    commandShell: shell,
    environmentVariables: { TEST_BG_SECRET: "private-token-value" },
    secretValues: ["private-token-value"],
  } as unknown as ToolContext;
  const run = async (input: Partial<ExecuteCommandInput>) =>
    (await executeCommand(ctx).execute!(
      {
        command: "printf done",
        background: true,
        toolCallDescription: "test",
        ...input,
      },
      { toolCallId: "test", messages: [] },
    )) as ExecuteCommandResult;
  return { jobs, ctx, run };
}

describe("background command tools", () => {
  it("uses isolated shells and delivers a redacted completion exactly once", async () => {
    const { run, jobs } = fixture();
    const job = await run({ command: 'sleep 0.2; printf "$TEST_BG_SECRET"' });
    expect(job.status).toBe("running");
    const foreground = await run({
      command: "printf foreground",
      background: false,
    });
    expect(foreground.stdout).toBe("foreground");
    expect(jobs.status(job.jobId!).status).toBe("running");
    const notifications = await jobs.notifications(true);
    expect(JSON.stringify(notifications)).toContain("[REDACTED]");
    expect(JSON.stringify(notifications)).not.toContain("private-token-value");
    expect(await jobs.notifications(false)).toEqual([]);
    expect(jobs.status(job.jobId!).exitCode).toBe(0);
  });

  it("publishes redacted live output and terminal state for the process sidebar", async () => {
    const updates: import("../../../eventBus").BackgroundJobState[] = [];
    const { run, jobs } = fixture((state) => updates.push(state));
    const job = await run({
      command: 'printf "$TEST_BG_SECRET\\n"; sleep 0.1; printf done',
    });
    await jobs.notifications(true);
    expect(updates[0]).toMatchObject({
      jobId: job.jobId,
      status: "running",
      stdout: "",
    });
    expect(
      updates.some(
        (state) =>
          state.status === "running" && state.stdout.includes("[REDACTED]"),
      ),
    ).toBe(true);
    expect(updates.at(-1)).toMatchObject({
      jobId: job.jobId,
      status: "completed",
      exitCode: 0,
    });
    expect(updates.at(-1)?.finishedAt).toBeGreaterThanOrEqual(
      updates[0].startedAt,
    );
    expect(JSON.stringify(updates)).not.toContain("private-token-value");
  });

  it("cancels only the selected job and keeps the foreground shell usable", async () => {
    const { run, jobs } = fixture();
    const first = await run({ command: "sleep 30" });
    const second = await run({ command: "sleep 0.2; printf other" });
    expect((await jobs.cancel(first.jobId!)).exitCode).toBe(130);
    while (jobs.status(second.jobId!).status === "running")
      await jobs.notifications(true);
    expect(jobs.status(second.jobId!).stdout).toBe("other");
    expect((await run({ background: false })).success).toBe(true);
  });

  it.each([
    { command: "sleep 30", timeoutSeconds: 0.1, code: 124 },
    { command: "printf failure >&2; exit 7", timeoutSeconds: 5, code: 7 },
  ])("reports terminal status $code without losing output", async ({
    command,
    timeoutSeconds,
    code,
  }) => {
    const { run, jobs } = fixture();
    const job = await run({ command, timeoutSeconds });
    await jobs.notifications(true);
    const result = jobs.status(job.jobId!);
    expect(result.success).toBe(false);
    expect(result.exitCode).toBe(code);
    if (code === 7) expect(result.stderr).toContain("failure");
  });

  it("rejects invalid deadlines and unsupported contexts before launching jobs", async () => {
    const { run, ctx, jobs } = fixture();
    expect((await run({ timeoutSeconds: 9999 })).success).toBe(false);
    ctx.backgroundJobs = undefined;
    expect((await run({})).error).toContain("local, unrecorded");
    expect(await jobs.notifications(false)).toEqual([]);
  });

  it("retains large completion output outside model context with a read_file reference", async () => {
    const { run, jobs, ctx } = fixture();
    const job = await run({ command: "head -c 100000 /dev/zero | tr '\\0' x" });
    const notifications = await jobs.notifications(true, ctx);
    const content = String(notifications[0].content);
    expect(content).toContain("tool-output:");
    expect(Buffer.byteLength(content)).toBeLessThan(52 * 1024);
    expect(jobs.status(job.jobId!).stdout).toHaveLength(100000);
  });

  it("bounds active jobs and drains them on disposal", async () => {
    const { run, jobs } = fixture();
    const launched = await Promise.all(
      Array.from({ length: 8 }, () => run({ command: "sleep 30" })),
    );
    expect((await run({ command: "sleep 30" })).error).toContain(
      "Eight background",
    );
    await jobs.dispose();
    for (const job of launched)
      expect(jobs.status(job.jobId!).exitCode).toBe(130);
    expect(await jobs.notifications(false)).toEqual([]);
  });
});
